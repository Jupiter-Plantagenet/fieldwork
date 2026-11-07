"""Independent training-lease controller; no worker/model imports or physical eviction.

Not installed/activated by importing this module. DB driver is loaded only by CLI.
"""
import json
import time


class PostgresBackend:
    """Explicit controller connection factory, never a request Store or tenant GUC.

    Logical recovery only: physical slots are unconditionally retained. No slot
    locks are acquired, so the existing slot-first/run order is not inverted.
    """
    def __init__(self, connect, workspaces):
        self.connect = connect
        self.workspaces = workspaces

    @staticmethod
    def _limits(connection):
        connection.execute("SET LOCAL lock_timeout='50ms'")
        connection.execute("SET LOCAL statement_timeout='250ms'")
        connection.execute("SET LOCAL idle_in_transaction_session_timeout='1000ms'")

    def candidates(self, cursor, batch_size):
        with self.connect() as connection:
            self._limits(connection)
            return connection.execute("""SELECT id,fence,revision,state FROM fw_runs
                WHERE workspace=ANY(%s) AND id>%s
                  AND state IN ('leased','running','cancel_requested')
                  AND lease<=clock_timestamp() ORDER BY id LIMIT %s""",
                (self.workspaces, cursor, batch_size)).fetchall()

    def expire(self, candidate):
        with self.connect() as connection:
            self._limits(connection)
            # Recheck exact snapshot and DB expiry under the canonical run lock.
            # A renewal wins without a revision bump, hence the second expiry
            # predicate matters. SKIP LOCKED never waits behind a worker row.
            changed = connection.execute("""WITH locked AS (
                SELECT id FROM fw_runs WHERE id=%s AND workspace=ANY(%s)
                  AND fence=%s AND revision=%s AND state=%s
                  AND state IN ('leased','running','cancel_requested')
                  AND lease<=clock_timestamp() FOR UPDATE SKIP LOCKED
                ) UPDATE fw_runs r SET
                    state=CASE WHEN r.state='cancel_requested' THEN 'cancelled' ELSE 'interrupted' END,
                    fence=r.fence+1,revision=r.revision+1
                FROM locked WHERE r.id=locked.id AND r.lease<=clock_timestamp()
                RETURNING r.id,r.workspace,r.state,r.fence,r.revision""",
                (candidate['id'], self.workspaces, candidate['fence'],
                 candidate['revision'], candidate['state'])).fetchone()
            if changed is None:
                return None
            detail = {'state': changed['state'], 'fence': changed['fence'],
                      'physical_slot': 'RETAINED_NOT_RECONCILED',
                      'diagnosis': 'LOGICAL_EXPIRY_IS_NOT_PHYSICAL_EXIT',
                      'automatic_retry': False}
            connection.execute("""INSERT INTO fw_events
                (workspace,run,kind,payload,object_revision)
                VALUES(%s,%s,'expired',%s::jsonb,%s)""",
                (changed['workspace'], changed['id'], json.dumps(detail), changed['revision']))
            return {'run': changed['id'], **detail}


def scan_once(backend, cursor='', batch_size=16, budget_seconds=1.0):
    started = time.monotonic()
    rows = backend.candidates(cursor, batch_size)
    receipt = {'cursor': cursor if rows else '', 'transitions': [], 'errors': []}
    for index, candidate in enumerate(rows):
        # Soft pass budget: successful discovery always gets one row attempt.
        # Discovery and an in-flight transaction can overrun it; no hard deadline.
        if index and time.monotonic() - started >= budget_seconds:
            break
        # Advance even on a poisoned row; next pass continues rather than retrying
        # the first bad row forever. Each DB mutation has its own transaction.
        receipt['cursor'] = candidate['id']
        try:
            result = backend.expire(candidate)
        except Exception as exc:
            receipt['errors'].append({'run': candidate['id'], 'code': type(exc).__name__})
            continue
        if result is not None:
            receipt['transitions'].append(result)
    return receipt


def parse_options(argv=None):
    import argparse
    import math
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('INVALID_CONTROLLER_OPTIONS')
    parser = Parser(description=__doc__)
    parser.add_argument('--authority-file', required=True)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=float, default=2.0)
    parser.add_argument('--batch-size', type=int, default=16)
    options = parser.parse_args(argv)
    if not math.isfinite(options.interval) or not 0 < options.interval <= 5 or not 1 <= options.batch_size <= 32:
        raise ValueError('INVALID_CONTROLLER_LIMITS')
    return options


def validate_authority(authority):
    # This is explicit operator authority, NOT a least-privilege certificate.
    if not isinstance(authority, dict):
        raise ValueError('INVALID_CONTROLLER_AUTHORITY')
    if authority.get('authority_mode') == 'scoped-machine-v1':
        from .scoped_authority import validate
        return validate(authority)
    scopes = authority.get('workspaces')
    if (authority.get('purpose') != 'fieldwork-training-lease-controller'
            or authority.get('authority_mode') != 'trusted-operator-not-least-privilege'
            or not isinstance(authority.get('dsn'), str) or not authority['dsn']
            or not isinstance(scopes, list) or not 1 <= len(scopes) <= 100
            or any(not isinstance(scope, str) or not scope or scope == '*' for scope in scopes)):
        raise ValueError('INVALID_CONTROLLER_AUTHORITY')
    return authority


def run_controller(backend, options):
    cursor = ''
    while True:
        started = time.monotonic()
        try:
            receipt = scan_once(backend, cursor, options.batch_size)
            cursor = receipt['cursor']
        except Exception as exc:
            receipt = {'cursor': cursor, 'transitions': [],
                       'errors': [{'code': type(exc).__name__}]}
        print(json.dumps({**receipt, 'physical_slot': 'RETAINED_NOT_RECONCILED'}), flush=True)
        if options.once:
            return 1 if receipt['errors'] else 0
        time.sleep(max(0, options.interval - (time.monotonic() - started)))


def main(argv=None):
    from pathlib import Path
    try:
        options = parse_options(argv)
        path = Path(options.authority_file)
        if path.stat().st_size > 65536:
            raise ValueError('INVALID_CONTROLLER_AUTHORITY')
        authority = validate_authority(json.loads(path.read_text()))
        if authority['authority_mode'] == 'scoped-machine-v1':
            from .scoped_authority import MachineBackend, check_private
            check_private(path)
            backend = MachineBackend(authority)
            backend.verify()
            return run_controller(backend, options)
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.conninfo import make_conninfo
        # Explicit separate authority file only: never Store(), API credentials,
        # session role, request tenant context, migrations or role provisioning.
        dsn = make_conninfo(authority['dsn'], connect_timeout=1,
                           application_name='fieldwork-training-lease-controller')
        def connect():
            return psycopg.connect(dsn, row_factory=dict_row)
        # Existing browser principal has no fw_slot privilege. Do not accept it
        # as controller merely because a caller labels a file as authority.
        with connect() as connection:
            PostgresBackend._limits(connection)
            permitted = connection.execute("SELECT has_table_privilege(current_user,'fw_slot','SELECT') AS allowed").fetchone()
            if not permitted['allowed']:
                raise ValueError('REQUEST_PRINCIPAL_NOT_CONTROLLER')
        return run_controller(PostgresBackend(connect, authority['workspaces']), options)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # Driver messages can contain DSNs or private config values.
        print(json.dumps({'code': 'CONTROLLER_STOPPED', 'error_type': type(exc).__name__}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
