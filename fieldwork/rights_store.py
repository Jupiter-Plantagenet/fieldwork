"""PostgreSQL adapter; no schema installation or privileged fallback here."""
from contextlib import contextmanager
import psycopg
from .rights_decision import DecisionRejected


@contextmanager
def rights_repository(store):
    try:
        # Consistent facts/membership snapshot without row-lock UPDATE privileges.
        with store.connect(isolation_level=psycopg.IsolationLevel.REPEATABLE_READ) as connection:
            yield RightsRepository(connection)
    except psycopg.Error:
        raise DecisionRejected('RIGHTS_DATABASE_DEPENDENCY') from None


class RightsRepository:
    def __init__(self, connection):
        self.c = connection

    def authorize(self, workspace, actor, purpose):
        # Live persisted membership/role, not an intake-supplied role or cached flag.
        row = self.c.execute('SELECT role FROM fw_accounts WHERE workspace=%s AND name=%s',
                             (workspace, actor)).fetchone()
        if purpose == 'private_thumbnail_ui':
            roles = {'owner', 'researcher', 'reviewer', 'viewer'}
        elif purpose == 'read_only_real_inference':
            # This admission is deliberately separate from every consequential
            # rights purpose (training, intake, or export control).
            roles = {'owner', 'researcher', 'reviewer'}
        else:
            roles = {'owner', 'researcher'}
        return bool(row and row['role'] in roles)

    def asset(self, workspace, dataset, member):
        return self.c.execute('''SELECT member_id,asset_sha256,asset_bytes,
            canonical_license,license_text,source_evidence,attribution,rights_state
            FROM fw_rights_assets WHERE workspace=%s AND dataset_id=%s AND member_id=%s''',
            (workspace, dataset, member)).fetchone()

    def members(self, workspace, dataset):
        inventory = self.c.execute('''SELECT member_count,state FROM fw_rights_datasets
            WHERE workspace=%s AND dataset_id=%s''', (workspace, dataset)).fetchone()
        if not inventory or inventory['state'] != 'authenticated':
            raise DecisionRejected('RIGHTS_QUARANTINED')
        rows = self.c.execute('''SELECT member_id FROM fw_rights_assets
            WHERE workspace=%s AND dataset_id=%s ORDER BY member_id''', (workspace, dataset)).fetchall()
        if len(rows) != inventory['member_count']:
            raise DecisionRejected('INCOMPLETE_INVENTORY')
        return [row['member_id'] for row in rows]

    def authenticated_inventory(self, workspace, dataset):
        """Check inventory completeness without returning any member identities."""
        inventory = self.c.execute('''SELECT d.member_count,d.state,COUNT(a.member_id) AS actual_count
            FROM fw_rights_datasets AS d
            LEFT JOIN fw_rights_assets AS a
              ON a.workspace=d.workspace AND a.dataset_id=d.dataset_id
            WHERE d.workspace=%s AND d.dataset_id=%s
            GROUP BY d.member_count,d.state''', (workspace, dataset)).fetchone()
        if not inventory or inventory['state'] != 'authenticated':
            raise DecisionRejected('RIGHTS_QUARANTINED')
        expected, actual = inventory['member_count'], inventory['actual_count']
        if type(expected) is not int or type(actual) is not int or expected != actual:
            raise DecisionRejected('INCOMPLETE_INVENTORY')
        if expected < 1:
            raise DecisionRejected('RIGHTS_QUARANTINED')
        return expected

    def assets_with_decisions(self, workspace, dataset, purpose):
        """Every asset row of the dataset with its decision envelope for `purpose` (None if absent), one query.

        Same snapshot and the same columns as asset()/decision(); replaces 2 round trips per member."""
        # Evidence digests come from migration 022's generated columns when present (they are recomputed by
        # PostgreSQL on every write of the source bytes), else they are hashed in the query. Either way no blob is
        # shipped and _verify() consumes `<column>_sha256` + `<column>_bytes` exactly as it would hash raw bytes.
        stored = self.c.execute("""SELECT count(*) AS n FROM information_schema.columns WHERE table_schema='public'
            AND table_name='fw_rights_assets' AND column_name='license_text_sha256'""").fetchone()['n'] == 1
        def digest(column):
            expr = 'a.' + column + '_sha256' if stored else "encode(sha256(a." + column + "),'hex')"
            return expr + ' AS ' + column + '_sha256, octet_length(a.' + column + ') AS ' + column + '_bytes'
        columns = ', '.join(digest(c) for c in ('canonical_license', 'license_text', 'source_evidence', 'attribution'))
        rows = self.c.execute('''SELECT a.member_id,a.asset_sha256,a.asset_bytes,a.rights_state,d.envelope,''' + columns + '''
            FROM fw_rights_assets a LEFT JOIN fw_rights_decisions d
              ON d.workspace=a.workspace AND d.dataset_id=a.dataset_id AND d.member_id=a.member_id AND d.purpose=%s
            WHERE a.workspace=%s AND a.dataset_id=%s''', (purpose, workspace, dataset)).fetchall()
        out = {}
        for row in rows:
            row = dict(row)
            envelope = row.pop('envelope')
            out[row['member_id']] = (row, bytes(envelope) if envelope is not None else None)
        return out

    def decision(self, workspace, dataset, member, purpose):
        row = self.c.execute('''SELECT envelope FROM fw_rights_decisions
            WHERE workspace=%s AND dataset_id=%s AND member_id=%s AND purpose=%s''',
            (workspace, dataset, member, purpose)).fetchone()
        return bytes(row['envelope']) if row else None

    def save(self, workspace, dataset, member, purpose, raw, code):
        self.c.execute('''INSERT INTO fw_rights_decisions
            (workspace,dataset_id,member_id,purpose,envelope,last_result)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT(workspace,dataset_id,member_id,purpose)
            DO UPDATE SET envelope=excluded.envelope,last_result=excluded.last_result,received_utc=clock_timestamp()''',
            (workspace, dataset, member, purpose, raw, code))
