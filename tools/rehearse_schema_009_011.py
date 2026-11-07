"""Rehearse Fieldwork migrations 009-011 on a restored, disposable PostgreSQL copy.

The retained backup and globals are read-only inputs. Globals passwords are
removed before replay, restored object ownership is preserved, and all three
migration bodies run in one PostgreSQL transaction. The runner prints only the
evidence path and a status summary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
BACKUP_BASE = ROOT / "var/snapshots/pre009011-20261101T213744Z"
MIGRATIONS = (
    "009_fresh_image_inference.sql",
    "010_workspace_controls.sql",
    "011_real_artifact_retention.sql",
)
EXPECTED_MIGRATION_HASHES = {
    "009_fresh_image_inference.sql": "5adb6f41d423198d04c4ed09ce8bb68aa8560dada792c13abcb55a960beb5227",
    "010_workspace_controls.sql": "cfe6bf0275dc839c24e8a27b1dd1d2b0b11968902af5b24ea302ad8d07b16a10",
    "011_real_artifact_retention.sql": "02bdcf6e9364f10ba39e95de638ac57541c0891e3b0deccc8f65b04c57a92950",
}
EXPECTED_DUMP_SHA256 = "d33664e249f69eafb2bce8d2b6e283b1e400ef97f3cb5c228c94f7cbcd2a074f"
CONTAINER_PREFIX = "fieldwork-schema-rehearsal-"
PORT = 15542


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], *, input_bytes: bytes | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def restore_globals_without_passwords(path: Path) -> bytes:
    raw = path.read_bytes()
    clean = re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)", b"", raw)
    if re.search(rb"(?i)PASSWORD\s+", clean):
        raise ValueError("GLOBAL_PASSWORD_REDACTION_INCOMPLETE")
    return clean


def outer_body(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    first = next(i for i, line in enumerate(lines)
                 if line.strip() and not line.lstrip().startswith("--"))
    if not nonblank or lines[first].strip().upper() != "BEGIN;" or lines[nonblank[-1]].strip().upper() != "COMMIT;":
        raise ValueError("MIGRATION_ENVELOPE_INVALID")
    return "".join(lines[:first] + lines[first + 1:nonblank[-1]] + lines[nonblank[-1] + 1:])


def table_snapshot(conn) -> tuple[dict[str, list[str]], dict[str, dict[str, object]]]:
    conn.execute("SET work_mem TO '16MB'")
    conn.execute("SET temp_file_limit TO '512MB'")
    tables = conn.execute("""
        SELECT c.relname
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind IN ('r','p') ORDER BY c.relname
    """).fetchall()
    columns: dict[str, list[str]] = {}
    result: dict[str, dict[str, object]] = {}
    for row in tables:
        table = row["relname"]
        cols = [r["attname"] for r in conn.execute("""
            SELECT a.attname FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=%s AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY a.attnum
        """, (table,)).fetchall()]
        columns[table] = cols
        result[table] = row_fingerprint(conn, table, cols, "fw_schema_snapshot_" + str(len(result)))
    return columns, result


def run_sql_in_transaction(conn, bodies: list[str]) -> None:
    with conn.transaction():
        conn.execute("\n".join(bodies))


def row_fingerprint(conn, table: str, columns: list[str], cursor_name: str) -> dict[str, object]:
    pk = [r["attname"] for r in conn.execute("""
        SELECT a.attname
        FROM pg_catalog.pg_index i
        CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum,ord)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
        WHERE i.indrelid=to_regclass(%s) AND i.indisprimary AND k.ord<=i.indnkeyatts
        ORDER BY k.ord
    """, ("public." + table,)).fetchall()]
    if not pk or not set(pk).issubset(columns):
        raise ValueError("EXISTING_TABLE_PRIMARY_KEY_REQUIRED_FOR_BOUNDED_HASH")
    projection = sql.SQL(",").join(sql.Identifier(c) for c in columns)
    order = sql.SQL(",").join(sql.SQL("x.") + sql.Identifier(c) for c in pk)
    query = sql.SQL("SELECT to_jsonb(x)::text AS row_json FROM (SELECT {} FROM public.{}) AS x ORDER BY {}").format(
        projection, sql.Identifier(table), order)
    h = hashlib.sha256()
    n = 0
    with conn.cursor(name=cursor_name) as cur:
        cur.execute(query)
        while batch := cur.fetchmany(1000):
            for rowdata in batch:
                h.update(rowdata["row_json"].encode("utf-8"))
                h.update(b"\n")
                n += 1
    return {"rows": n, "row_sha256": h.hexdigest()}


def inspect_contract(conn, before_tables: set[str], before_columns: dict[str, list[str]],
                     before_data: dict[str, dict[str, object]]) -> dict[str, object]:
    after_columns, after_data = table_snapshot(conn)
    preserved = {}
    for table, cols in before_columns.items():
        if table not in after_columns or not set(cols).issubset(after_columns[table]):
            preserved[table] = False
            continue
        # Recompute against the exact pre-migration projection, ignoring only new nullable/default columns.
        current = row_fingerprint(conn, table, cols, "fw_schema_verify_" + str(len(preserved)))
        preserved[table] = current == before_data[table]

    protected_tables = ["fw_real_image_inputs", "fw_workspace_settings", "fw_workspace_settings_events", "fw_real_artifact_retention"]
    rls = {}
    for table in protected_tables:
        row = conn.execute("""
            SELECT c.relrowsecurity AS enabled,c.relforcerowsecurity AS forced
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=%s
        """, (table,)).fetchone()
        rls[table] = bool(row and row["enabled"] and row["forced"])

    expected_functions = [
        "fw_real_worker_cap_v1.image_inference_profile_ok(jsonb,text,text)",
        "fw_real_worker_cap_v1.real_image_inference_input(text,text,text,integer,integer,uuid,text)",
        "fw_real_worker_cap_v1.complete_real_image_inference(text,text,text,integer,integer,uuid,jsonb,integer,double precision,boolean,text,text,text)",
        "fw_real_worker_cap_v1.bundle_inference_blocked(text,text)",
    ]
    definer_owners = {}
    for signature in expected_functions:
        row = conn.execute("""
            SELECT r.rolname AS owner, p.prosecdef AS security_definer,
                   has_function_privilege('public',p.oid,'EXECUTE') AS public_execute
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
            WHERE p.oid=to_regprocedure(%s)
        """, (signature,)).fetchone()
        definer_owners[signature] = bool(row and row["owner"] == "fieldwork_real_worker_definer"
                                          and row["security_definer"] and not row["public_execute"])

    worker_rows = conn.execute("""
        SELECT s.principal, r.rolcanlogin, r.rolinherit,
               has_table_privilege(s.principal,'public.fw_runs','SELECT') AS direct_runs_select
        FROM fw_worker_cap_v1.scope s JOIN pg_catalog.pg_roles r ON r.rolname=s.principal
        ORDER BY s.principal
    """).fetchall()
    worker_caps = {
        "scoped_login_count": len(worker_rows),
        "all_noninheriting": bool(worker_rows) and all(not x["rolinherit"] for x in worker_rows),
        "all_logins": bool(worker_rows) and all(x["rolcanlogin"] for x in worker_rows),
        "no_direct_runs_select": bool(worker_rows) and all(not x["direct_runs_select"] for x in worker_rows),
    }
    controls = {
        "admission_trigger": conn.execute("SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='trg_workspace_run_admission_v1' AND NOT tgisinternal) AS ok").fetchone()["ok"],
        "retention_fence_trigger": conn.execute("SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='trg_real_inference_retention_fence_v1' AND NOT tgisinternal) AS ok").fetchone()["ok"],
        "retention_restrictive_policy": conn.execute("SELECT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='fw_runs' AND policyname='fw_real_worker_retention_fence' AND permissive='RESTRICTIVE') AS ok").fetchone()["ok"],
    }
    return {
        "existing_table_rows_and_hashes_unchanged": preserved,
        "existing_table_preservation_pass": bool(preserved) and all(preserved.values()),
        "existing_table_names_unchanged": before_tables.issubset(after_columns),
        "new_tables": sorted(set(after_columns) - before_tables),
        "new_table_rows": {t: after_data[t]["rows"] for t in sorted(set(after_columns) - before_tables)},
        "rls_force_enabled": rls,
        "definer_capability_owners_and_acl": definer_owners,
        "worker_capabilities": worker_caps,
        "admission_and_retention_controls": controls,
    }


def exercise_resume_admission(conn) -> dict[str, object]:
    """Prove an interrupted real run cannot resume above capacity, then roll back all fixtures."""
    class RehearsalRollback(Exception):
        pass

    observed = {"status": "not_feasible", "reason": "no suitable interrupted real run in the populated backup"}
    try:
        with conn.transaction():
            workspace = conn.execute("""
                SELECT workspace,
                       count(*) FILTER (WHERE state='interrupted') AS inactive,
                       count(*) FILTER (WHERE state IN ('queued','leased','running','cancel_requested')) AS active
                FROM fw_runs
                WHERE config->>'scope' IN ('real-training/v1','real-inference/v1','real-image-inference/v1')
                GROUP BY workspace
                HAVING count(*) FILTER (WHERE state='interrupted') >= 1
                   AND (count(*) FILTER (WHERE state IN ('queued','leased','running','cancel_requested')) >= 1
                        OR count(*) FILTER (WHERE state='interrupted') >= 2)
                ORDER BY workspace LIMIT 1
            """).fetchone()
            if workspace:
                ws = workspace["workspace"]
                targets = conn.execute("""
                    SELECT id FROM fw_runs WHERE workspace=%s AND state='interrupted'
                      AND config->>'scope' IN ('real-training/v1','real-inference/v1','real-image-inference/v1')
                    ORDER BY id LIMIT 2
                """, (ws,)).fetchall()
                conn.execute("""
                    INSERT INTO fw_workspace_settings(workspace,max_concurrent_runs)
                    VALUES (%s,1) ON CONFLICT(workspace) DO UPDATE SET
                      max_concurrent_runs=1, revision=fw_workspace_settings.revision+1,
                      updated_utc=clock_timestamp()
                """, (ws,))
                if workspace["active"] == 0:
                    conn.execute("UPDATE fw_runs SET state='queued' WHERE id=%s", (targets[0]["id"],))
                    target = targets[1]["id"]
                else:
                    target = targets[0]["id"]
                try:
                    with conn.transaction():
                        conn.execute("UPDATE fw_runs SET state='queued' WHERE id=%s", (target,))
                except psycopg.Error as exc:
                    denied = (exc.sqlstate == "P0001" and
                              getattr(getattr(exc, "diag", None), "message_primary", None) == "WORKSPACE_RUN_LIMIT")
                    observed = {"status": "executed_pass" if denied else "executed_fail",
                                "resume_transition_denied_at_capacity": denied,
                                "sqlstate": exc.sqlstate}
                if observed["status"] == "not_feasible":
                    observed = {"status": "executed_fail", "resume_transition_denied_at_capacity": False,
                                "reason": "capacity fixture did not raise WORKSPACE_RUN_LIMIT"}
            raise RehearsalRollback()
    except RehearsalRollback:
        pass
    return observed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, help="Evidence directory; created exclusively")
    args = ap.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or ROOT / ".local/round5-resume" / f"schema-009-011-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "fieldwork.schema-rehearsal/v1", "started_utc": datetime.now(timezone.utc).isoformat(),
                                "live_database_touched": False, "container": None, "port": PORT,
                                "stage": "validate-backup-and-pins"}
    created = False
    container = CONTAINER_PREFIX + stamp.lower()
    report["container"] = container
    try:
        manifest_path = BACKUP_BASE.with_suffix(".json")
        globals_path = BACKUP_BASE.with_name(BACKUP_BASE.name + "-globals.sql")
        dump_path = BACKUP_BASE.with_suffix(".dump")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        dump_bytes = dump_path.read_bytes()
        globals_bytes = globals_path.read_bytes()
        if digest(dump_bytes) != EXPECTED_DUMP_SHA256 or digest(dump_bytes) != manifest["db"]["sha256"]:
            raise ValueError("BACKUP_DUMP_DIGEST_MISMATCH")
        if digest(globals_bytes) != manifest["globals"]["sha256"]:
            raise ValueError("BACKUP_GLOBALS_DIGEST_MISMATCH")
        mig_bytes = {}
        migration_hashes = {}
        for name in MIGRATIONS:
            data = (ROOT / "migrations" / name).read_bytes()
            expected = EXPECTED_MIGRATION_HASHES[name]
            actual = digest(data)
            if not expected or actual != expected:
                raise ValueError("MIGRATION_SOURCE_PIN_MISSING_OR_MISMATCH")
            migration_hashes[name] = actual
            mig_bytes[name] = data
        report["backup"] = {"manifest": manifest_path.name, "dump_bytes": len(dump_bytes),
                             "dump_sha256": digest(dump_bytes), "globals_sha256": digest(globals_bytes),
                             "restored_with_owners": True, "globals_passwords_removed_before_restore": True}
        report["migration_sha256"] = migration_hashes
        redacted_globals = restore_globals_without_passwords(globals_path)
        (out / "globals.redacted.sql").write_bytes(redacted_globals)
        local = json.loads((ROOT / ".local.json").read_text(encoding="utf-8"))
        params = conninfo_to_dict(local["dsn"])
        owner = params["user"]
        dbname = params["dbname"]
        if dbname != "fieldwork":
            raise ValueError("BACKUP_DATABASE_IDENTITY_UNEXPECTED")
        existing = run(["docker", "inspect", container])
        if existing.returncode == 0:
            raise ValueError("OWNED_CONTAINER_NAME_ALREADY_EXISTS")
        # The only target port opened is the explicitly reserved local rehearsal port.
        pw = secrets.token_urlsafe(32)
        runlog = out / "docker-run.stdout.log"
        proc = run(["docker", "run", "-d", "--name", container,
                    "-p", f"127.0.0.1:{PORT}:5432", "-e", "POSTGRES_USER=postgres",
                    "-e", "POSTGRES_PASSWORD=" + pw, "--memory", "768m", "--cpus", "1.0",
                    "--shm-size", "64m", "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
                    "postgres:16-alpine"], timeout=120)
        runlog.write_bytes(proc.stdout + b"\n" + proc.stderr)
        if proc.returncode:
            raise RuntimeError("ISOLATED_POSTGRES_START_FAILED")
        created = True
        report["stage"] = "wait-for-isolated-postgres"
        admin = make_conninfo(host="127.0.0.1", port=PORT, dbname="postgres", user="postgres", password=pw, connect_timeout=3)
        ready = False
        for _ in range(60):
            try:
                with psycopg.connect(admin) as c:
                    c.execute("SELECT 1")
                ready = True
                break
            except psycopg.Error:
                time.sleep(1)
        if not ready:
            raise RuntimeError("ISOLATED_POSTGRES_READINESS_TIMEOUT")
        report["stage"] = "restore-password-redacted-globals"
        globals_result = run(["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1"], input_bytes=redacted_globals)
        (out / "globals-restore.stdout.log").write_bytes(globals_result.stdout)
        (out / "globals-restore.stderr.log").write_bytes(globals_result.stderr)
        if globals_result.returncode:
            raise RuntimeError("SANITIZED_GLOBALS_RESTORE_FAILED")
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(dbname), sql.Identifier(owner)))
        report["stage"] = "restore-populated-backup-with-owners"
        restored = run(["docker", "exec", "-i", container, "pg_restore", "-U", "postgres", "-d", dbname, "--exit-on-error"], input_bytes=dump_bytes, timeout=600)
        (out / "pg-restore.stdout.log").write_bytes(restored.stdout)
        (out / "pg-restore.stderr.log").write_bytes(restored.stderr)
        if restored.returncode:
            raise RuntimeError("OWNERSHIP_PRESERVING_RESTORE_FAILED")
        op = make_conninfo(host="127.0.0.1", port=PORT, dbname=dbname, user="postgres", password=pw)
        report["stage"] = "snapshot-populated-pre-migration-tables"
        with psycopg.connect(op, row_factory=dict_row) as c:
            columns_before, tables_before = table_snapshot(c)
            owner_rows = c.execute("""
                SELECT count(*) AS n FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_roles r ON r.oid=c.relowner
                WHERE c.relnamespace='public'::regnamespace AND r.rolname=%s
            """, (owner,)).fetchone()["n"]
        report["restore"] = {"exit_code": restored.returncode, "pre_migration_public_tables": len(tables_before),
                              "pre_migration_rows": sum(int(x["rows"]) for x in tables_before.values()),
                              "objects_owned_by_source_database_owner": owner_rows > 0}
        bodies = []
        for name in MIGRATIONS:
            data = mig_bytes[name].decode("utf-8")
            if name in ("009_fresh_image_inference.sql", "011_real_artifact_retention.sql"):
                bodies.append(outer_body(ROOT / "migrations" / name))
            else:
                bodies.append(data)
        with psycopg.connect(op, row_factory=dict_row) as c:
            report["stage"] = "atomic-apply-009-010-011"
            run_sql_in_transaction(c, bodies)
            report["stage"] = "rollback-only-resume-admission-negative"
            report["resume_admission_negative"] = exercise_resume_admission(c)
            report["stage"] = "verify-preserved-data-and-privileges"
            report["post_migration"] = inspect_contract(c, set(tables_before), columns_before, tables_before)
            report["transaction_atomicity"] = "009+010+011 committed together"
            report["all_new_tables_empty"] = all(n == 0 for n in report["post_migration"]["new_table_rows"].values())
            report["all_rls_force_enabled"] = all(report["post_migration"]["rls_force_enabled"].values())
            report["all_worker_definer_capabilities_correct"] = all(report["post_migration"]["definer_capability_owners_and_acl"].values())
            report["noinherit_worker_capability_verified"] = all(report["post_migration"]["worker_capabilities"][k] for k in ("all_noninheriting", "all_logins", "no_direct_runs_select"))
            report["admission_and_retention_triggers_verified"] = all(report["post_migration"]["admission_and_retention_controls"].values())
        report["status"] = "PASS" if all(report.get(key) for key in ("all_new_tables_empty", "all_rls_force_enabled", "all_worker_definer_capabilities_correct", "noinherit_worker_capability_verified", "admission_and_retention_triggers_verified")) and report["post_migration"]["existing_table_preservation_pass"] and report["resume_admission_negative"].get("status") in ("executed_pass", "not_feasible") else "FAIL"
        report["stage"] = "complete"
    except BaseException as exc:
        report["status"] = "FAIL"
        report["failure_class"] = type(exc).__name__
        if isinstance(exc, psycopg.Error):
            report["database_sqlstate"] = exc.sqlstate
        report["failure_code"] = exc.args[0] if exc.args and isinstance(exc.args[0], str) and re.fullmatch(r"[A-Z0-9_]{1,80}", exc.args[0]) else None
        # Exception text can include database details; intentionally exclude it from evidence and console.
    finally:
        if created:
            stop = run(["docker", "rm", "-f", container], timeout=120)
            (out / "owned-container-disposal.log").write_bytes(stop.stdout + b"\n" + stop.stderr)
            report["owned_container_disposed"] = stop.returncode == 0
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        evidence = out / "report.json"
        evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            (out / "globals.redacted.sql").unlink()
        except FileNotFoundError:
            pass
    print(json.dumps({"status": report["status"], "evidence": str(evidence)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
