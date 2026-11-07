"""Restore the retained post-003/006 snapshot into an isolated PG container and apply 007."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / ".local/backups/w3-20261101T180956Z/post-003-006.dump"
MIGRATION = ROOT / "migrations/007_real_run_worker.sql"
EVIDENCE = ROOT / "evidence/real-run-007-rehearsal"
IMAGE = "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
NAME = "fw-real007-rehearsal"
PORT = "15542"
DB = "fieldwork_rehearsal"


def run(args: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result


def docker_sql(sql: str, *, user: str = "postgres", check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["docker", "exec", "-i", NAME, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
                "-U", user, "-d", DB, "-At"], input_text=sql, check=check)


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    raw = EVIDENCE / stamp
    raw.mkdir()
    if not BACKUP.is_file() or not MIGRATION.is_file():
        raise FileNotFoundError("expected retained backup or migration is missing")
    backup_hash = hashlib.sha256(BACKUP.read_bytes()).hexdigest()
    migration_hash_before = hashlib.sha256(MIGRATION.read_bytes()).hexdigest()
    if run(["docker", "inspect", NAME], check=False).returncode == 0:
        raise RuntimeError(f"refusing to reuse pre-existing container {NAME}")

    report: dict[str, object] = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "container": NAME,
        "image": IMAGE,
        "port_binding": f"127.0.0.1:{PORT}:5432",
        "limits": {"memory": "512m", "cpus": "1", "pgdata_tmpfs": "512m"},
        "backup": str(BACKUP),
        "backup_sha256": backup_hash,
        "migration": str(MIGRATION),
        "migration_sha256_before": migration_hash_before,
        "steps": [],
    }
    log_path = raw / "commands.log"
    command_lines: list[str] = []
    code = 0
    created = False
    try:
        c = run(["docker", "run", "--detach", "--name", NAME,
                 "--memory", "512m", "--cpus", "1",
                 "--publish", f"127.0.0.1:{PORT}:5432",
                 "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m",
                 "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
                 "--env", f"POSTGRES_DB={DB}", IMAGE], check=True)
        created = True
        command_lines.append(f"docker run -> {c.stdout.strip()}")
        run(["docker", "cp", str(BACKUP), f"{NAME}:/tmp/post-003-006.dump"])
        command_lines.append("copied retained post-003/006 archive into isolated container")

        # Wait for the newly initialized temporary server.
        for _ in range(30):
            ready = run(["docker", "exec", NAME, "pg_isready", "-U", "postgres", "-d", DB], check=False)
            command_lines.append(f"pg_isready exit={ready.returncode}")
            if ready.returncode == 0:
                break
            import time
            time.sleep(1)
        else:
            raise RuntimeError("isolated PostgreSQL did not become ready")

        # Export roles with passwords omitted from the actual retained cluster.
        roles = run(["docker", "exec", "fieldwork-postgres", "sh", "-lc",
                     'pg_dumpall -U "$POSTGRES_USER" --roles-only --no-role-passwords'], check=True)
        (raw / "roles-no-passwords.sql").write_text(roles.stdout, encoding="utf-8")
        existing = set(docker_sql("SELECT rolname FROM pg_roles ORDER BY rolname;", check=True).stdout.splitlines())
        role_statements = []
        skipped_existing: list[str] = []
        for line in roles.stdout.splitlines():
            match = re.fullmatch(r'CREATE ROLE (?:"((?:[^"]|"")+)"|([^;\s]+));', line)
            if match:
                role_name = (match.group(1).replace('""', '"') if match.group(1) else match.group(2))
                if role_name in existing:
                    skipped_existing.append(role_name)
                    continue
            role_statements.append(line)
        role_sql = "\n".join(role_statements) + "\n"
        (raw / "roles-import.sql").write_text(role_sql, encoding="utf-8")
        run(["docker", "exec", "-i", NAME, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", DB],
            input_text=role_sql)
        command_lines.append("imported password-free retained role dump; skipped pre-created cluster role names only")
        report["role_names_skipped_as_precreated"] = skipped_existing

        # Restore the custom-format post-003/006 database. Keep ACLs, while making
        # the isolated init role own restored objects so it can execute migration.
        restored = run(["docker", "exec", NAME, "pg_restore", "--exit-on-error", "--no-owner",
                        "-U", "postgres", "-d", DB, "/tmp/post-003-006.dump"])
        command_lines.append("pg_restore post-003-006.dump --no-owner")
        report["steps"].append({"restore_exit": restored.returncode})
        source_state = docker_sql("SELECT current_setting('server_version'); SELECT count(*) FROM public.fw_runs; "
                                  "SELECT count(*) FROM public.fw_samples; SELECT count(*) FROM public.fw_rights_decisions; "
                                  "SELECT count(*) FROM public.fw_attempts;")
        source_lines = source_state.stdout.splitlines()
        report["pre_migration_db_checks"] = {"server_version": source_lines[0],
            "runs": source_lines[1], "samples": source_lines[2], "rights_decisions": source_lines[3],
            "attempts": source_lines[4]}
        (raw / "pre-migration-checks.txt").write_text(source_state.stdout, encoding="utf-8")

        migration_text = MIGRATION.read_text(encoding="utf-8")
        apply = run(["docker", "exec", "-i", NAME, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", DB],
                    input_text=migration_text, check=False)
        (raw / "migration.stdout.txt").write_text(apply.stdout, encoding="utf-8")
        (raw / "migration.stderr.txt").write_text(apply.stderr, encoding="utf-8")
        report["steps"].append({"migration_apply_exit": apply.returncode})
        command_lines.append(f"migration apply exit={apply.returncode}")
        if apply.returncode:
            raise subprocess.CalledProcessError(apply.returncode, "psql migration 007", apply.stdout, apply.stderr)

        # Confirm capability creation, constraints, and least-privilege boundary
        # using one actual registered worker principal where the retained scope has one.
        catalog_sql = """
SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='fw_real_worker_cap_v1')::text;
SELECT (SELECT rolsuper OR rolbypassrls OR rolcanlogin FROM pg_roles WHERE rolname='fieldwork_real_worker_definer')::text;
SELECT coalesce((SELECT principal FROM fw_worker_cap_v1.scope ORDER BY principal LIMIT 1),'');
"""
        catalog = docker_sql(catalog_sql)
        vals = catalog.stdout.splitlines()
        if len(vals) < 3:
            raise RuntimeError("catalog smoke returned incomplete results")
        fn_count, unsafe_owner, principal = vals[:3]
        report["post_migration_catalog"] = {"real_function_count": int(fn_count),
            "definer_any_super_bypass_or_login": unsafe_owner, "sample_worker_principal": principal or None}
        if int(fn_count) != 12 or unsafe_owner != "false":
            raise RuntimeError("capability catalog or NOLOGIN definer invariant failed")
        if not principal:
            report["worker_role_smoke"] = "skipped: retained worker scope is empty"
        else:
            # Use identifier quoting in SQL generated from a trusted role catalog value.
            ident = '"' + principal.replace('"', '""') + '"'
            smoke = f"""
BEGIN;
SET LOCAL ROLE {ident};
SELECT has_schema_privilege(current_user,'fw_real_worker_cap_v1','USAGE');
SELECT has_function_privilege(current_user,'fw_real_worker_cap_v1.next_real_run(text[])','EXECUTE');
SELECT has_function_privilege(current_user,'fw_real_worker_cap_v1.real_inputs(text,text,text,integer,integer,uuid)','EXECUTE');
SELECT has_function_privilege(current_user,'fw_real_worker_cap_v1.profile_ok(jsonb,text,text)','EXECUTE');
SELECT has_table_privilege(current_user,'public.fw_runs','SELECT');
SELECT fw_real_worker_cap_v1.next_real_run(ARRAY[]::text[]) IS NULL;
ROLLBACK;
"""
            smoke_result = docker_sql(smoke)
            (raw / "worker-privilege-smoke.txt").write_text(smoke_result.stdout, encoding="utf-8")
            checks = smoke_result.stdout.splitlines()
            expected = ["t", "t", "t", "f", "f", "t"]
            if checks != expected:
                raise RuntimeError(f"worker privilege smoke mismatch: {checks}")
            report["worker_role_smoke"] = {"principal": principal,
                "assertions": ["schema usage", "queue and real-input function execute", "private profile helper denied",
                               "direct fw_runs SELECT denied", "empty real queue returns no job"]}

        after = docker_sql("SELECT count(*) FROM public.fw_runs; SELECT count(*) FROM public.fw_samples; "
                           "SELECT count(*) FROM public.fw_rights_decisions; "
                           "SELECT count(*) FROM public.fw_attempts;")
        after_lines = after.stdout.splitlines()
        report["post_smoke_counts"] = {"runs": after_lines[0], "samples": after_lines[1],
            "rights_decisions": after_lines[2], "attempts": after_lines[3]}
        if after_lines != source_lines[1:]:
            raise RuntimeError("bounded smoke changed retained runs/samples/rights/attempts counts")
        report["migration_sha256_after"] = hashlib.sha256(MIGRATION.read_bytes()).hexdigest()
        if report["migration_sha256_after"] != migration_hash_before:
            raise RuntimeError("candidate migration changed during rehearsal")
        report["result"] = "PASS"
    except Exception as exc:
        code = 1
        report["result"] = "FAIL"
        report["failure"] = f"{type(exc).__name__}: {exc}"
    finally:
        if created:
            logs = run(["docker", "logs", NAME], check=False)
            (raw / "postgres-container.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
            removed = run(["docker", "rm", "--force", NAME], check=False)
            command_lines.append(f"removed owned disposable container exit={removed.returncode}")
            report["container_removed"] = removed.returncode == 0
        (raw / "commands.log").write_text("\n".join(command_lines) + "\n", encoding="utf-8")
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        report["raw_evidence_directory"] = str(raw)
        (raw / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
