from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row

from fieldwork import scoped_authority as SA

ROOT = Path(__file__).resolve().parents[1]
TARGET_WORKSPACE = "814830e3-55a0-4925-ad37-5d3dac7d4df8"
TARGET_RUN = "4b71572f-9d06-4b9f-86fb-162aa4b18616"
MIGRATIONS = {
    "017_privacy_lifecycle.sql": "81e7587f33a5a30fa9a8c48369703a5c2266d3ad52926c28ab9b14974eb116ee",
    "018_worker_privacy_guard_execute.sql": "0073beb0c1fe6093ae5e63b062bb38a160bede8bcf062bf6244cdf505bf184c8",
}
MIGRATION_019_SHA256 = "8698b0f0c8e02d09f577e90d11673db336a8b71bcca944e275f4ddfd136bbf34"
CONTAINER_PREFIX = "fieldwork-lease-privacy019-"
PORT = 15547


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command, *, input_bytes=None, timeout=300, env=None):
    return subprocess.run(
        command,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        env=env,
    )


def resource_gate() -> dict:
    import psutil

    disk = shutil.disk_usage(ROOT.drive + "\\")
    vm = psutil.virtual_memory()
    sample = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object CommittedBytes,CommitLimit,PercentCommittedBytesInUse | ConvertTo-Json -Compress",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        text=True,
    )
    try:
        values = json.loads(sample.stdout)
        commit = int(values["PercentCommittedBytesInUse"])
        used = int(values["CommittedBytes"])
        limit = int(values["CommitLimit"])
    except Exception:
        raise RuntimeError("HOST_COMMIT_COUNTER_UNAVAILABLE") from None
    if sample.returncode or limit <= 0 or used > limit or disk.free < 50 * 1024**3 or vm.available <= 6 * 1024**3 or commit >= 85:
        raise RuntimeError("HOST_RESOURCE_GATE_REFUSED")
    return {
        "c_free_bytes": disk.free,
        "available_ram_bytes": vm.available,
        "commit_percent": commit,
        "commit_source": "Win32_PerfFormattedData_PerfOS_Memory",
        "committed_bytes": used,
        "commit_limit_bytes": limit,
    }


def migration_body(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    nonblank = [i for i, line in enumerate(lines) if line.strip()]
    first = next((i for i, line in enumerate(lines) if line.strip() and not line.lstrip().startswith("--")), None)
    if first is None or lines[first].strip().upper() != "BEGIN;" or lines[nonblank[-1]].strip().upper() != "COMMIT;":
        raise RuntimeError("MIGRATION_ENVELOPE_INVALID")
    return "".join(lines[:first] + lines[first + 1 : nonblank[-1]] + lines[nonblank[-1] + 1 :])


def safe_backup(manifest_path: Path) -> tuple[dict, bytes, bytes]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest_path.relative_to((ROOT / "var/snapshots").resolve(strict=True))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("container") != "fieldwork-postgres" or manifest.get("database") != "fieldwork":
        raise RuntimeError("BACKUP_DATABASE_IDENTITY_UNEXPECTED")
    dump = ROOT / manifest["db"]["path"]
    globals_file = ROOT / manifest["globals"]["path"]
    dump_raw = dump.read_bytes()
    globals_raw = globals_file.read_bytes()
    if sha(dump_raw) != manifest["db"]["sha256"] or sha(globals_raw) != manifest["globals"]["sha256"]:
        raise RuntimeError("BACKUP_DIGEST_MISMATCH")
    from fieldwork.scoped_authority import check_private

    check_private(dump)
    check_private(globals_file)
    return manifest, dump_raw, globals_raw


def catalog_state(connection) -> dict:
    rows = connection.execute(
        """SELECT pg_catalog.pg_get_userbyid(p.proowner) AS owner,
                  p.prosecdef AS secdef,p.proconfig AS config,p.proacl::text AS acl,
                  pg_catalog.has_function_privilege('fw_lease_machine_v1_owner',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS lease_owner_execute,
                  pg_catalog.has_function_privilege('fw_lease_machine_v1',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS lease_login_execute,
                  pg_catalog.has_function_privilege('fw_worker_v1_definer',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS worker_owner_execute,
                  pg_catalog.has_function_privilege('fieldwork_real_worker_definer',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS real_owner_execute,
                  pg_catalog.has_function_privilege('fieldwork_intake_worker',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS intake_execute,
                  pg_catalog.has_function_privilege('fieldwork_api',
                    'public.fw_privacy_workspace_deleted_v1(text)','EXECUTE') AS api_execute,
                  EXISTS(SELECT 1 FROM pg_catalog.aclexplode(p.proacl) a
                         WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
           FROM pg_catalog.pg_proc p
           WHERE p.oid='public.fw_privacy_workspace_deleted_v1(text)'::regprocedure"""
    ).fetchone()
    return dict(rows)


def target_state(connection) -> dict | None:
    row = connection.execute(
        """SELECT id,workspace,state,fence,revision,epoch,attempt,
                  lease<=clock_timestamp() AS overdue
           FROM public.fw_runs WHERE workspace=%s AND id=%s""",
        (TARGET_WORKSPACE, TARGET_RUN),
    ).fetchone()
    return dict(row) if row else None


def write_report(path: Path, report: dict) -> None:
    from fieldwork.scoped_authority import check_private

    temp = path.with_suffix(path.suffix + ".tmp")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(temp, "xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    check_private(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    from fieldwork.scoped_authority import check_private

    check_private(out)
    container = CONTAINER_PREFIX + stamp.lower()
    nonce = secrets.token_hex(16)
    created = False
    report = {
        "schema": "fieldwork.lease-privacy-guard-019-rehearsal/v1",
        "status": "RUNNING",
        "stage": "start",
        "live_database_touched": False,
        "target_workspace": TARGET_WORKSPACE,
        "target_run": TARGET_RUN,
        "container": container,
        "port": PORT,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }
    cleanup = {"attempted": False, "confirmed": False}
    try:
        report["host_resource_gate"] = resource_gate()
        manifest, dump_raw, globals_raw = safe_backup(args.backup_manifest)
        if not MIGRATION_019_SHA256 or sha((ROOT / "migrations/019_lease_privacy_guard_execute.sql").read_bytes()) != MIGRATION_019_SHA256:
            raise RuntimeError("MIGRATION_019_PIN_MISMATCH")
        source_pins = {
            f"migrations/{name}": sha((ROOT / "migrations" / name).read_bytes())
            for name in MIGRATIONS
        }
        if any(source_pins[f"migrations/{name}"] != expected for name, expected in MIGRATIONS.items()):
            raise RuntimeError("SOURCE_PIN_MISMATCH")
        source_pins["migrations/019_lease_privacy_guard_execute.sql"] = MIGRATION_019_SHA256
        source_pins["tools/rehearse_lease_privacy_019.py"] = sha(Path(__file__).read_bytes())
        report["source_sha256"] = source_pins
        report["backup"] = {
            "manifest": str(args.backup_manifest.resolve().relative_to(ROOT)).replace("\\", "/"),
            "dump_bytes": len(dump_raw),
            "dump_sha256": sha(dump_raw),
            "globals_sha256": sha(globals_raw),
        }

        local = json.loads((ROOT / ".local.json").read_text(encoding="utf-8"))
        live = conninfo_to_dict(local["dsn"])
        if live.get("host") not in ("127.0.0.1", "::1") or live.get("port") != "5542" or live.get("dbname") != "fieldwork":
            raise RuntimeError("LIVE_DATABASE_IDENTITY_REFUSED")
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", PORT))
            except OSError:
                raise RuntimeError("SCRATCH_PORT_NOT_FREE") from None
        if run(["docker", "inspect", container]).returncode == 0:
            raise RuntimeError("OWNED_CONTAINER_NAME_ALREADY_EXISTS")
        image = run(["docker", "inspect", "fieldwork-postgres", "--format={{.Image}}"])
        image_id = image.stdout.decode("ascii", "strict").strip()
        if image.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise RuntimeError("LOCAL_POSTGRES_IMAGE_UNAVAILABLE")
        report["postgres_image_id"] = image_id

        password = secrets.token_urlsafe(32)
        env = dict(os.environ)
        env["POSTGRES_PASSWORD"] = password
        started = run(
            [
                "docker", "run", "--pull=never", "-d", "--name", container,
                "--label", "fieldwork.owner=lease-privacy019-rehearsal",
                "--label", "fieldwork.nonce=" + nonce,
                "-p", f"127.0.0.1:{PORT}:5432",
                "-e", "POSTGRES_USER=postgres", "-e", "POSTGRES_PASSWORD",
                "--memory", "768m", "--cpus", "1.0", "--shm-size", "64m",
                "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m", image_id,
            ],
            timeout=120,
            env=env,
        )
        if started.returncode:
            raise RuntimeError("SCRATCH_POSTGRES_START_FAILED")
        created = True
        admin_dsn = make_conninfo(host="127.0.0.1", port=PORT, dbname="postgres", user="postgres", password=password, connect_timeout=3)
        ready = False
        for _ in range(60):
            try:
                with psycopg.connect(admin_dsn) as connection:
                    connection.execute("SELECT 1")
                ready = True
                break
            except psycopg.Error:
                time.sleep(1)
        if not ready:
            raise RuntimeError("SCRATCH_POSTGRES_READINESS_TIMEOUT")

        safe_globals = re.sub(rb"(?i)\s+PASSWORD\s+(?:'[^']*'|NULL)", b"", globals_raw)
        if re.search(rb"(?i)PASSWORD\s+", safe_globals):
            raise RuntimeError("GLOBAL_PASSWORD_REDACTION_INCOMPLETE")
        if run(["docker", "exec", "-i", container, "psql", "-X", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1"], input_bytes=safe_globals).returncode:
            raise RuntimeError("SANITIZED_GLOBALS_RESTORE_FAILED")

        owner = live["user"]
        dbname = live["dbname"]
        with psycopg.connect(admin_dsn, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(dbname), sql.Identifier(owner)))
        restored = run(["docker", "exec", "-i", container, "pg_restore", "-U", "postgres", "-d", dbname, "--exit-on-error"], input_bytes=dump_raw, timeout=600)
        if restored.returncode:
            raise RuntimeError("OWNERSHIP_PRESERVING_RESTORE_FAILED")
        scratch_dsn = make_conninfo(host="127.0.0.1", port=PORT, dbname=dbname, user="postgres", password=password, connect_timeout=5)

        live_authority_path = Path(r"C:\Users\user\.portfolio-local-access\fw-authority-a7c9-28ec9975bfa84c38ad86b61a04442feb\authority.json")
        check_private(live_authority_path)
        live_authority = SA.validate(json.loads(live_authority_path.read_text(encoding="utf-8")))
        if live_authority["workspaces"] != ["*"]:
            raise RuntimeError("SCOPED_AUTHORITY_SCOPE_DRIFT")
        login = live_authority["connection"]["user"]
        scratch_password = secrets.token_urlsafe(32)

        with psycopg.connect(scratch_dsn, row_factory=dict_row, autocommit=True) as admin:
            pre = catalog_state(admin)
            row = target_state(admin)
            scope = admin.execute("SELECT principal,workspaces,version,owner FROM fw_lease_cap_v1.scope WHERE principal=%s", (login,)).fetchone()
            if pre["lease_owner_execute"] or pre["lease_login_execute"] or pre["public_execute"]:
                raise RuntimeError("SCRATCH_019_MISSING_GRANT_PRECONDITION")
            if not scope or scope["workspaces"] != ["*"] or scope["owner"] != login + "_owner":
                raise RuntimeError("SCRATCH_CONTROLLER_SCOPE_MISMATCH")
            if not row or row["workspace"] != TARGET_WORKSPACE or row["state"] != "cancel_requested" or not row["overdue"]:
                raise RuntimeError("SCRATCH_TARGET_RUN_PRECONDITION_FAILED")
            admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(login), sql.Literal(scratch_password)))

        scratch_authority = {
            "purpose": "fieldwork-training-lease-controller",
            "authority_mode": SA.MODE,
            "capability_schema": SA.SCHEMA,
            "capability_version": 1,
            "workspaces": ["*"],
            "connection": {
                "host": "127.0.0.1", "port": PORT, "dbname": dbname,
                "user": login, "password": scratch_password, "sslmode": "disable",
            },
        }
        scratch_authority = SA.validate(scratch_authority)
        backend = SA.MachineBackend(scratch_authority)
        backend.verify()
        report["stage"] = "apply_018_before_019_probe"
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as admin:
            admin.execute(migration_body(ROOT / "migrations/018_worker_privacy_guard_execute.sql"))
            post_018 = catalog_state(admin)
            if not post_018["worker_owner_execute"] or post_018["lease_owner_execute"] or post_018["public_execute"]:
                raise RuntimeError("SCRATCH_018_POST_ACL_MISMATCH")
        report["post_018"] = {
            "worker_owner_execute": post_018["worker_owner_execute"],
            "lease_owner_execute": post_018["lease_owner_execute"],
            "lease_login_execute": post_018["lease_login_execute"],
            "public_execute": post_018["public_execute"],
        }
        backend.verify()
        candidates = backend.candidates("", 32)
        if len(candidates) != 1 or candidates[0].get("id") != TARGET_RUN:
            raise RuntimeError("SCRATCH_EXPIRE_CANDIDATE_SET_MISMATCH")
        candidate = candidates[0]
        report["stage"] = "apply_019_after_reproduced_42501"
        try:
            backend.expire(candidate)
            raise RuntimeError("SCRATCH_019_FAILURE_NOT_REPRODUCED")
        except psycopg.errors.InsufficientPrivilege as exc:
            if exc.sqlstate != "42501":
                raise RuntimeError("SCRATCH_019_UNEXPECTED_PRE_ERROR") from None
            pre_sqlstate = exc.sqlstate
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as admin:
            unchanged = target_state(admin)
            if not unchanged or unchanged["state"] != row["state"] or unchanged["fence"] != row["fence"] or unchanged["revision"] != row["revision"]:
                raise RuntimeError("SCRATCH_PRE_FAILURE_CHANGED_RUN")
        report["pre_019"] = {
            "lease_owner_execute": post_018["lease_owner_execute"],
            "lease_login_execute": post_018["lease_login_execute"],
            "public_execute": post_018["public_execute"],
            "expire_sqlstate": pre_sqlstate,
            "run_state_after_denied_call": unchanged["state"],
            "fence_after_denied_call": unchanged["fence"],
            "revision_after_denied_call": unchanged["revision"],
            "candidate_count": len(candidates),
        }
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as admin:
            admin.execute(migration_body(ROOT / "migrations/019_lease_privacy_guard_execute.sql"))
            post = catalog_state(admin)
        if not post["lease_owner_execute"] or post["lease_login_execute"] or post["public_execute"] or not post["worker_owner_execute"]:
            raise RuntimeError("SCRATCH_019_POST_ACL_FAILED")
        backend.verify()
        candidates_after = backend.candidates("", 32)
        if len(candidates_after) != 1 or candidates_after[0].get("id") != TARGET_RUN:
            raise RuntimeError("SCRATCH_POST_EXPIRE_CANDIDATE_SET_MISMATCH")
        report["stage"] = "expire_exact_run_after_019"
        transition = backend.expire(candidates_after[0])
        with psycopg.connect(scratch_dsn, row_factory=dict_row) as admin:
            after = target_state(admin)
            slot = admin.execute("SELECT run,launching FROM public.fw_slot WHERE id=1").fetchone()
        if (
            not transition
            or transition.get("run") != TARGET_RUN
            or transition.get("state") != "cancelled"
            or not after
            or after["state"] != "cancelled"
            or after["fence"] != row["fence"] + 1
            or after["revision"] != row["revision"] + 1
            or slot["run"] is not None
            or slot["launching"]
            or backend.candidates("", 32)
        ):
            raise RuntimeError("SCRATCH_019_EXPIRY_POSTCONDITION_FAILED")
        report["post_019"] = {
            "lease_owner_execute": post["lease_owner_execute"],
            "lease_login_execute": post["lease_login_execute"],
            "public_execute": post["public_execute"],
            "worker_owner_execute": post["worker_owner_execute"],
            "transition_state": transition.get("state"),
            "target_state": after["state"],
            "fence": after["fence"],
            "revision": after["revision"],
            "slot_empty": slot["run"] is None and not slot["launching"],
            "remaining_candidate_count": 0,
        }
        report["status"] = "PASS"
        report["stage"] = "verified"
    except Exception as exc:
        message = getattr(getattr(exc, "diag", None), "message_primary", "")
        sqlstate = getattr(exc, "sqlstate", None)
        text = message if isinstance(message, str) and re.fullmatch(r"019_[A-Z0-9_]+", message) else str(exc)
        report.update(
            status="FAIL",
            error_code=text if text.isupper() and len(text) < 100 else "REHEARSAL_EXCEPTION_" + type(exc).__name__,
            error_sqlstate=sqlstate,
            failed_stage=report.get("stage"),
        )
    finally:
        cleanup = {"attempted": created, "confirmed": not created}
        if created:
            inspected = run(["docker", "inspect", container, "--format={{json .Config.Labels}}"], timeout=30)
            try:
                labels = json.loads(inspected.stdout.decode("utf-8", "strict")) if inspected.returncode == 0 else {}
            except Exception:
                labels = {}
            if inspected.returncode == 0 and labels.get("fieldwork.owner") == "lease-privacy019-rehearsal" and labels.get("fieldwork.nonce") == nonce:
                removed = run(["docker", "rm", "-f", container], timeout=60)
                absent = run(["docker", "inspect", container], timeout=20).returncode != 0
                cleanup["confirmed"] = removed.returncode == 0 and absent
            else:
                cleanup["confirmed"] = False
        report["scratch_container_cleanup"] = cleanup
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_report(out / "rehearsal.json", report)
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "failed_stage": report.get("failed_stage"),
                "error_code": report.get("error_code"),
                "report": str((out / "rehearsal.json").relative_to(ROOT)).replace("\\", "/"),
                "cleanup_confirmed": cleanup["confirmed"],
            }
        )
    )
    return 0 if report.get("status") == "PASS" and cleanup["confirmed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
