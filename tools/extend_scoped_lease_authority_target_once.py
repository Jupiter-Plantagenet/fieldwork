from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

from fieldwork import scoped_authority as SA
from fieldwork.worker_identity import write_authority

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
AUTHORITY = Path(
    r"C:\Users\user\.portfolio-local-access\fw-authority-a7c9-28ec9975bfa84c38ad86b61a04442feb\authority.json"
)
TARGET = "814830e3-55a0-4925-ad37-5d3dac7d4df8"
DENIAL_SENTINEL = "00000000-0000-4000-8000-000000000000"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_lock() -> dict:
    import psutil

    path = REPO / ".cache/product-build.lock/owner.json"
    owner = json.loads(path.read_text(encoding="utf-8"))
    ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
    if (
        owner.get("product") != "fieldwork"
        or owner.get("purpose") != "fieldwork-real-activation"
        or (owner.get("pid"), owner.get("create_time")) not in ancestors
    ):
        raise RuntimeError("FIELDWORK_REAL_ACTIVATION_LOCK_REQUIRED")
    return {"product": "fieldwork", "purpose": "fieldwork-real-activation", "pid": owner["pid"]}


def require_controller_absent(authority_path: Path) -> None:
    import psutil

    canonical = str(authority_path.resolve()).casefold()
    matches = []
    for process in psutil.process_iter(["pid", "create_time", "exe", "cwd", "cmdline"]):
        try:
            args = [str(x) for x in (process.info.get("cmdline") or [])]
            folded = [arg.casefold() for arg in args]
            exe = Path(process.info.get("exe") or "").name.casefold()
            module = any(folded[i : i + 2] == ["-m", "fieldwork.lease_recovery"] for i in range(len(folded) - 1))
            authority = any(
                folded[i] == "--authority-file"
                and str(Path(args[i + 1]).resolve()).casefold() == canonical
                for i in range(len(args) - 1)
            )
            cwd = str(process.info.get("cwd") or "").casefold()
            if exe in {"python.exe", "pythonw.exe"} and module and authority and cwd == str(ROOT).casefold():
                matches.append({"pid": process.info["pid"], "create_time": process.info.get("create_time")})
        except (OSError, psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if matches:
        raise RuntimeError("SCOPED_CONTROLLER_STILL_RUNNING")


def private_write(path: Path, value: dict) -> None:
    from fieldwork.scoped_authority import check_private

    temp = path.with_suffix(path.suffix + ".tmp")
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(temp, "xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    check_private(path)


def backup_file(item: dict) -> dict:
    from fieldwork.scoped_authority import check_private

    rel = Path(item.get("path", ""))
    if rel.is_absolute() or ".." in rel.parts or rel.parts[:2] != ("var", "snapshots"):
        raise RuntimeError("BACKUP_FILE_PATH_INVALID")
    path = ROOT / rel
    check_private(path)
    raw = path.read_bytes()
    result = {"path": rel.as_posix(), "bytes": len(raw), "sha256": sha(raw)}
    if result["bytes"] != item.get("bytes") or result["sha256"] != item.get("sha256"):
        raise RuntimeError("BACKUP_FILE_DIGEST_MISMATCH")
    return result


def database_identity(connection) -> dict:
    row = connection.execute(
        """SELECT pg_catalog.current_database() AS database, d.oid AS database_oid,
                  (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier
           FROM pg_catalog.pg_database d WHERE d.datname=pg_catalog.current_database()"""
    ).fetchone()
    return dict(row) if row else {}


def function_snapshot(connection, owner: str) -> dict:
    rows = connection.execute(
        """SELECT p.proname, p.prosrc, p.prosecdef, p.proconfig,
                  pg_catalog.pg_get_userbyid(p.proowner) AS owner,
                  p.proacl::text AS acl
           FROM pg_catalog.pg_proc p
           JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
           WHERE n.nspname='fw_lease_cap_v1'
             AND p.proname IN ('allowed','info','expire')
           ORDER BY p.proname"""
    ).fetchall()
    if len(rows) != 3 or any(row["owner"] != owner or not row["prosecdef"] for row in rows):
        raise RuntimeError("CONTROLLER_FUNCTION_OWNER_OR_COUNT_DRIFT")
    expected = {"allowed": SA.ALLOWED, "info": SA.INFO, "expire": SA.EXPIRE}
    if any(
        row["prosrc"] != expected.get(row["proname"])
        or row["proconfig"] != ["search_path=pg_catalog, pg_temp"]
        for row in rows
    ):
        raise RuntimeError("CONTROLLER_FUNCTION_SOURCE_DRIFT")
    return {
        row["proname"]: {
            "source_sha256": sha(row["prosrc"].encode("utf-8")),
            "owner": row["owner"],
            "security_definer": row["prosecdef"],
            "config": row["proconfig"],
            "acl": row["acl"],
        }
        for row in rows
    }


def main() -> None:
    lock = require_lock()
    from fieldwork.scoped_authority import check_private

    check_private(AUTHORITY)
    authority = SA.validate(json.loads(AUTHORITY.read_text(encoding="utf-8")))
    if "*" in authority["workspaces"] or TARGET in authority["workspaces"]:
        raise RuntimeError("SCOPE_EXTENSION_PRECONDITION_FAILED")
    old_scopes = list(authority["workspaces"])
    new_scopes = sorted(set(old_scopes) | {TARGET})
    require_controller_absent(AUTHORITY)

    local = json.loads((ROOT / ".local.json").read_text(encoding="utf-8"))
    dsn = local.get("dsn")
    params = conninfo_to_dict(dsn) if isinstance(dsn, str) else {}
    if params.get("host") not in {"127.0.0.1", "::1"} or params.get("port") != "5542" or params.get("dbname") != "fieldwork":
        raise RuntimeError("RETAINED_DATABASE_IDENTITY_REFUSED")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    authority_backup = AUTHORITY.with_name(AUTHORITY.name + ".before-target-scope-" + stamp)
    shutil.copy2(AUTHORITY, authority_backup)
    check_private(authority_backup)
    authority_backup_sha = sha(authority_backup.read_bytes())
    if authority_backup_sha != sha(AUTHORITY.read_bytes()):
        raise RuntimeError("AUTHORITY_BACKUP_MISMATCH")

    label = "fieldwork-lease-scope-extension-" + stamp
    backup = subprocess.run(
        [sys.executable, "-B", "-m", "tools.r5p_backup", label],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )
    if backup.returncode:
        raise RuntimeError("FRESH_BACKUP_FAILED")
    manifests = sorted((ROOT / "var/snapshots").glob(label + "-*.json"))
    if len(manifests) != 1:
        raise RuntimeError("FRESH_BACKUP_MANIFEST_AMBIGUOUS")
    manifest_path = manifests[0]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("container") != "fieldwork-postgres" or manifest.get("database") != "fieldwork":
        raise RuntimeError("FRESH_BACKUP_DATABASE_IDENTITY")
    backup_files = {name: backup_file(manifest.get(name, {})) for name in ("db", "globals")}

    owner = authority["connection"]["user"] + "_owner"
    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        identity = database_identity(connection)
        functions_before = function_snapshot(connection, owner)
        scope_rows = connection.execute("SELECT principal,workspaces,version,owner FROM fw_lease_cap_v1.scope ORDER BY principal").fetchall()
        queued_before = connection.execute("SELECT count(*)::bigint AS count FROM public.fw_runs WHERE state='queued'").fetchone()["count"]
        if (
            identity.get("database") != "fieldwork"
            or identity.get("database_oid") != 16384
            or identity.get("system_identifier") != "7700868276222033955"
            or len(scope_rows) != 1
            or scope_rows[0]["principal"] != authority["connection"]["user"]
            or scope_rows[0]["owner"] != owner
            or list(scope_rows[0]["workspaces"]) != old_scopes
        ):
            raise RuntimeError("SCOPED_AUTHORITY_OR_DATABASE_PRECONDITION_FAILED")

    before_receipt = {
        "schema": "fieldwork.scoped-lease-authority-target-extension/v1",
        "status": "prepared",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "lock": lock,
        "target_workspace": TARGET,
        "scope_before": old_scopes,
        "scope_after": new_scopes,
        "authority_path": str(AUTHORITY),
        "authority_backup_sha256": authority_backup_sha,
        "authority_source_sha256": sha(AUTHORITY.read_bytes()),
        "database_identity": identity,
        "function_before": functions_before,
        "queued_count_before": queued_before,
        "backup": {
            "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
            "db": backup_files["db"],
            "globals": backup_files["globals"],
        },
    }
    out = ROOT / ".local/real-data/activation"
    from fieldwork.scoped_authority import check_private

    check_private(out)
    receipt_path = out / ("lease-scope-extension-" + stamp + ".json")
    private_write(receipt_path, before_receipt)

    upgraded = SA.upgrade(
        lambda: psycopg.connect(dsn, row_factory=dict_row, options="-c search_path=pg_catalog,pg_temp"),
        authority,
        new_scopes,
    )
    write_authority(AUTHORITY, upgraded)
    check_private(AUTHORITY)
    reread = SA.validate(json.loads(AUTHORITY.read_text(encoding="utf-8")))
    if reread["workspaces"] != new_scopes or reread["connection"]["password"] != authority["connection"]["password"]:
        raise RuntimeError("SCOPED_AUTHORITY_FILE_POSTCONDITION_FAILED")

    backend = SA.MachineBackend(reread)
    backend.verify()
    with backend.connect() as machine:
        allowed = machine.execute("SELECT fw_lease_cap_v1.allowed(%s) AS allowed", (DENIAL_SENTINEL,)).fetchone()["allowed"]
        hidden = machine.execute("SELECT id FROM public.fw_runs WHERE workspace=%s LIMIT 1", (DENIAL_SENTINEL,)).fetchone()
        if allowed or hidden is not None:
            raise RuntimeError("OUT_OF_SCOPE_WORKSPACE_ACCESS")

    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        identity_after = database_identity(connection)
        functions_after = function_snapshot(connection, owner)
        scope_after = connection.execute("SELECT principal,workspaces,version,owner FROM fw_lease_cap_v1.scope ORDER BY principal").fetchall()
        queued_after = connection.execute("SELECT count(*)::bigint AS count FROM public.fw_runs WHERE state='queued'").fetchone()["count"]
        if (
            identity_after != identity
            or functions_after != functions_before
            or len(scope_after) != 1
            or scope_after[0]["principal"] != authority["connection"]["user"]
            or scope_after[0]["workspaces"] != new_scopes
            or scope_after[0]["owner"] != owner
            or queued_after != queued_before
        ):
            raise RuntimeError("SCOPED_AUTHORITY_POSTCONDITION_FAILED")

    before_receipt.update(
        {
            "status": "applied",
            "committed_utc": datetime.now(timezone.utc).isoformat(),
            "scope_after_readback": new_scopes,
            "function_after": functions_after,
            "queued_count_after": queued_after,
            "out_of_scope_allowed": allowed,
            "out_of_scope_rows_visible": hidden is not None,
            "authority_after_sha256": sha(AUTHORITY.read_bytes()),
        }
    )
    private_write(receipt_path, before_receipt)
    print(
        json.dumps(
            {
                "status": "applied",
                "target_workspace": TARGET,
                "scope_count": len(new_scopes),
                "out_of_scope_denied": not allowed and hidden is None,
                "queued_count": queued_after,
                "receipt": str(receipt_path.relative_to(ROOT)).replace("\\", "/"),
            }
        )
    )


if __name__ == "__main__":
    main()
