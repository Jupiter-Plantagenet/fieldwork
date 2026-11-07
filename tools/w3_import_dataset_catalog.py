"""Import the retained round-4 catalog into the retained Fieldwork database.

The source and target DSNs are read only in memory from .local.json. The tool emits
aggregate receipts only; it never writes row values, credentials, DSNs, or protected
sample identities to a receipt or console.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DB = "fieldwork_round4_dataset"
TARGET_DB = "fieldwork"
WORKSPACE = "814830e3-55a0-4925-ad37-5d3dac7d4df8"
MEDIA_SOURCE_ROOT = ROOT / "var/datasets/tf_flowers/media"
MEDIA_TARGET_ROOT = ROOT / ".local/real-data/media"
REGISTRY_PATH = ROOT / "var/commons_r5/rights/reviewers.json"
EVIDENCE_ROOT = ROOT / "evidence/w3-dataset-catalog-import"
CONTAINER_SOURCE = "fieldwork-postgres"
CONTAINER_PORT = "15542"
CONTAINER_MEMORY = "512m"
CONTAINER_CPUS = "1"
CONTAINER_PGDATA_TMPFS = "512m"

TABLES = (
    "fw_accounts",
    "fw_rights_datasets",
    "fw_rights_assets",
    "fw_rights_decisions",
    "fw_intake_batches",
    "fw_samples",
    "fw_intake_members",
    "fw_versions",
    "fw_proposals",
    "fw_holdout_stewards",
    "fw_holdout_plans",
    "fw_holdout_exposures",
)
WORKSPACE_TABLES = tuple(t for t in TABLES if t != "fw_accounts")
PK_ORDER = {
    "fw_accounts": ("name",),
    "fw_rights_datasets": ("workspace", "dataset_id"),
    "fw_rights_assets": ("workspace", "dataset_id", "member_id"),
    "fw_rights_decisions": ("workspace", "dataset_id", "member_id", "purpose"),
    "fw_intake_batches": ("workspace", "batch_id"),
    "fw_samples": ("workspace", "sample_id"),
    "fw_intake_members": ("workspace", "batch_id", "ordinal"),
    "fw_versions": ("workspace", "id"),
    "fw_proposals": ("workspace", "id"),
    "fw_holdout_stewards": ("workspace", "actor"),
    "fw_holdout_plans": ("workspace", "plan_id"),
    "fw_holdout_exposures": ("workspace", "plan_id", "seq"),
}
PROTECTED_SPLITS = ("holdout", "protected", "holdout_population")
TRAINING_SPLITS = ("train", "validation")
PROTECTED_EXISTS = """EXISTS (
  SELECT 1 FROM public.fw_versions v
  CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(v.manifest->'samples')='array' THEN v.manifest->'samples' ELSE '[]'::jsonb END
  ) AS manifest_item(item)
  WHERE v.workspace=s.workspace
    AND (manifest_item.item->>'id'=s.sample_id::text
         OR manifest_item.item->>'sha256'=s.raw_sha256
         OR manifest_item.item->>'pixel_sha256'=s.pixel_sha256)
    AND (manifest_item.item->>'split'=ANY(%s::text[])
         OR manifest_item.item ? 'holdout_population'
         OR manifest_item.item->>'protected'='true')
)"""
ELIGIBLE_EXISTS = """EXISTS (
  SELECT 1 FROM public.fw_versions v
  CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(v.manifest->'samples')='array' THEN v.manifest->'samples' ELSE '[]'::jsonb END
  ) AS manifest_item(item)
  WHERE v.workspace=s.workspace AND manifest_item.item->>'id'=s.sample_id::text
    AND manifest_item.item->>'split'=ANY(%s::text[])
)"""


class ImportRefused(RuntimeError):
    def __init__(self, code: str, details: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def _value(row, index=0):
    """Scalar metadata queries use the connection's dictionary row factory too."""
    return tuple(row.values())[index]


def _source_admin_dsn() -> str:
    """Load the local DSN in memory and return a source database conninfo string."""
    local_config = ROOT / ".local.json"
    if local_config.is_symlink():
        raise ImportRefused("LOCAL_DSN_FILE_SYMLINK_REFUSED")
    doc = json.loads(local_config.read_text(encoding="utf-8"))
    values = conninfo_to_dict(doc["dsn"])
    values["dbname"] = SOURCE_DB
    return make_conninfo(**values)


def _target_admin_dsn(dbname: str = TARGET_DB) -> str:
    local_config = ROOT / ".local.json"
    if local_config.is_symlink():
        raise ImportRefused("LOCAL_DSN_FILE_SYMLINK_REFUSED")
    doc = json.loads(local_config.read_text(encoding="utf-8"))
    values = conninfo_to_dict(doc["dsn"])
    values["dbname"] = dbname
    return make_conninfo(**values)


def _container_target_dsn(port: str) -> str:
    local_config = ROOT / ".local.json"
    if local_config.is_symlink():
        raise ImportRefused("LOCAL_DSN_FILE_SYMLINK_REFUSED")
    doc = json.loads(local_config.read_text(encoding="utf-8"))
    values = conninfo_to_dict(doc["dsn"])
    values.update({"host": "127.0.0.1", "port": port, "dbname": TARGET_DB,
                   "user": "fieldwork", "password": "", "sslmode": "disable"})
    return make_conninfo(**values)


def _canonical(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$bytes": len(value), "$sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (UUID, Decimal)):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def _json_bytes(value: Any) -> bytes:
    return json.dumps(_canonical(value), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _aggregate_rows(conn: psycopg.Connection, table: str, columns: list[str], *,
                    workspace: str = WORKSPACE, exclude_media_path: bool = False) -> dict[str, Any]:
    cols = [c for c in columns if not (exclude_media_path and c == "media_path")]
    order = [c for c in PK_ORDER[table] if c in cols]
    query = sql.SQL("SELECT {cols} FROM public.{table} WHERE workspace=%s ORDER BY {order}").format(
        cols=sql.SQL(",").join(sql.Identifier(c) for c in cols),
        table=sql.Identifier(table), order=sql.SQL(",").join(sql.Identifier(c) for c in order))
    digest = hashlib.sha256()
    count = 0
    with conn.cursor(name=f"w3_import_hash_{table}", row_factory=dict_row) as cur:
        cur.execute(query, (workspace,))
        while rows := cur.fetchmany(512):
            for row in rows:
                digest.update(_json_bytes(row))
                digest.update(b"\n")
                count += 1
    return {"rows": count, "sha256": digest.hexdigest()}


def _columns(conn: psycopg.Connection, table: str) -> list[str]:
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position", (table,)
    ).fetchall()
    return [_value(r) for r in rows]


def _scalar_count(conn: psycopg.Connection, table: str, workspace: str = WORKSPACE) -> int:
    return int(_value(conn.execute(sql.SQL("SELECT count(*) FROM public.{} WHERE workspace=%s").format(
        sql.Identifier(table)), (workspace,)).fetchone()))


def _account_preflight(source: psycopg.Connection, target: psycopg.Connection) -> dict[str, Any]:
    source_rows = source.execute(
        "SELECT name,salt,password_hash,workspace,role FROM public.fw_accounts WHERE workspace=%s ORDER BY name",
        (WORKSPACE,)).fetchall()
    result = {"source_rows": len(source_rows), "insert": 0, "reuse_exact": 0,
              "conflicts": [], "bindings": []}
    source_names = set()
    for src in source_rows:
        source_names.add(src["name"])
        dst = target.execute(
            "SELECT name,salt,password_hash,workspace,role FROM public.fw_accounts WHERE name=%s",
            (src["name"],)).fetchone()
        if dst is None:
            result["insert"] += 1
            result["bindings"].append({"name": src["name"], "source_workspace": src["workspace"],
                                       "source_role": src["role"], "target": "absent"})
            continue
        exact = all(src[k] == dst[k] for k in ("name", "salt", "password_hash", "workspace", "role"))
        result["bindings"].append({"name": src["name"], "source_workspace": src["workspace"],
                                   "source_role": src["role"], "target_workspace": dst["workspace"],
                                   "target_role": dst["role"], "exact_full_row_match": exact})
        if exact:
            result["reuse_exact"] += 1
        else:
            result["conflicts"].append({"name": src["name"], "source_workspace": src["workspace"],
                                         "source_role": src["role"], "target_workspace": dst["workspace"],
                                         "target_role": dst["role"], "exact_full_row_match": False})
    extra_target = target.execute(
        "SELECT name,workspace,role FROM public.fw_accounts WHERE workspace=%s ORDER BY name", (WORKSPACE,)
    ).fetchall()
    extras = [dict(r) for r in extra_target if r["name"] not in source_names]
    if extras:
        result["conflicts"].extend({"name": r["name"], "source_workspace": WORKSPACE,
                                    "source_role": None, "target_workspace": r["workspace"],
                                    "target_role": r["role"], "target_only_workspace_account": True}
                                   for r in extras)
    return result


def _role_authority_ok(conn: psycopg.Connection) -> bool:
    row = conn.execute("""SELECT (r.rolsuper OR r.rolbypassrls),
        bool_and(has_table_privilege(current_user,format('public.%%I',t),'INSERT'))
        FROM pg_roles r CROSS JOIN unnest(%s::text[]) AS tables(t)
        WHERE r.rolname=current_user GROUP BY r.rolsuper,r.rolbypassrls""", (list(TABLES),)).fetchone()
    return bool(row and _value(row) and _value(row, 1))


def _registry_receipt(source: psycopg.Connection) -> dict[str, Any]:
    if any(p.is_symlink() for p in (ROOT / "var", ROOT / "var/commons_r5",
                                    ROOT / "var/commons_r5/rights", REGISTRY_PATH)):
        raise ImportRefused("PUBLIC_REVIEWER_REGISTRY_SYMLINK_REFUSED")
    if not REGISTRY_PATH.is_file():
        return {"path": str(REGISTRY_PATH.relative_to(ROOT)), "exists": False}
    registry_raw = REGISTRY_PATH.read_bytes()
    doc = json.loads(registry_raw)
    entries = {}
    for row in doc.get("reviewers", []):
        if isinstance(row, dict):
            entries[(str(row.get("reviewer_id")), str(row.get("key_id")))] = (
                set(map(str, row.get("workspace_ids", []))), set(map(str, row.get("purposes", []))))
    pairs = set(entries)
    steward_pairs = source.execute(
        "SELECT reviewer_id,key_id FROM public.fw_holdout_stewards WHERE workspace=%s", (WORKSPACE,)
    ).fetchall()
    matched = sum((str(_value(r)), str(_value(r, 1))) in pairs for r in steward_pairs)
    checked = 0
    decision_matched = 0
    malformed = 0
    with source.cursor(name="w3_import_registry_decisions") as cur:
        cur.execute("SELECT envelope FROM public.fw_rights_decisions WHERE workspace=%s AND last_result='VERIFIED'", (WORKSPACE,))
        while rows := cur.fetchmany(512):
            for record in rows:
                raw = record['envelope']
                checked += 1
                try:
                    payload = json.loads(bytes(raw).decode("utf-8"))["payload"]
                    key = (str(payload["reviewer_id"]), str(payload["key_id"]))
                    scopes = entries.get(key)
                    if scopes and payload.get("workspace_id") in scopes[0] and payload.get("purpose") in scopes[1]:
                        decision_matched += 1
                except (UnicodeError, ValueError, TypeError, KeyError):
                    malformed += 1
    return {"path": str(REGISTRY_PATH.relative_to(ROOT)), "exists": True,
            "sha256": hashlib.sha256(registry_raw).hexdigest(), "steward_bindings": len(steward_pairs),
            "steward_bindings_found": matched, "rights_decisions_checked": checked,
            "rights_decision_bindings_found": decision_matched,
            "malformed_rights_decisions": malformed}


def _protected_counts(source: psycopg.Connection) -> dict[str, Any]:
    protected = source.execute(sql.SQL(
        "SELECT count(*) FROM public.fw_samples s WHERE s.workspace=%s AND " + PROTECTED_EXISTS
    ), (WORKSPACE, list(PROTECTED_SPLITS))).fetchone()["count"]
    eligible = source.execute(sql.SQL(
        "SELECT count(*) FROM public.fw_samples s WHERE s.workspace=%s AND NOT " + PROTECTED_EXISTS +
        " AND " + ELIGIBLE_EXISTS
    ), (WORKSPACE, list(PROTECTED_SPLITS), list(TRAINING_SPLITS))).fetchone()["count"]
    drives = source.execute(sql.SQL(
        "SELECT CASE WHEN media_path ~* '^[a-z]:' THEN upper(left(media_path,1)) ELSE 'OTHER' END AS drive,"
        "count(*) FROM public.fw_samples s WHERE s.workspace=%s AND NOT " + PROTECTED_EXISTS +
        " AND " + ELIGIBLE_EXISTS + " GROUP BY 1 ORDER BY 1"
    ), (WORKSPACE, list(PROTECTED_SPLITS), list(TRAINING_SPLITS))).fetchall()
    return {"protected_rows_excluded_from_media": int(protected),
            "eligible_train_validation_rows": int(eligible),
            "eligible_media_drive_counts": {str(_value(r)): int(_value(r, 1)) for r in drives}}


def _workspace_table_preflight(target: psycopg.Connection) -> dict[str, int]:
    return {table: _scalar_count(target, table) for table in WORKSPACE_TABLES}


def _schema_preflight(source: psycopg.Connection, target: psycopg.Connection) -> dict[str, Any]:
    differences = {}
    for table in TABLES:
        s_cols = _columns(source, table)
        t_cols = _columns(target, table)
        expected = list(s_cols)
        if table == "fw_intake_batches":
            expected.insert(2, "source_intake_id")
        if t_cols != expected:
            differences[table] = {"source_columns": s_cols, "target_columns": t_cols,
                                 "expected_target_columns": expected}
    return {"differences": differences, "ok": not differences}


def _version_manifest_digests(conn: psycopg.Connection) -> list[str]:
    rows = conn.execute("SELECT manifest->>'digest' FROM public.fw_versions WHERE workspace=%s ORDER BY id",
                        (WORKSPACE,)).fetchall()
    return [str(_value(r)) for r in rows]


def _holdout_summary(conn: psycopg.Connection) -> dict[str, Any]:
    states = conn.execute("SELECT state,count(*) FROM public.fw_holdout_plans WHERE workspace=%s GROUP BY state ORDER BY state",
                          (WORKSPACE,)).fetchall()
    exposures = conn.execute("SELECT count(*) FROM public.fw_holdout_exposures WHERE workspace=%s",
                             (WORKSPACE,)).fetchone()["count"]
    return {"plan_state_counts": {str(_value(r)): int(_value(r, 1)) for r in states},
            "exposure_rows": int(exposures)}


def _source_receipt(source: psycopg.Connection, target: psycopg.Connection) -> dict[str, Any]:
    columns = {table: _columns(source, table) for table in TABLES}
    table_receipts = {}
    for table in TABLES:
        if table == "fw_accounts":
            table_receipts[table] = {"rows": _scalar_count(source, table),
                                     "sha256": "omitted-sensitive-account-fields"}
        else:
            table_receipts[table] = _aggregate_rows(source, table, columns[table],
                exclude_media_path=(table == "fw_samples"))
    return {"source_table_receipts": table_receipts,
            "source_version_manifest_digests": _version_manifest_digests(source),
            "source_holdout_summary": _holdout_summary(source),
            "target_workspace_counts_before": _workspace_table_preflight(target)}


def _preflight(source: psycopg.Connection, target: psycopg.Connection) -> dict[str, Any]:
    if not _role_authority_ok(target):
        raise ImportRefused("TARGET_ROLE_MUST_BYPASS_RLS_OR_BE_SUPERUSER")
    schema = _schema_preflight(source, target)
    accounts = _account_preflight(source, target)
    counts = {table: _scalar_count(source, table) for table in TABLES}
    target_counts = _workspace_table_preflight(target)
    nonempty = {t: n for t, n in target_counts.items() if n}
    media = _protected_counts(source)
    registry = _registry_receipt(source)
    blockers = []
    if not schema["ok"]:
        blockers.append("SOURCE_TARGET_SCHEMA_MISMATCH")
    if accounts["conflicts"]:
        blockers.append("GLOBAL_ACCOUNT_NAME_COLLISION")
    if nonempty:
        blockers.append("TARGET_WORKSPACE_ALREADY_HAS_CATALOG_ROWS")
    if counts["fw_intake_batches"] and source.execute(
        "SELECT count(*) FROM public.fw_intake_batches WHERE workspace=%s AND state NOT IN ('complete','rejected','interrupted')",
        (WORKSPACE,)).fetchone()["count"]:
        blockers.append("SOURCE_BATCH_NOT_TERMINAL")
    if media["eligible_media_drive_counts"].keys() - {"C"}:
        blockers.append("ELIGIBLE_MEDIA_PATH_OUTSIDE_C_DRIVE")
    if (not registry.get("exists")
            or registry.get("steward_bindings_found") != registry.get("steward_bindings")
            or registry.get("rights_decisions_checked") != registry.get("rights_decision_bindings_found")
            or registry.get("malformed_rights_decisions") != 0):
        blockers.append("PUBLIC_REVIEWER_REGISTRY_BINDING_MISSING")
    if counts["fw_rights_datasets"] == 0 or counts["fw_versions"] == 0:
        blockers.append("SOURCE_CATALOG_INCOMPLETE")
    hashes = _source_receipt(source, target)
    return {"workspace_id": WORKSPACE, "source_database": SOURCE_DB, "target_database": TARGET_DB,
            "source_counts": counts, "schema": schema, "accounts": accounts,
            "media_protection": media, "reviewer_registry": registry,
            "target_workspace_counts_before": target_counts,
            "version_manifest_digests": hashes["source_version_manifest_digests"],
            "holdout_summary": hashes["source_holdout_summary"],
            "source_table_receipts": hashes["source_table_receipts"],
            "blockers": blockers, "ready": not blockers}


def _stream_rows(conn: psycopg.Connection, table: str, columns: list[str]) -> Iterable[dict[str, Any]]:
    order = [c for c in PK_ORDER[table] if c in columns]
    query = sql.SQL("SELECT {cols} FROM public.{table} WHERE workspace=%s ORDER BY {order}").format(
        cols=sql.SQL(",").join(sql.Identifier(c) for c in columns),
        table=sql.Identifier(table), order=sql.SQL(",").join(sql.Identifier(c) for c in order))
    with conn.cursor(name=f"w3_import_copy_{table}", row_factory=dict_row) as cur:
        cur.execute(query, (WORKSPACE,))
        while rows := cur.fetchmany(512):
            yield from rows


def _insert_row(target: psycopg.Connection, table: str, row: dict[str, Any], *,
                columns: list[str], media_paths: dict[str, str] | None = None,
                batch_staging: bool = False) -> None:
    values = dict(row)
    if table == "fw_samples" and media_paths:
        mapped = media_paths.get(str(values["sample_id"]))
        if mapped is not None:
            values["media_path"] = mapped
    if table == "fw_intake_batches" and batch_staging:
        values["state"] = "staging"
        values["finished_utc"] = None
        values["report_sha256"] = None
    if table == "fw_versions" and isinstance(values.get("manifest"), dict):
        values["manifest"] = Jsonb(values["manifest"])
    if table == "fw_holdout_plans" and values.get("result") is not None:
        values["result"] = Jsonb(values["result"])
    insert_columns = list(columns)
    if table == "fw_intake_batches":
        insert_columns.insert(2, "source_intake_id")
        values["source_intake_id"] = None
    q = sql.SQL("INSERT INTO public.{} ({}) VALUES ({})").format(
        sql.Identifier(table), sql.SQL(",").join(sql.Identifier(c) for c in insert_columns),
        sql.SQL(",").join(sql.Placeholder() for _ in insert_columns))
    target.execute(q, tuple(values[c] for c in insert_columns))


def _insert_catalog(source: psycopg.Connection, target: psycopg.Connection,
                    media_paths: dict[str, str]) -> dict[str, int]:
    inserted: dict[str, int] = {t: 0 for t in TABLES}
    columns = {table: _columns(source, table) for table in TABLES}
    existing_accounts = _account_preflight(source, target)
    if existing_accounts["conflicts"]:
        raise ImportRefused("GLOBAL_ACCOUNT_NAME_COLLISION", {"accounts": existing_accounts["conflicts"]})

    # Exact pre-existing account rows can be reused; all non-account source rows
    # are append-only and were required to be absent by preflight.
    for row in _stream_rows(source, "fw_accounts", columns["fw_accounts"]):
        existing = target.execute("SELECT name,salt,password_hash,workspace,role FROM public.fw_accounts WHERE name=%s",
                                  (row["name"],)).fetchone()
        if existing is not None:
            if not all(row[k] == existing[k] for k in ("name", "salt", "password_hash", "workspace", "role")):
                raise ImportRefused("GLOBAL_ACCOUNT_NAME_COLLISION")
            continue
        _insert_row(target, "fw_accounts", row, columns=columns["fw_accounts"])
        inserted["fw_accounts"] += 1

    # Rights foreign-key order.
    for table in ("fw_rights_datasets", "fw_rights_assets", "fw_rights_decisions"):
        for row in _stream_rows(source, table, columns[table]):
            _insert_row(target, table, row, columns=columns[table])
            inserted[table] += 1

    batch_rows = list(_stream_rows(source, "fw_intake_batches", columns["fw_intake_batches"]))
    for row in batch_rows:
        _insert_row(target, "fw_intake_batches", row, columns=columns["fw_intake_batches"], batch_staging=True)
        inserted["fw_intake_batches"] += 1

    for table in ("fw_samples", "fw_intake_members", "fw_versions", "fw_proposals",
                  "fw_holdout_stewards", "fw_holdout_plans", "fw_holdout_exposures"):
        for row in _stream_rows(source, table, columns[table]):
            _insert_row(target, table, row, columns=columns[table], media_paths=media_paths)
            inserted[table] += 1

    # Migration 006 requires staging -> exact terminal status; do not bypass it.
    for source_row in batch_rows:
        terminal = dict(source_row)
        target.execute("""UPDATE public.fw_intake_batches SET state=%s,reason=%s,source_total=%s,
             accepted=%s,rejected=%s,duplicate=%s,noop=%s,report_sha256=%s,finished_utc=%s
             WHERE workspace=%s AND batch_id=%s AND state='staging'""",
             (terminal["state"], terminal["reason"], terminal["source_total"], terminal["accepted"],
              terminal["rejected"], terminal["duplicate"], terminal["noop"], terminal["report_sha256"],
              terminal["finished_utc"], terminal["workspace"], terminal["batch_id"]))
        if target.execute("SELECT count(*) FROM public.fw_intake_batches WHERE workspace=%s AND batch_id=%s AND state=%s",
                          (terminal["workspace"], terminal["batch_id"], terminal["state"])).fetchone()["count"] != 1:
            raise ImportRefused("BATCH_TERMINAL_TRANSITION_NOT_PERSISTED")
    return inserted


def _eligible_media_rows(source: psycopg.Connection) -> Iterable[dict[str, Any]]:
    query = sql.SQL("""SELECT s.sample_id,s.raw_sha256,s.raw_bytes,s.media_path,s.format
      FROM public.fw_samples s WHERE s.workspace=%s AND NOT """) + sql.SQL(PROTECTED_EXISTS) + sql.SQL(" AND ") + sql.SQL(ELIGIBLE_EXISTS) + sql.SQL(" ORDER BY s.sample_id")
    with source.cursor(name="w3_import_media_sources", row_factory=dict_row) as cur:
        cur.execute(query, (WORKSPACE, list(PROTECTED_SPLITS), list(TRAINING_SPLITS)))
        while rows := cur.fetchmany(256):
            yield from rows


def _copy_media(source: psycopg.Connection, run_id: str) -> tuple[dict[str, str], dict[str, Any]]:
    if any(p.is_symlink() for p in (ROOT / ".local", ROOT / ".local/real-data",
                                    MEDIA_TARGET_ROOT.parent, MEDIA_TARGET_ROOT,
                                    ROOT / ".local/real-data/staging")):
        raise ImportRefused("MEDIA_TARGET_ROOT_SYMLINK_REFUSED")
    media_root = MEDIA_TARGET_ROOT.absolute()
    if PureWindowsPath(str(media_root)).drive.upper() != "C:":
        raise ImportRefused("MEDIA_TARGET_ROOT_NOT_ON_C")
    stage_root = ROOT / ".local/real-data/staging" / run_id
    media_root.mkdir(parents=True, exist_ok=True)
    stage_root.mkdir(parents=True, exist_ok=False)
    mapped: dict[str, str] = {}
    aggregate = hashlib.sha256()
    total_bytes = 0
    copied = 0
    reused = 0
    if any(p.is_symlink() for p in (ROOT / "var", ROOT / "var/datasets", ROOT / "var/datasets/tf_flowers", MEDIA_SOURCE_ROOT)):
        raise ImportRefused("MEDIA_SOURCE_ROOT_SYMLINK_REFUSED")
    source_root = MEDIA_SOURCE_ROOT.resolve(strict=True)
    if PureWindowsPath(str(source_root)).drive.upper() != "C:":
        raise ImportRefused("MEDIA_SOURCE_ROOT_NOT_ON_C")
    for row in _eligible_media_rows(source):
        raw_path = str(row["media_path"])
        win_path = PureWindowsPath(raw_path)
        if win_path.drive.upper() != "C:" or not win_path.is_absolute():
            raise ImportRefused("ELIGIBLE_MEDIA_PATH_OUTSIDE_C_DRIVE")
        source_path = Path(raw_path)
        if source_path.is_symlink():
            raise ImportRefused("ELIGIBLE_MEDIA_SYMLINK_REFUSED")
        # Refuse symlinked path components before resolving the catalog-local path.
        try:
            lexical_rel = source_path.absolute().relative_to(MEDIA_SOURCE_ROOT.absolute())
        except ValueError:
            raise ImportRefused("ELIGIBLE_MEDIA_PATH_OUTSIDE_SOURCE_CATALOG") from None
        if ".." in lexical_rel.parts:
            raise ImportRefused("ELIGIBLE_MEDIA_PATH_OUTSIDE_SOURCE_CATALOG")
        walk = MEDIA_SOURCE_ROOT.absolute()
        for part in lexical_rel.parts:
            walk = walk / part
            if walk.is_symlink():
                raise ImportRefused("ELIGIBLE_MEDIA_SYMLINK_REFUSED")
        resolved = source_path.resolve(strict=True)
        try:
            resolved.relative_to(source_root)
        except ValueError:
            raise ImportRefused("ELIGIBLE_MEDIA_PATH_OUTSIDE_SOURCE_CATALOG") from None
        if not resolved.is_file():
            raise ImportRefused("ELIGIBLE_MEDIA_NOT_REGULAR_FILE")
        digest = str(row["raw_sha256"])
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ImportRefused("ELIGIBLE_MEDIA_SHA_FORMAT_INVALID")
        ext = PureWindowsPath(raw_path).suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,8}", ext):
            ext = ".bin"
        target_path = media_root / digest[:2] / f"{digest}{ext}"
        if target_path.parent.is_symlink():
            raise ImportRefused("CONTENT_ADDRESSED_MEDIA_SYMLINK_REFUSED")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        if target_path.is_symlink() or target_path.parent.is_symlink():
            raise ImportRefused("CONTENT_ADDRESSED_MEDIA_SYMLINK_REFUSED")
        if target_path.exists():
            current_hash = hashlib.sha256()
            current_size = 0
            with target_path.open("rb") as f:
                for block in iter(lambda: f.read(1024 * 1024), b""):
                    current_hash.update(block)
                    current_size += len(block)
            if current_size != row["raw_bytes"] or current_hash.hexdigest() != digest:
                raise ImportRefused("CONTENT_ADDRESSED_MEDIA_COLLISION")
            reused += 1
        else:
            tmp = stage_root / f"{digest}.{os.getpid()}.partial"
            h = hashlib.sha256()
            size = 0
            try:
                with resolved.open("rb") as src, tmp.open("xb") as dst:
                    while block := src.read(1024 * 1024):
                        dst.write(block)
                        h.update(block)
                        size += len(block)
                    dst.flush()
                    os.fsync(dst.fileno())
            except OSError:
                raise ImportRefused("ELIGIBLE_MEDIA_COPY_IO_FAILED") from None
            if size != row["raw_bytes"] or h.hexdigest() != digest:
                raise ImportRefused("ELIGIBLE_MEDIA_SOURCE_HASH_MISMATCH")
            try:
                os.rename(tmp, target_path)
            except OSError:
                # Preserve the staged bytes and refuse to overwrite a concurrent file.
                if not target_path.exists():
                    raise ImportRefused("CONTENT_ADDRESSED_MEDIA_COMMIT_FAILED") from None
                current_hash = hashlib.sha256()
                current_size = 0
                with target_path.open("rb") as existing_file:
                    for block in iter(lambda: existing_file.read(1024 * 1024), b""):
                        current_hash.update(block)
                        current_size += len(block)
                if current_hash.hexdigest() != digest or current_size != row["raw_bytes"]:
                    raise ImportRefused("CONTENT_ADDRESSED_MEDIA_COLLISION") from None
                reused += 1
            else:
                copied += 1
        sample_id = str(row["sample_id"])
        mapped[sample_id] = str(target_path)
        total_bytes += int(row["raw_bytes"])
        aggregate.update(f"{sample_id}\0{digest}\0{row['raw_bytes']}\n".encode("ascii"))
    return mapped, {"eligible_rows": len(mapped), "copied_files": copied, "reused_verified_files": reused,
                    "total_input_bytes": total_bytes, "sample_sha_size_index_sha256": aggregate.hexdigest(),
                    "destination_root": str(MEDIA_TARGET_ROOT.relative_to(ROOT))}


def _target_receipt(target: psycopg.Connection, source_columns: dict[str, list[str]]) -> dict[str, Any]:
    receipts = {}
    for table in TABLES:
        if table == "fw_accounts":
            receipts[table] = {"rows": _scalar_count(target, table)}
        else:
            receipts[table] = _aggregate_rows(target, table, source_columns[table],
                exclude_media_path=(table == "fw_samples"))
    return {"target_table_receipts": receipts,
            "target_version_manifest_digests": _version_manifest_digests(target),
            "target_holdout_summary": _holdout_summary(target)}


def _verify_counts_and_hashes(source: psycopg.Connection, target: psycopg.Connection) -> dict[str, Any]:
    source_columns = {table: _columns(source, table) for table in TABLES}
    target_receipt = _target_receipt(target, source_columns)
    source_receipt = {}
    for table in TABLES:
        if table == "fw_accounts":
            source_receipt[table] = {"rows": _scalar_count(source, table)}
        else:
            source_receipt[table] = _aggregate_rows(source, table, source_columns[table],
                exclude_media_path=(table == "fw_samples"))
    mismatches = [table for table in TABLES if source_receipt[table] != target_receipt["target_table_receipts"][table]]
    if _version_manifest_digests(source) != target_receipt["target_version_manifest_digests"]:
        mismatches.append("version_manifest_digests")
    if _holdout_summary(source) != target_receipt["target_holdout_summary"]:
        mismatches.append("holdout_summary")
    if mismatches:
        raise ImportRefused("POST_IMPORT_AGGREGATE_MISMATCH", {"tables": mismatches})
    accounts = _account_preflight(source, target)
    if accounts["conflicts"] or accounts["reuse_exact"] + accounts["insert"] != accounts["source_rows"]:
        raise ImportRefused("POST_IMPORT_ACCOUNT_BINDING_MISMATCH")
    return {"source_table_receipts": source_receipt, **target_receipt, "aggregate_match": True}


def _verify_sample_media_paths(source: psycopg.Connection, target: psycopg.Connection,
                               media_paths: dict[str, str]) -> dict[str, Any]:
    source_paths = {str(r["sample_id"]): str(r["media_path"])
                    for r in _stream_rows(source, "fw_samples", ["workspace", "sample_id", "media_path"])}
    target_paths = {str(r["sample_id"]): str(r["media_path"])
                    for r in _stream_rows(target, "fw_samples", ["workspace", "sample_id", "media_path"])}
    if source_paths.keys() != target_paths.keys():
        raise ImportRefused("POST_IMPORT_SAMPLE_PATH_SET_MISMATCH")
    changed = 0
    unchanged = 0
    path_hash = hashlib.sha256()
    for sample_id in sorted(source_paths):
        expected = media_paths.get(sample_id, source_paths[sample_id])
        actual = target_paths[sample_id]
        if actual != expected:
            raise ImportRefused("POST_IMPORT_SAMPLE_MEDIA_PATH_MISMATCH")
        changed += sample_id in media_paths
        unchanged += sample_id not in media_paths
        path_hash.update(sample_id.encode("ascii") + b"\0" + actual.encode("utf-8") + b"\n")
    return {"sample_rows": len(source_paths), "relocated_train_validation_rows": changed,
            "unchanged_protected_or_unversioned_rows": unchanged,
            "all_sample_path_bindings_sha256": path_hash.hexdigest()}


def _write_receipt(run_dir: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    raw = _json_bytes(receipt) + b"\n"
    path = run_dir / "receipt.json"
    with path.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    return {"receipt_path": str(path.relative_to(ROOT)), "receipt_sha256": hashlib.sha256(raw).hexdigest()}


def _run_id(mode: str) -> tuple[str, Path]:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{mode}-{now}"
    path = EVIDENCE_ROOT / run_id
    path.mkdir(parents=True, exist_ok=False)
    return run_id, path


def _docker(args: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["docker", *args], input=input_text, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ImportRefused("DISPOSABLE_POSTGRES_COMMAND_FAILED", {"executable": "docker", "exit_code": result.returncode})
    return result


def _backup_metadata(backup: Path) -> dict[str, str]:
    if PureWindowsPath(str(backup)).drive.upper() != "C:" or backup.is_symlink():
        raise ImportRefused("MAIN_BACKUP_MUST_BE_REGULAR_C_DRIVE_FILE")
    if not backup.is_file():
        raise ImportRefused("MAIN_BACKUP_NOT_FOUND")
    digest = hashlib.sha256()
    with backup.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return {"basename": backup.name, "sha256": digest.hexdigest()}


def _prepare_rehearsal_container(backup: Path, run_id: str, register_owned) -> tuple[str, str, dict[str, Any]]:
    backup_info = _backup_metadata(backup)
    container = f"fw-w3-catalog-{run_id.lower()}".replace(":", "-")
    inspect = subprocess.run(["docker", "inspect", CONTAINER_SOURCE, "--format", "{{.Image}}"],
                             capture_output=True, text=True, check=False)
    if inspect.returncode:
        raise ImportRefused("MAIN_POSTGRES_CONTAINER_NOT_FOUND")
    image_id = inspect.stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ImportRefused("POSTGRES_IMAGE_ID_INVALID")
    existing = subprocess.run(["docker", "inspect", container], capture_output=True, text=True, check=False)
    if existing.returncode == 0:
        raise ImportRefused("REFUSING_TO_REUSE_EXISTING_REHEARSAL_CONTAINER")
    _docker(["run", "--detach", "--name", container, "--memory", CONTAINER_MEMORY,
             "--cpus", CONTAINER_CPUS, "--publish", f"127.0.0.1:{CONTAINER_PORT}:5432",
             "--tmpfs", f"/var/lib/postgresql/data:rw,nosuid,nodev,size={CONTAINER_PGDATA_TMPFS}",
             "--env", "POSTGRES_USER=fieldwork", "--env", f"POSTGRES_DB={TARGET_DB}",
             "--env", "POSTGRES_HOST_AUTH_METHOD=trust", image_id])
    register_owned(container)
    _docker(["cp", str(backup), f"{container}:/tmp/fieldwork-main.dump"])
    ready = False
    for _ in range(45):
        check = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "fieldwork", "-d", TARGET_DB],
                               capture_output=True, text=True, check=False)
        if check.returncode == 0:
            ready = True
            break
        import time
        time.sleep(1)
    if not ready:
        raise ImportRefused("DISPOSABLE_POSTGRES_NOT_READY")

    role_dump = _docker(["exec", CONTAINER_SOURCE, "sh", "-lc",
                         'pg_dumpall -U "$POSTGRES_USER" --roles-only --no-role-passwords']).stdout
    existing_roles = _docker(["exec", container, "psql", "-X", "-q", "-At", "-U", "fieldwork", "-d", TARGET_DB,
                              "-c", "SELECT rolname FROM pg_roles ORDER BY rolname"]).stdout.splitlines()
    existing = set(existing_roles)
    role_lines = []
    for line in role_dump.splitlines():
        match = re.fullmatch(r'CREATE ROLE (?:"((?:[^"]|"")+)"|([^;\s]+));', line)
        if match:
            name = match.group(1).replace('""', '"') if match.group(1) else match.group(2)
            if name in existing:
                continue
        role_lines.append(line)
    _docker(["exec", "-i", container, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1",
             "-U", "fieldwork", "-d", TARGET_DB], input_text="\n".join(role_lines) + "\n")
    _docker(["exec", container, "pg_restore", "--exit-on-error", "--no-owner", "-U", "fieldwork",
             "-d", TARGET_DB, "/tmp/fieldwork-main.dump"])
    info = {"main_backup_basename": backup_info["basename"], "main_backup_sha256": backup_info["sha256"],
            "postgres_image_id": image_id, "container": container,
            "port_binding": f"127.0.0.1:{CONTAINER_PORT}:5432",
            "memory_limit": CONTAINER_MEMORY, "cpu_limit": CONTAINER_CPUS,
            "pgdata_tmpfs": CONTAINER_PGDATA_TMPFS}
    return container, CONTAINER_PORT, info


def _plan(mode: str, *, backup: Path | None = None) -> int:
    run_id, run_dir = _run_id(mode)
    container = None
    owned_containers: list[str] = []
    receipt: dict[str, Any] = {"schema": "fieldwork.w3-catalog-import-receipt/v1", "run_id": run_id,
                               "mode": mode, "started_utc": datetime.now(timezone.utc).isoformat(),
                               "source_database": SOURCE_DB, "target_database": TARGET_DB,
                               "workspace_id": WORKSPACE, "live_write_performed": False}
    try:
        if mode == "apply":
            if backup is None:
                raise ImportRefused("LIVE_APPLY_REQUIRES_EXPLICIT_FRESH_MAIN_BACKUP")
            receipt["main_backup"] = _backup_metadata(backup)
        if mode == "rehearse":
            if backup is None:
                raise ImportRefused("REHEARSAL_REQUIRES_EXPLICIT_MAIN_BACKUP")
            container, port, rehearsal = _prepare_rehearsal_container(
                backup, run_id, owned_containers.append)
            receipt["rehearsal"] = rehearsal
            target_conninfo = _container_target_dsn(port)
        else:
            target_conninfo = _target_admin_dsn()
        source_conninfo = _source_admin_dsn()
        with psycopg.connect(source_conninfo, row_factory=dict_row) as source, psycopg.connect(
                target_conninfo, row_factory=dict_row) as target:
            source.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            target.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            compatibility = ROOT / 'migrations/008_predecode_intake_results.sql'
            receipt['intake_compatibility_migration_sha256'] = hashlib.sha256(compatibility.read_bytes()).hexdigest()
            if mode == 'rehearse':
                # Rehearse the forward guard fix on the disposable restore only.
                # Live apply must install it separately under the migration lock.
                target.commit()
                target.autocommit = True
                target.execute(compatibility.read_text(encoding='utf-8'))
                target.autocommit = False
                target.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            preflight = _preflight(source, target)
            receipt["preflight"] = preflight
            if not preflight["ready"]:
                raise ImportRefused("CATALOG_IMPORT_PREFLIGHT_BLOCKED", {"blockers": preflight["blockers"]})
            if mode == "plan":
                receipt["status"] = "PLAN_READY"
                receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
                pointer = _write_receipt(run_dir, receipt)
                print(json.dumps({"status": receipt["status"], **pointer,
                                  "source_counts": preflight["source_counts"],
                                  "media": preflight["media_protection"],
                                  "accounts": {"insert": preflight["accounts"]["insert"],
                                               "reuse_exact": preflight["accounts"]["reuse_exact"],
                                               "conflicts": len(preflight["accounts"]["conflicts"])}}))
                return 0

            # Release the plan snapshot before copying files. A second preflight
            # runs inside the eventual write transaction.
            target.commit()
            media_paths, media_receipt = _copy_media(source, run_id)
            receipt["media"] = media_receipt
            with target.transaction():
                target.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                target.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"fw-w3-import:{WORKSPACE}",))
                # Repeat append-only checks under the write transaction.
                locked = _preflight(source, target)
                if not locked["ready"]:
                    raise ImportRefused("CATALOG_IMPORT_PREFLIGHT_CHANGED", {"blockers": locked["blockers"]})
                inserted = _insert_catalog(source, target, media_paths)
                verified = _verify_counts_and_hashes(source, target)
                verified["sample_media_paths"] = _verify_sample_media_paths(source, target, media_paths)
                receipt["inserted_rows"] = inserted
                receipt["verified"] = verified
            receipt["status"] = "REHEARSAL_PASS" if mode == "rehearse" else "APPLY_PASS"
            receipt["live_write_performed"] = mode == "apply"
            receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
            pointer = _write_receipt(run_dir, receipt)
            print(json.dumps({"status": receipt["status"], **pointer,
                              "inserted_rows": inserted, "media": media_receipt,
                              "aggregate_match": verified["aggregate_match"]}))
        return 0
    except ImportRefused as exc:
        receipt["status"] = "REFUSED"
        receipt["refusal_code"] = exc.code
        receipt["safe_details"] = exc.details
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        pointer = _write_receipt(run_dir, receipt)
        print(json.dumps({"status": "REFUSED", "code": exc.code, **pointer,
                          "safe_details": exc.details}))
        return 2
    except Exception as exc:
        # Do not print exception text: driver errors can include connection context.
        receipt["status"] = "ERROR"
        receipt["error_class"] = type(exc).__name__
        import traceback
        receipt['error_frames'] = [{'file': Path(frame.filename).name,
                                    'line': frame.lineno, 'function': frame.name}
                                   for frame in traceback.extract_tb(exc.__traceback__)]
        receipt["finished_utc"] = datetime.now(timezone.utc).isoformat()
        pointer = _write_receipt(run_dir, receipt)
        print(json.dumps({"status": "ERROR", "error_class": type(exc).__name__, **pointer}))
        return 1
    finally:
        if owned_containers:
            owned_container = owned_containers[0]
            removed = subprocess.run(["docker", "rm", "--force", owned_container], capture_output=True,
                                     text=True, check=False)
            (run_dir / "container-cleanup.json").write_text(json.dumps({
                "owned_container": owned_container, "removed": removed.returncode == 0,
                "exit_code": removed.returncode}, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "rehearse", "apply"))
    parser.add_argument("--main-backup", type=Path,
                        help="Required for rehearse and apply: fresh custom-format backup of main fieldwork DB.")
    parser.add_argument("--confirm-live-workspace", default=None,
                        help="For apply only, repeat the exact workspace UUID to authorize the live write mode.")
    args = parser.parse_args(argv)
    if args.mode in ("rehearse", "apply") and args.main_backup is None:
        parser.error(f"{args.mode} requires --main-backup")
    if args.mode == "plan" and args.main_backup is not None:
        parser.error("--main-backup is valid only with rehearse or apply")
    if args.mode == "apply" and args.confirm_live_workspace != WORKSPACE:
        parser.error(f"apply requires --confirm-live-workspace {WORKSPACE}")
    if args.mode != "apply" and args.confirm_live_workspace is not None:
        parser.error("--confirm-live-workspace is valid only with apply")
    if args.mode == "apply":
        sys.path.insert(0, str(ROOT.parent / 'tools'))
        import product_lock
        import psutil
        owner = product_lock.read_owner(ROOT.parent / '.cache/product-build.lock') or {}
        ancestors = {(p.pid, p.create_time()) for p in psutil.Process().parents()}
        if (owner.get('product') != 'fieldwork' or owner.get('purpose') != 'fieldwork-catalog-import'
                or (owner.get('pid'), owner.get('create_time')) not in ancestors):
            raise SystemExit('FIELDWORK_CATALOG_IMPORT_HOST_LOCK_REQUIRED')
    return _plan(args.mode, backup=args.main_backup)


if __name__ == "__main__":
    raise SystemExit(main())
