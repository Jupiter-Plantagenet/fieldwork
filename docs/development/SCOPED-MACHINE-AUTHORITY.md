# Scoped lease machine authority v1 — NOT ACTIVATED

This is one opt-in local PostgreSQL path, not full ML-T-FENCE, security certification, or a release pass. No retained deployment is authorized by these files.

## Boundary

`scoped-machine-v1` uses a separate LOGIN with NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION, NOINHERIT and no memberships. It gets only six run columns (id/workspace/fence/revision/state/lease), schema usage, and three fixed routines. It gets no direct business DML, account/session/checkpoint/evidence/artifact access, slot access, or schema/database CREATE. Discovery reads eligible expired rows. Machine SELECT permission itself exposes those six columns for all rows in approved workspaces, not only expired rows.

The protected `fw_lease_cap_v1.scope` table holds the exact session login and approved workspace array. The machine cannot read or modify it directly. A separate NOLOGIN, nonowner, nonbypass function owner gets scoped run SELECT, UPDATE of state/fence/revision, event INSERT, and event-sequence usage. SECURITY DEFINER routines have a fixed pg_catalog/pg_temp path and schema-qualified application objects. They bind **session_user**, not current_user/GUC. The expiry routine checks exact run/fence/revision/state, workspace and DB expiry under FOR UPDATE SKIP LOCKED; transition and one event commit together. No physical slot mutation, kill, retry, attempt, checkpoint, or proof reset is performed.

Existing `fw_tenant` policies are untouched. Capability permissive AND restrictive policies are TO only the new roles. The restrictive policy prevents the existing PUBLIC permissive tenant/GUC policy from broadening machine scope. Neither PUBLIC nor request API has capability EXECUTE/schema usage. No application trigger or request owner shortcut is added.

Startup (and each backend transaction) validates the authenticated DB/session identity, role flags/memberships, fixed function source/owner/config, protected metadata, exact role-specific policies, RLS flags, effective business column/DML grants, PUBLIC/cross-principal function grants and CREATE denial. The explicitly trusted installer must be the database owner: the capability schema and scope table must remain owned by that identity. The standard `pg_database_owner` ownership alias is allowed only for the public schema. Nonserver roles inheriting or able to SET ROLE into the installer are rejected, not implicitly trusted. Metadata table AND column ACLs reject PUBLIC/third-principal access, mutation and delegation; the definer owner receives only metadata SELECT without grant option. Both capability identities are checked using effective table/column/sequence rights, including PUBLIC and inherited rights: six run SELECT columns, owner UPDATE only state/fence/revision, owner INSERT only workspace/run/kind/payload/object_revision on events, and owner USAGE only on the event sequence. Schema CREATE by untrusted grantees and explicit grant options on capability objects are rejected without repair. Required helper EXECUTE and schema USAGE must exist. The definer inherently controls its own three fixed functions as their owner; that necessary ownership is not an assertion that it cannot delegate through arbitrary administrator-created SQL. No unrelated business ownership/grants are allowed for either capability identity. These are unsafe-state/default-privilege/drift checks, not protection from a malicious PostgreSQL server/superuser or a concurrently malicious administrator changing the capability during a transaction. PostgreSQL server, installer and OS credential owner remain trusted.

## Future explicit operator workflow — DO NOT RUN ON RETAINED NOW

1. Parent fresh independent source review and own admitted exact-source reruns must pass. Make a recovery backup and preservation inventory first. Explicitly resolve/approve exact retained DB and workspace whitelist privately; do not infer a browser account workspace from the default synthetic-lab workspace. No training, scanner service, restart, retained migration, or authority generation is approved here.
2. Review database policies, table/sequence schema, triggers and existing PUBLIC grants. Existing FORCE RLS on runs/events is required. Operator must be authorized to create roles/schema and grant narrow object rights. Never run db_security.install as part of this utility; it does not migrate the retained application. Unsafe preexisting roles are never adopted/repaired. One capability installation per database is supported.
3. Prepare an explicit private **operator connection JSON**, exactly host/port/dbname/user/password/sslmode, in an OS-private directory. No DSN/service/defaults. Supply a nonsecret plan JSON (below). No secret goes on the command line.
4. Only after separate explicit retained authorization:

```text
.venv/Scripts/python.exe -m fieldwork.scoped_authority --operator-file <private-operator.json> --plan-file <approved-plan.json> --authority-file <new-private-directory>/authority.json --confirm-provision
```

Nonsecret plan shape (replace every placeholder intentionally; port is a JSON integer):

```json
{
  "purpose": "fieldwork-training-lease-controller",
  "authority_mode": "scoped-machine-v1",
  "connection": {"host":"127.0.0.1","port":5542,"dbname":"<approved-database>","user":"<new-approved-machine-login>","sslmode":"disable"},
  "capability_schema":"fw_lease_cap_v1",
  "capability_version":1,
  "workspaces":["<exact-approved-workspace>"]
}
```

Only explicit loopback host 127.0.0.1/::1 and sslmode disable are supported by this bounded local deployment path. Remote deployments/TLS modes require separate review, not editing defaults. All PG* environment variables are rejected, including PGSERVICE/PGPASSFILE/PGPASSWORD/PGOPTIONS; connection password is mandatory and nonempty. No environment credential/passfile fallback is accepted. Operator endpoint must equal plan endpoint. Machine SQL never accepts a client-selected routine/schema.

A fresh file is staged before DB provisioning, using an exclusive file open, restrictive private directory and ACL readback (Windows owner/current-user/SYSTEM/Administrators/OWNER RIGHTS only; POSIX owner-only mode). Windows uses icacls for DACL creation; broad existing directories/files fail closed and are not silently repaired. Never put authority JSON into source, evidence, logs, URLs, or shared folders. The generated file may remain after failed provisioning; it is not proof of DB installation. Repeating the same plan/file verifies the existing installation, does not rotate the password or change scope/grants. A lost file or changed whitelist is a separately reviewed change, not an automatic repair. Initial provisioning can commit but fail postcommit verification (e.g. incompatible preexisting PUBLIC privileges); this leaves a staged authority/installation, never scanner activation. Investigate and roll back explicitly.

5. After grant/ACL readback and fresh preservation review, separately approve a single pass:

```text
.venv/Scripts/python.exe -m fieldwork.lease_recovery --authority-file <private-directory>/authority.json --once
```

Only later separately approve any unattended loop/service. The old explicit `trusted-operator-not-least-privilege` CLI remains backward-compatible and must not be selected for retained activation. This utility never starts a scanner.

## Rollback / suspension

Stop only the explicitly owned new controller process/service. Operator can REVOKE CONNECT for the dedicated login or ALTER that new login NOLOGIN and terminate only its reviewed sessions; CONNECT may still be granted via PUBLIC, so NOLOGIN plus exact-session termination is the definitive stop. Do not modify the existing API role. Back up metadata and audit receipts first. After session shutdown, explicitly drop the dedicated schema CASCADE, DROP OWNED BY the two newly created roles in the approved database, then DROP only those roles after checking other database dependencies. Never drop unrelated objects, run a broad cluster cleanup, or physically free training slots. Logical expiry already committed is not automatically reversed: preserve original run/event history and handle future recovery separately.

## Proof limits

Tests use only unique disposable databases and owned temporary roles. Accelerated SQL expiry is scheduling scaffolding except the unchanged prior natural 45s regression. Tiny processes do not represent active training. Wrong-user/wrong-database CLI negatives may fail authentication or database availability before reaching the identity guard; wrong-schema coverage is configuration rejection only. Authority reads and path-based ACL checks are separate operations, not handle-bound TOCTOU protection or same-user isolation. A stable trusted private parent directory and no concurrent path replacement are prerequisites; current OS user, SYSTEM and Administrators remain trusted.

Correction evidence includes sanitized catalog owner/machine table, column, metadata, schema, function and sequence ACL readbacks, effective privilege checks, unsafe grants unchanged after verifier rejection, and immediate pre-expiry scoped snapshots proving slot/attempt/checkpoint preservation. Empty checkpoint fixtures establish no populated checkpoint/file preservation claim. Fixture-wide before snapshots taken before seed/claim are NOT equality proofs; only the immediate pre-expiry protected baseline is compared. Snapshot labels establish isolated fixture preservation only, not dataset rights, accepted-model quality, or retained deployment safety. Original 74-test parent evidence remains historical for its exact original source hashes; corrected source requires new child runs, fresh independent review and the parent's own exact-source admitted rerun. Evidence manifests are exclusive local hash seals, not signatures or storage-enforced immutability. Light admission requires 939524096 available bytes; the three Torch publisher proofs require a separately fresh 6 GiB available RAM and 12 GiB free disk gate, otherwise explicitly defer them without lowering the gate. No training is performed. Soft controller pass budgets, finite backlog and bounded connection/commit assumptions remain; not a universal deadline/capacity guarantee.
