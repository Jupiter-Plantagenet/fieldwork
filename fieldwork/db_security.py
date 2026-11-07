"""Admin-only expansion migration and dedicated least-privilege API login.
Primary reference: PostgreSQL16 ddl-rowsecurity / sql-createrole documentation.
API role cannot claim jobs or publish checkpoints. Controller remains separate.
"""
import json,secrets
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from .store import ROOT,Store


def install(store,login,password):
    with store.connect() as c:
        if not c.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',(login,)).fetchone():
            c.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}').format(sql.Identifier(login),sql.Literal(password)))
        flags=c.execute('SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=%s',(login,)).fetchone()
        if any(flags.values()):raise ValueError('Unsafe existing API role')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS fw_runs_tenant_id ON fw_runs(workspace,id)')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS fw_attempts_tenant_run_id ON fw_attempts(run,id)')
        c.execute('''DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fw_events_tenant_run') THEN
                ALTER TABLE fw_events ADD CONSTRAINT fw_events_tenant_run FOREIGN KEY(workspace,run) REFERENCES fw_runs(workspace,id);
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fw_checkpoints_run_attempt') THEN
                ALTER TABLE fw_checkpoints ADD CONSTRAINT fw_checkpoints_run_attempt FOREIGN KEY(run,attempt) REFERENCES fw_attempts(run,id);
            END IF;
        END $$;''')
        # Existing child schemas remain compatible: RLS follows the canonical run FK.
        for table in ['fw_runs','fw_events','fw_versions','fw_proposals','fw_attempts','fw_checkpoints']:
            identifier=sql.Identifier(table)
            c.execute(sql.SQL('ALTER TABLE {} ENABLE ROW LEVEL SECURITY').format(identifier))
            c.execute(sql.SQL('ALTER TABLE {} FORCE ROW LEVEL SECURITY').format(identifier))
            c.execute(sql.SQL('DROP POLICY IF EXISTS fw_tenant ON {}').format(identifier))
            expression=sql.SQL("workspace=current_setting('fieldwork.workspace',true)") if table not in ('fw_attempts','fw_checkpoints') else sql.SQL("EXISTS(SELECT 1 FROM fw_runs r WHERE r.id=run AND r.workspace=current_setting('fieldwork.workspace',true))")
            c.execute(sql.SQL('CREATE POLICY fw_tenant ON {} USING ({}) WITH CHECK ({})').format(identifier,expression,expression))
        role=sql.Identifier(login)
        c.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(role))
        # Review F5: no table-level UPDATE on fw_runs. The request principal may change
        # only the cancel/resume columns, and migrations/005's fw_runs_guard trigger
        # limits those to browser transitions with monotonic fence/generation.
        c.execute(sql.SQL('REVOKE UPDATE ON fw_runs FROM {}').format(sql.Identifier(login)))
        has_generation=c.execute("SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='fw_runs' AND column_name='cancel_generation'").fetchone()
        c.execute(sql.SQL('GRANT UPDATE (state, fence, revision'+(', cancel_generation' if has_generation else '')+') ON fw_runs TO {}').format(sql.Identifier(login)))
        for table,permissions in {'fw_runs':'SELECT, INSERT','fw_events':'SELECT, INSERT','fw_versions':'SELECT, INSERT, UPDATE','fw_proposals':'SELECT, INSERT, UPDATE','fw_attempts':'SELECT','fw_checkpoints':'SELECT','fw_accounts':'SELECT','fw_sessions':'SELECT, INSERT, UPDATE, DELETE'}.items():
            c.execute(sql.SQL('GRANT '+permissions+' ON {} TO {}').format(sql.Identifier(table),role))
        for sequence in ['fw_events_seq_seq','fw_proposals_ordinal_seq']:
            c.execute(sql.SQL('GRANT USAGE, SELECT ON SEQUENCE {} TO {}').format(sql.Identifier(sequence),role))
        c.execute(sql.SQL('ALTER ROLE {} SET statement_timeout=5000').format(role))
        c.execute(sql.SQL('ALTER ROLE {} SET idle_in_transaction_session_timeout=10000').format(role))
        from .checkpoint_read import install as install_checkpoint_read
        install_checkpoint_read(c,login)


def provision():
    s=Store();s.migrate();path=ROOT/'.local-api.json'
    if path.exists():
        private=json.loads(path.read_text());params=conninfo_to_dict(private['dsn']);login=params['user'];password=params['password']
    else:
        login='fieldwork_api';password=secrets.token_urlsafe(48);params=conninfo_to_dict(s.dsn);params.update(user=login,password=password)
        private={'dsn':make_conninfo(**params)}
    install(s,login,password)
    if not path.exists():
        with path.open('x') as f:json.dump(private,f)
    print(json.dumps({'api_principal':login,'superuser':False,'bypassrls':False,'migration':'expansion-v2','secret_printed':False}))

if __name__=='__main__':provision()
