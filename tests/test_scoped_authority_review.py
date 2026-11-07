"""SC-01/02 real SQL drift regression; original 21 scoped tests unchanged."""
import json,os,uuid
from pathlib import Path
import pytest
from psycopg import sql
from tests.test_scoped_authority import machine,seed


def snapshot(s):
    with s.connect() as c:
        return {t:c.execute(sql.SQL('SELECT * FROM {} ORDER BY 1').format(sql.Identifier('public',t))).fetchall()
                for t in ['fw_runs','fw_events','fw_slot','fw_attempts','fw_checkpoints']}


def catalog(s,a):
    # Public catalogs only: never passwords/DSNs/authority file contents.
    with s.connect() as c:
        return {
            'relations':c.execute("SELECT n.nspname,c.relname,c.relowner::regrole::text owner,c.relacl::text acl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','fw_lease_cap_v1') AND c.relkind IN ('r','S') ORDER BY 1,2").fetchall(),
            'columns':c.execute("SELECT a.attrelid::regclass::text relation,a.attname,a.attacl::text acl FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','fw_lease_cap_v1') AND a.attnum>0 AND NOT a.attisdropped ORDER BY 1,2").fetchall(),
            'schemas':c.execute("SELECT nspname,nspowner::regrole::text owner,nspacl::text acl FROM pg_namespace WHERE nspname IN ('public','fw_lease_cap_v1') ORDER BY 1").fetchall(),
            'functions':c.execute("SELECT p.oid::regprocedure::text routine,p.proowner::regrole::text owner,p.proacl::text acl FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='fw_lease_cap_v1' ORDER BY 1").fetchall(),
            'database':c.execute("SELECT datdba::regrole::text owner,datacl::text acl FROM pg_database WHERE datname=current_database()").fetchall(),
            'effective':c.execute("SELECT r.rolname,has_column_privilege(r.oid,'public.fw_runs','id','SELECT') run_id_select,has_column_privilege(r.oid,'fw_lease_cap_v1.scope','workspaces','UPDATE') scope_update,has_sequence_privilege(r.oid,'public.fw_events_seq_seq','USAGE') sequence_usage,has_schema_privilege(r.oid,'fw_lease_cap_v1','CREATE') schema_create FROM pg_roles r WHERE rolname=ANY(%s) ORDER BY 1",([a['connection']['user'],a['connection']['user']+'_owner'],)).fetchall()}


def record(label,value):
    if os.environ.get('FWM_EVIDENCE'):
        with (Path(os.environ['FWM_EVIDENCE'])/(label+'-'+uuid.uuid4().hex+'.json')).open('x') as f:json.dump(value,f,default=str,indent=2)


def test_sc01_machine_column_scope_update_is_rejected(machine):
    s,a,b,api=machine;seed(s)
    with s.connect() as c:
        c.execute(sql.SQL('GRANT UPDATE(workspaces) ON fw_lease_cap_v1.scope TO {}').format(sql.Identifier(a['connection']['user'])))
        rights=c.execute("SELECT has_table_privilege(%s,'fw_lease_cap_v1.scope','UPDATE') table_update,has_column_privilege(%s,'fw_lease_cap_v1.scope','workspaces','UPDATE') column_update",(a['connection']['user'],)*2).fetchone()
        assert rights=={'table_update':False,'column_update':True}
    before=snapshot(s)
    with pytest.raises(ValueError,match='UNPROTECTED_SCOPE_METADATA'):b.verify()
    assert snapshot(s)==before
    with s.connect() as c:
        assert c.execute("SELECT has_column_privilege(%s,'fw_lease_cap_v1.scope','workspaces','UPDATE') v",(a['connection']['user'],)).fetchone()['v']


@pytest.mark.parametrize('grant',[
    'SELECT ON public.fw_slot','UPDATE ON public.fw_slot','SELECT ON public.fw_checkpoints',
    'UPDATE ON public.fw_checkpoints','UPDATE(config) ON public.fw_runs',
    'SELECT ON public.fw_events','INSERT(seq) ON public.fw_events',
    'SELECT ON SEQUENCE public.fw_events_seq_seq','UPDATE ON SEQUENCE public.fw_events_seq_seq',
    'USAGE ON SEQUENCE public.fw_proposals_ordinal_seq','CREATE ON SCHEMA public',
    'CREATE ON SCHEMA fw_lease_cap_v1','CREATE ON DATABASE {db}',
    'SELECT(id) ON public.fw_runs WITH GRANT OPTION',
    'USAGE ON SEQUENCE public.fw_events_seq_seq WITH GRANT OPTION',
    'USAGE ON SCHEMA public WITH GRANT OPTION',
    'EXECUTE ON FUNCTION fw_lease_cap_v1.allowed(text) WITH GRANT OPTION',
])
def test_sc02_owner_exact_allowlist_rejects_drift(machine,grant):
    s,a,b,api=machine;seed(s)
    clean=catalog(s,a);record('clean-acl',clean)
    delegate=grant.endswith(' WITH GRANT OPTION')
    target=grant.removesuffix(' WITH GRANT OPTION')
    with s.connect() as c:
        target=sql.SQL(target).format(db=sql.Identifier(a['connection']['dbname']))
        c.execute(sql.SQL('GRANT {} TO {}'+(' WITH GRANT OPTION' if delegate else '')).format(target,sql.Identifier(a['connection']['user']+'_owner')))
    before=snapshot(s);unsafe=catalog(s,a)
    with pytest.raises(ValueError):b.verify()
    assert snapshot(s)==before and catalog(s,a)==unsafe
    record('rejected-owner-acl',{'grant':grant,'unsafe_unchanged':True,'catalog':unsafe})


@pytest.mark.parametrize('drift',[
    'public-column','third-column','third-table','metadata-grant-option',
    'cap-schema-create','public-schema-create','metadata-owner','schema-owner',
    'machine-select-delegation','machine-function-delegation','owner-inheritance','installer-inheritance',
    'public-business-column','public-business-table','public-sequence',
])
def test_effective_metadata_and_delegation_drift(machine,drift):
    s,a,b,api=machine;seed(s);third='fwm_third_'+uuid.uuid4().hex
    with s.connect() as c:c.execute(sql.SQL('CREATE ROLE {} NOLOGIN').format(sql.Identifier(third)))
    try:
        record('clean-acl',catalog(s,a))
        with s.connect() as c:
            machine_role=sql.Identifier(a['connection']['user']);owner=sql.Identifier(a['connection']['user']+'_owner');role=sql.Identifier(third)
            statements={
                'public-column':sql.SQL('GRANT UPDATE(workspaces) ON fw_lease_cap_v1.scope TO PUBLIC'),
                'third-column':sql.SQL('GRANT UPDATE(workspaces) ON fw_lease_cap_v1.scope TO {}').format(role),
                'third-table':sql.SQL('GRANT UPDATE ON fw_lease_cap_v1.scope TO {}').format(role),
                'metadata-grant-option':sql.SQL('GRANT SELECT ON fw_lease_cap_v1.scope TO {} WITH GRANT OPTION').format(owner),
                'cap-schema-create':sql.SQL('GRANT CREATE ON SCHEMA fw_lease_cap_v1 TO {}').format(role),
                'public-schema-create':sql.SQL('GRANT CREATE ON SCHEMA public TO {}').format(role),
                'metadata-owner':sql.SQL('ALTER TABLE fw_lease_cap_v1.scope OWNER TO {}').format(role),
                'schema-owner':sql.SQL('ALTER SCHEMA fw_lease_cap_v1 OWNER TO {}').format(role),
                'machine-select-delegation':sql.SQL('GRANT SELECT(id) ON public.fw_runs TO {} WITH GRANT OPTION').format(machine_role),
                'machine-function-delegation':sql.SQL('GRANT EXECUTE ON FUNCTION fw_lease_cap_v1.allowed(text) TO {} WITH GRANT OPTION').format(machine_role),
                'installer-inheritance':sql.SQL('GRANT {} TO {}').format(sql.Identifier(c.execute('SELECT current_user name').fetchone()['name']),role),
                'owner-inheritance':sql.SQL('GRANT {} TO {}').format(role,owner),
                'public-business-column':sql.SQL('GRANT SELECT(path) ON public.fw_checkpoints TO PUBLIC'),
                'public-business-table':sql.SQL('GRANT SELECT ON public.fw_slot TO PUBLIC'),
                'public-sequence':sql.SQL('GRANT SELECT ON SEQUENCE public.fw_events_seq_seq TO PUBLIC'),
            }
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA fw_lease_cap_v1 TO {}').format(role)) if drift in ['third-column','third-table'] else None
            c.execute(statements[drift])
        unsafe=catalog(s,a);before=snapshot(s)
        with pytest.raises(ValueError):b.verify()
        assert snapshot(s)==before and catalog(s,a)==unsafe
        record('rejected-acl',{'drift':drift,'unsafe_unchanged':True,'catalog':unsafe})
    finally:
        with s.connect() as c:
            # Return owned fixture metadata only so the original fixture can clean up.
            installer=c.execute('SELECT current_user name').fetchone()['name']
            if drift=='metadata-owner':c.execute(sql.SQL('ALTER TABLE fw_lease_cap_v1.scope OWNER TO {}').format(sql.Identifier(installer)))
            if drift=='schema-owner':c.execute(sql.SQL('ALTER SCHEMA fw_lease_cap_v1 OWNER TO {}').format(sql.Identifier(installer)))
            c.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(third)))
            c.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(third)))


def test_missing_required_expire_execute_is_rejected(machine):
    s,a,b,api=machine
    with s.connect() as c:c.execute(sql.SQL('REVOKE EXECUTE ON FUNCTION fw_lease_cap_v1.expire(text,integer,integer,text) FROM {}').format(sql.Identifier(a['connection']['user'])))
    with pytest.raises(ValueError):b.verify()


def test_immediate_preexpiry_scoped_preservation_readback(machine):
    s,a,b,api=machine;rid=seed(s)
    candidate=b.candidates('',16)[0]
    before=snapshot(s);acl=catalog(s,a)
    with s.connect() as c:scope=c.execute('SELECT * FROM fw_lease_cap_v1.scope').fetchall()
    assert b.expire(candidate)['run']==rid
    after=snapshot(s)
    for t in ['fw_slot','fw_attempts','fw_checkpoints']:assert before[t]==after[t]
    with s.connect() as c:assert scope==c.execute('SELECT * FROM fw_lease_cap_v1.scope').fetchall()
    record('immediate-preexpiry',{'isolated_only':True,'before':before,'after':after,'scope':scope,'catalog':acl,'protected_preserved':True,'checkpoints_populated':False})
