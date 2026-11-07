"""Effective function ACLs: actual nonowner PG and full startup composition.

All drift is authored by the isolated DBA, never a browser exploit fixture.
"""
import pytest
from psycopg import sql
from test_checkpoint_effective_dependency import runtime,authored_rows,tenant,observe,save
from fieldwork.checkpoint_read import SIGNATURE


def deny_every_boundary(got,reason):
    assert got['operator']==reason and got['request']==reason,got
    assert got['dependency']=='CHECKPOINT_READ_V1_DEPENDENCY:'+reason,got
    assert got['readiness']==503,got
    assert got['startup']=='CHECKPOINT_READ_V1_DEPENDENCY:'+reason,got


def test_default_null_acl_denies_complete_startup_composition(authored_rows):
    admin,request,role=authored_rows
    with admin.connect() as conn:
        definition=conn.execute('SELECT pg_get_functiondef(to_regprocedure(%s)) definition',(SIGNATURE,)).fetchone()['definition']
        conn.execute('DROP FUNCTION '+SIGNATURE)
        conn.execute(definition)
        conn.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' OWNER TO {}').format(sql.Identifier(role+'_cp_lock')))
        acl=conn.execute("""SELECT proacl::text acl,
            (SELECT count(*) FROM aclexplode(proacl) a WHERE grantee=0) raw_public_rows,
            EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a
                WHERE grantee=0 AND privilege_type='EXECUTE') public_execute,
            has_function_privilege(%s,oid,'EXECUTE') api_execute
            FROM pg_proc WHERE oid=to_regprocedure(%s)""",(role,SIGNATURE)).fetchone()
    try:
        assert acl=={'acl':None,'raw_public_rows':0,'public_execute':True,'api_execute':True},acl
        with tenant(request,'tenant-a') as conn:
            actual=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
            cross=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-b',1,'tenant-a')").fetchone()
        assert actual=={'digest':'fixture-digest'} and cross is None
        got=observe(admin,request,role)
        save('effective-acl-default-null.json',{'acl':acl,'actual_nonowner':actual,'cross_tenant':cross,'admission':got,'boundary':'DBA drift; session-user guard/RLS unchanged; no browser escalation claim'})
        deny_every_boundary(got,'CHECKPOINT_PUBLIC_EXECUTE')
    finally:
        with admin.connect() as conn:
            conn.execute('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC')
            conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(role)))


@pytest.mark.parametrize('label,public,intended,empty,grant_option',[
    ('intended_only',False,True,False,False),
    ('explicit_public',True,True,False,False),
    ('public_and_intended_revoked',False,False,False,False),
    ('explicit_empty_acl',False,False,True,False),
    ('regranted_intended',False,True,True,False),
    ('intended_grant_option',False,True,False,True),
])
def test_effective_acl_regression_matrix(authored_rows,label,public,intended,empty,grant_option):
    import psycopg
    admin,request,role=authored_rows
    with admin.connect() as conn:
        definition=conn.execute('SELECT pg_get_functiondef(to_regprocedure(%s)) definition',(SIGNATURE,)).fetchone()['definition']
    try:
        with admin.connect() as conn:
            conn.execute('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC')
            conn.execute(sql.SQL('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM {}').format(sql.Identifier(role)))
            if empty:
                conn.execute(sql.SQL('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM {}').format(sql.Identifier(role+'_cp_lock')))
            if public:conn.execute('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO PUBLIC')
            if intended:
                conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}'+(' WITH GRANT OPTION' if grant_option else '')).format(sql.Identifier(role)))
            acl=conn.execute("""SELECT proacl::text acl,
                EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a
                    WHERE grantee=0 AND privilege_type='EXECUTE') public_execute,
                has_function_privilege(%s,oid,'EXECUTE') api_execute
                FROM pg_proc WHERE oid=to_regprocedure(%s)""",(role,SIGNATURE)).fetchone()
        assert acl['acl'] is not None and acl['public_execute']==public and acl['api_execute']==intended,acl
        if empty and not intended:assert acl['acl']=='{}',acl
        actual=None;sqlstate=None
        with tenant(request,'tenant-a') as conn:
            if intended:
                actual=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
                assert actual=={'digest':'fixture-digest'}
            else:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
                    conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')")
                sqlstate=exc.value.sqlstate
                assert sqlstate=='42501'
        got=observe(admin,request,role)
        with admin.connect() as conn:
            unchanged=conn.execute('SELECT proacl::text acl FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()['acl']==acl['acl']
        save('effective-acl-matrix-'+label+'.json',{'acl':acl,'actual_nonowner':actual,'execution_sqlstate':sqlstate,'admission':got,'acl_unchanged_by_readiness':unchanged})
        assert unchanged
        if public:deny_every_boundary(got,'CHECKPOINT_PUBLIC_EXECUTE')
        elif not intended:deny_every_boundary(got,'CHECKPOINT_EXECUTE_REQUIRED')
        else:assert got=={'operator':True,'request':True,'dependency':True,'readiness':200,'startup':True},got
    finally:
        # Recreate only the exclusively owned fixture to restore even empty ACLs.
        with admin.connect() as conn:
            conn.execute('DROP FUNCTION '+SIGNATURE);conn.execute(definition)
            conn.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' OWNER TO {}').format(sql.Identifier(role+'_cp_lock')))
            conn.execute('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC')
            conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(role)))


def test_inherited_execute_does_not_relax_existing_membership_policy(authored_rows):
    admin,request,role=authored_rows;owner=role+'_cp_lock'
    try:
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM {}').format(sql.Identifier(role)))
            conn.execute(sql.SQL('GRANT {} TO {}').format(sql.Identifier(owner),sql.Identifier(role)))
            allowed=conn.execute('SELECT has_function_privilege(%s,%s,\'EXECUTE\') allowed',(role,SIGNATURE)).fetchone()['allowed']
        assert allowed
        with tenant(request,'tenant-a') as conn:
            actual=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
        assert actual=={'digest':'fixture-digest'}
        got=observe(admin,request,role)
        save('effective-acl-inherited-forbidden-membership.json',{'api_effective_execute':allowed,'actual_nonowner':actual,'admission':got,'policy':'Existing membership rejection preserved; no new inherited-role allowance'})
        deny_every_boundary(got,'CHECKPOINT_ROLE_MEMBERSHIP')
    finally:
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE {} FROM {}').format(sql.Identifier(owner),sql.Identifier(role)))
            conn.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(role)))
