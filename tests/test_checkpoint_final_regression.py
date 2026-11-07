"""New canonical regression; frozen reviewer VT valid=True oracle is falsified.
Only its VT case now expects rejection; historical review files are untouched.
"""
"""Independent assertions on actual dependency semantics, no product replacement."""
import json,os
import pytest,psycopg
from psycopg import sql
from test_checkpoint_effective_dependency import runtime,authored_rows,tenant,observe,save
from fieldwork.checkpoint_read import verify,SIGNATURE

REQUIRED=[('fw_runs',c) for c in ['id','workspace','state','artifact_status','result']]+[('fw_checkpoints',c) for c in ['run','epoch','digest']]

@pytest.mark.parametrize('table,column',REQUIRED)
def test_individual_minimal_owner_select_dependency(authored_rows,table,column):
    admin,request,role=authored_rows;owner=sql.Identifier(role+'_cp_lock')
    with admin.connect() as conn:
        conn.execute(sql.SQL('REVOKE SELECT ON public.fw_runs,public.fw_checkpoints FROM {}').format(owner))
        conn.execute(sql.SQL('GRANT SELECT(id,workspace,state,artifact_status,result) ON public.fw_runs TO {}').format(owner))
        conn.execute(sql.SQL('GRANT SELECT(run,epoch,digest) ON public.fw_checkpoints TO {}').format(owner))
        conn.execute(sql.SQL('REVOKE SELECT({}) ON public.{} FROM {}').format(sql.Identifier(column),sql.Identifier(table),owner))
    try:
        with tenant(request,'tenant-a') as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
                conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')")
        got=observe(admin,request,role)
        save('independent-column-'+table+'-'+column+'.json',{'actual_helper_sqlstate':exc.value.sqlstate,'admission':got})
        assert got['operator']=='CHECKPOINT_OWNER_ACCESS_REQUIRED' and got['request']=='CHECKPOINT_OWNER_ACCESS_REQUIRED'
        assert got['readiness']==503 and got['startup'] is not True
    finally:
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE SELECT(id,workspace,state,artifact_status,result) ON public.fw_runs FROM {}').format(owner))
            conn.execute(sql.SQL('REVOKE SELECT(run,epoch,digest) ON public.fw_checkpoints FROM {}').format(owner))
            conn.execute(sql.SQL('GRANT SELECT ON public.fw_runs,public.fw_checkpoints TO {}').format(owner))

@pytest.mark.parametrize('path,valid',[
 ('"pg_catalog",\v"pg_temp"',False),
 ('\fPG_CATALOG ,\tPG_TEMP\n',True),
 ('"pg_catalog", "pg_""temp"',False),
 ('"pg_catalog", "pg_temp "',False),
 ('"pg_catalog", "$user"',False),
 ('"pg_temp", "pg_catalog"',False),
])
def test_additional_path_catalog_differential(authored_rows,path,valid):
    admin,request,role=authored_rows
    with admin.connect() as conn:
        conn.execute('CREATE TEMP TABLE ir_fixed_path_probe(x integer)')
        conn.execute("SELECT set_config('search_path',%s,true)",(path,))
        effective=conn.execute('SELECT current_schemas(true) schemas').fetchone()['schemas']
        conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT')
        stored=conn.execute('SELECT proconfig FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()['proconfig']
    try:
        got=observe(admin,request,role)
        with tenant(request,'tenant-a') as conn:
            actual=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
        assert actual=={'digest':'fixture-digest'}
        save('independent-path-'+str(abs(hash(path)))+'.json',{'path':path,'proconfig':stored,'effective_schemas':effective,'admission':got,'helper':actual,'expected_ready':valid})
        if valid:
            assert len(effective)==2 and effective[0]=='pg_catalog' and effective[1].startswith('pg_temp_')
            assert got=={'operator':True,'request':True,'dependency':True,'readiness':200,'startup':True}
        else:assert got['readiness']==503 and got['startup'] is not True
    finally:
        with admin.connect() as conn:conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path=pg_catalog,pg_temp')

def test_actual_cross_scope_argument_denial(authored_rows):
    admin,request,role=authored_rows
    with tenant(request,'tenant-a') as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
            conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-b',1,'tenant-b')")
    assert exc.value.sqlstate=='42501'
    with request.connect() as conn:
        assert conn.execute("SELECT current_setting('fieldwork.workspace',true) scope").fetchone()['scope']==''
        assert conn.execute('SELECT id FROM fw_runs').fetchall()==[]


def test_column_insert_write_drift_must_not_be_ready(authored_rows):
    admin,request,role=authored_rows
    with admin.connect() as conn:
        conn.execute(sql.SQL('GRANT INSERT(run,epoch,attempt,digest,path,metrics) ON public.fw_checkpoints TO {}').format(sql.Identifier(role)))
    try:
        got=observe(admin,request,role)
        with tenant(request,'tenant-a') as conn:
            privileges=conn.execute("SELECT has_table_privilege(current_user,'public.fw_checkpoints','INSERT') table_insert,has_any_column_privilege(current_user,'public.fw_checkpoints','INSERT') column_insert").fetchone()
            conn.execute("INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES('r-a',2,'a-r-a','untrusted','untrusted','{}')")
            actual=conn.execute("SELECT run,epoch,digest FROM public.fw_checkpoints WHERE run='r-a' AND epoch=2").fetchone()
            conn.rollback()
        save('independent-api-column-insert.json',{'admission':got,'actual_nonowner_privileges':privileges,'actual_inserted_row_rolled_back':actual,'boundary':'administrator-authored grant drift; not demonstrated unprivileged escalation'})
        assert got['readiness']==503 and got['startup'] is not True,got
    finally:
        with admin.connect() as conn:
            conn.execute(sql.SQL('REVOKE INSERT(run,epoch,attempt,digest,path,metrics) ON public.fw_checkpoints FROM {}').format(sql.Identifier(role)))
