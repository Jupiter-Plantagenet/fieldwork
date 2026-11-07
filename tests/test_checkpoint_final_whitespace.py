"""Real search_path GUC/catalog differential; not SQL lexer equivalence.

Erratum: the frozen independent VT valid=True hypothesis is preserved there;
this new regression requires rejection of its actual non-equivalent path.
"""
import hashlib
import pytest,psycopg
from test_checkpoint_effective_dependency import runtime,authored_rows,tenant,observe,save
from fieldwork.checkpoint_read import SIGNATURE

FORMS=[('bare','PG_CATALOG','pg_TEMP'),('quoted','"pg_catalog"','"pg_temp"'),
       ('mixed-left','"pg_catalog"','PG_TEMP'),('mixed-right','PG_CATALOG','"pg_temp"')]
CASES=[]
for name,w in [('SP',' '),('TAB','\t'),('LF','\n'),('CR','\r'),('FF','\f'),('VT','\v')]:
    for form,left,right in FORMS:
        for position in range(4):
            pieces=['',left,'',',','',right,'']
            pieces[[0,2,4,6][position]]=w
            CASES.append(pytest.param(''.join(pieces),name,position,id=f'{name}-{form}-position{position}'))

@pytest.mark.parametrize('path,whitespace,position',CASES)
def test_actual_guc_whitespace_resolution_controls_admission(authored_rows,path,whitespace,position):
    admin,request,role=authored_rows
    effective=None;stored=None;sqlstate=None
    with admin.connect() as conn:
        conn.execute('CREATE TEMP TABLE final_whitespace_probe(x integer)')
        try:
            with conn.transaction():
                conn.execute("SELECT set_config('search_path',%s,true)",(path,))
                effective=conn.execute('SELECT current_schemas(true) schemas').fetchone()['schemas']
                explicit=conn.execute('SELECT current_schemas(false) schemas').fetchone()['schemas']
                conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path FROM CURRENT')
                stored=conn.execute('SELECT proconfig FROM pg_proc WHERE oid=to_regprocedure(%s)',(SIGNATURE,)).fetchone()['proconfig']
        except psycopg.errors.InvalidParameterValue as exc:
            sqlstate=exc.sqlstate
    try:
        if sqlstate:
            # PostgreSQL rejected the representation itself, not an admission pass.
            save('guc-'+hashlib.sha256(path.encode()).hexdigest()+'.json',{'path':path,'sqlstate':sqlstate,'catalog_rejected':True})
            return
        # Implicit catalog injection can hide a non-existent first identifier;
        # fixed-path equivalence requires both explicit GUC entries to resolve.
        assert effective is not None and stored is not None
        equivalent=len(explicit)==2 and explicit[0]=='pg_catalog' and explicit[1].startswith('pg_temp_')
        observed=observe(admin,request,role)
        with tenant(request,'tenant-a') as conn:
            actual=conn.execute("SELECT * FROM fw_checkpoint_read_v1.locked_digest('r-a',1,'tenant-a')").fetchone()
        save('guc-'+hashlib.sha256(path.encode()).hexdigest()+'.json',{'path':path,'stored':stored,'effective':effective,'explicit':explicit,'equivalent':equivalent,'admission':observed,'actual_helper':actual,'VT_oracle_erratum':whitespace=='VT'})
        assert actual=={'digest':'fixture-digest'}
        if equivalent:
            assert observed=={'operator':True,'request':True,'dependency':True,'readiness':200,'startup':True},observed
        else:
            assert observed['operator']=='CHECKPOINT_FUNCTION_MISMATCH' and observed['request']=='CHECKPOINT_FUNCTION_MISMATCH',observed
            assert observed['dependency'] is not True and observed['readiness']==503 and observed['startup'] is not True,observed
        if path=='"pg_catalog",\v"pg_temp"':assert not equivalent
    finally:
        with admin.connect() as conn:conn.execute('ALTER FUNCTION '+SIGNATURE+' SET search_path=pg_catalog,pg_temp')
