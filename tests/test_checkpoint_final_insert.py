"""Effective checkpoint writes: real nonowner SQL; disposable DBA drift only."""
import pytest,psycopg
from psycopg import sql
from test_checkpoint_effective_dependency import runtime,authored_rows,tenant,observe,save

COLUMNS=['run','epoch','attempt','digest','path','metrics']

def denied(got):
    assert got['operator'] is not True and got['request'] is not True,got
    assert got['dependency'] is not True and got['readiness']==503 and got['startup'] is not True,got

@pytest.mark.parametrize('permission',['INSERT','UPDATE'])
@pytest.mark.parametrize('column',COLUMNS)
@pytest.mark.parametrize('grantee',['api','PUBLIC'])
def test_each_effective_column_write_denies_all_admission(authored_rows,permission,column,grantee):
    admin,request,role=authored_rows;target=sql.SQL('PUBLIC') if grantee=='PUBLIC' else sql.Identifier(role)
    statement=sql.SQL('{} '+permission+'({}) ON public.fw_checkpoints {} {}')
    def change(action):
        with admin.connect() as conn:
            conn.execute(statement.format(sql.SQL(action),sql.Identifier(column),sql.SQL('TO' if action=='GRANT' else 'FROM'),target))
    change('GRANT')
    try:
        with tenant(request,'tenant-a') as conn:
            effective=conn.execute("SELECT has_table_privilege(current_user,'public.fw_checkpoints',%s) table_write,has_column_privilege(current_user,'public.fw_checkpoints',%s,%s) column_write",(permission,column,permission)).fetchone()
            assert effective=={'table_write':False,'column_write':True}
            if permission=='INSERT':
                # Zero-row INSERT still exercises actual column authorization;
                # full-row actual INSERT/readback/rollback is a separate case.
                result=conn.execute(sql.SQL('INSERT INTO public.fw_checkpoints({}) SELECT {} FROM public.fw_checkpoints WHERE false').format(sql.Identifier(column),sql.Identifier(column)))
                assert result.rowcount==0
            else:
                result=conn.execute(sql.SQL("UPDATE public.fw_checkpoints SET {}={} WHERE run='r-a'").format(sql.Identifier(column),sql.Identifier(column)))
                assert result.rowcount==1
            conn.rollback()
        got=observe(admin,request,role)
        save(f'effective-{permission}-{column}-{grantee}.json',{'effective':effective,'actual_nonowner_sql_succeeded':True,'rowcount':result.rowcount,'rolled_back':True,'admission':got})
        denied(got)
    finally:change('REVOKE')
    assert observe(admin,request,role)['readiness']==200


def test_public_all_column_insert_actual_row_and_rollback(authored_rows):
    admin,request,role=authored_rows
    with admin.connect() as conn:conn.execute('GRANT INSERT(run,epoch,attempt,digest,path,metrics) ON public.fw_checkpoints TO PUBLIC')
    try:
        with tenant(request,'tenant-a') as conn:
            conn.execute("INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES('r-a',2,'a-r-a','untrusted','untrusted','{}')")
            row=conn.execute("SELECT run,epoch,digest FROM public.fw_checkpoints WHERE run='r-a' AND epoch=2").fetchone()
            conn.rollback()
        got=observe(admin,request,role)
        save('public-column-insert-actual.json',{'actual_row':row,'rolled_back':True,'admission':got})
        assert row=={'run':'r-a','epoch':2,'digest':'untrusted'}
        denied(got)
    finally:
        with admin.connect() as conn:conn.execute('REVOKE INSERT(run,epoch,attempt,digest,path,metrics) ON public.fw_checkpoints FROM PUBLIC')
    with tenant(request,'tenant-a') as conn:assert not conn.execute("SELECT 1 FROM public.fw_checkpoints WHERE run='r-a' AND epoch=2").fetchone()

@pytest.mark.parametrize('permission',['INSERT','UPDATE','DELETE'])
def test_table_write_drift_still_denied(authored_rows,permission):
    admin,request,role=authored_rows
    def change(action):
        with admin.connect() as conn:conn.execute(sql.SQL(action+' '+permission+' ON public.fw_checkpoints '+('TO' if action=='GRANT' else 'FROM')+' {}').format(sql.Identifier(role)))
    change('GRANT')
    try:denied(observe(admin,request,role))
    finally:change('REVOKE')


def test_no_default_checkpoint_write_grants_and_actual_denials(authored_rows):
    admin,request,role=authored_rows
    with tenant(request,'tenant-a') as conn:
        columns=[r['attname'] for r in conn.execute("SELECT attname FROM pg_attribute WHERE attrelid='public.fw_checkpoints'::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum")]
        assert columns==COLUMNS
        table={p:conn.execute("SELECT has_table_privilege(current_user,'public.fw_checkpoints',%s) allowed",(p,)).fetchone()['allowed'] for p in ['INSERT','UPDATE','DELETE']}
        column={p:conn.execute("SELECT has_any_column_privilege(current_user,'public.fw_checkpoints',%s) allowed",(p,)).fetchone()['allowed'] for p in ['INSERT','UPDATE']}
        assert not any(table.values()) and not any(column.values())
    states=[]
    for statement in ["INSERT INTO public.fw_checkpoints(run,epoch,attempt,digest,path,metrics) VALUES('r-a',2,'a-r-a','evil','evil','{}')", "UPDATE public.fw_checkpoints SET digest='evil' WHERE run='r-a'", "DELETE FROM public.fw_checkpoints WHERE run='r-a'"]:
        with tenant(request,'tenant-a') as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:conn.execute(statement)
        states.append(exc.value.sqlstate)
    save('no-default-writes.json',{'table':table,'column':column,'actual_sqlstates':states,'admission':observe(admin,request,role)})
    assert states==['42501']*3
