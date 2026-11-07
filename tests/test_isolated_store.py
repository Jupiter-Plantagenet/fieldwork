import uuid
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from fieldwork.store import Store


def test_store_explicit_dsn_keeps_live_records_untouched():
    live=Store();params=conninfo_to_dict(live.dsn);name='fieldwork_test_'+uuid.uuid4().hex
    with psycopg.connect(live.dsn,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    try:
        params['dbname']=name
        s=Store(dsn=make_conninfo(**params));s.migrate()
        w='isolated-'+str(uuid.uuid4());r=s.submit(w,'test','one',{'epochs':1})
        assert s.get(r['id'])['workspace']==w
        assert live.get(r['id']) is None
    finally:
        with psycopg.connect(live.dsn,autocommit=True) as c:c.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
