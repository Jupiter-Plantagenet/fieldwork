import json,subprocess,uuid
import os
PG_CONTAINER=os.environ.get('FIELDWORK_PG_CONTAINER','fieldwork-postgres')
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from fieldwork.store import Store,ROOT
from fieldwork.data import canonical,digest


def test_expansion_migration_preserves_original_snapshot_rows_and_is_repeatable():
    admin=Store();params=conninfo_to_dict(admin.dsn);name='fieldwork_migration_'+uuid.uuid4().hex
    backup=ROOT/'var/snapshots/pre-release-work.dump'
    assert backup.is_file(),'Private pre-migration snapshot required; this is not clean-host proof'
    with psycopg.connect(admin.dsn,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    try:
        subprocess.run(['docker','exec','-i',PG_CONTAINER,'pg_restore','-U',params['user'],'-d',name,'--no-owner','--exit-on-error'],input=backup.read_bytes(),capture_output=True,check=True,timeout=30)
        params['dbname']=name;s=Store(dsn=make_conninfo(**params))
        with s.connect() as c:
            assert c.execute("SELECT 1 FROM information_schema.columns WHERE table_name='fw_runs' AND column_name='artifact_status'").fetchone() is None
            before=c.execute('SELECT id,workspace,actor,idem,digest,config,state,fence,epoch,revision,attempt,checkpoint,result FROM fw_runs ORDER BY id').fetchall()
            events_before=c.execute('SELECT count(*) n FROM fw_events').fetchone()['n']
        s.migrate();s.migrate()
        with s.connect() as c:
            after=c.execute('SELECT id,workspace,actor,idem,digest,config,state,fence,epoch,revision,attempt,checkpoint,result FROM fw_runs ORDER BY id').fetchall()
            assert before==after
            assert c.execute('SELECT count(*) n FROM fw_events').fetchone()['n']==events_before
            assert c.execute("SELECT count(*) n FROM fw_runs WHERE artifact_status<>'not_started'").fetchone()['n']==0
        report={'source_snapshot_sha256':digest(backup.read_bytes()),'isolated_database':True,'original_runs_preserved':len(before),'original_events_preserved':events_before,'repeat_migration_noop':True,'destructive_downmigration_run':False,'old_binary_compatibility_full_suite':False,'live_database_reset':False}
        __import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'migration-rehearsal.json',canonical(report))
    finally:
        with psycopg.connect(admin.dsn,autocommit=True) as c:c.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
