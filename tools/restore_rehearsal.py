"""Real same-volume restore rehearsal; NOT independent encrypted disaster recovery.
Export one DB snapshot while holding product write/slot barriers. Copy immutable
checkpoint inventories, original fixture inputs, and attached result evidence.
Restore into a generated isolated database only; never reset the live database.
"""
import json,shutil,subprocess,time,uuid
from datetime import datetime,timezone
from pathlib import Path
import os
PG_CONTAINER=os.environ.get('FIELDWORK_PG_CONTAINER','fieldwork-postgres')
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo
from fieldwork.store import Store,ROOT
from fieldwork.data import canonical,digest


def inventory_copy(source,target,entries,relative):
    source=Path(source)
    if source.is_symlink() or not source.is_file():raise ValueError('Unreachable or symlinked committed file')
    data=source.read_bytes()
    if len(data)>64*1024*1024:raise ValueError('Rehearsal file exceeds declared bounded profile')
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb') as f:f.write(data)
    entries[relative]={'bytes':len(data),'sha256':digest(data)}


def rehearse():
    started=time.monotonic();s=Store();s.migrate();runid=uuid.uuid4().hex
    root=ROOT/'var/backup-rehearsals'/runid;backup=root/'backup';restored=root/'restored'
    from fieldwork.privacy_lifecycle import _check_c_ancestry,export_deletion_ledger,verify_apply_deletion_ledger
    parent=ROOT/'var'/'backup-rehearsals'
    _check_c_ancestry(parent,allow_missing_leaf=True)
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    _check_c_ancestry(parent)
    for directory in (root,backup,restored):
        _check_c_ancestry(directory,allow_missing_leaf=True)
        directory.mkdir(mode=0o700)
        _check_c_ancestry(directory)
    entries={};params=conninfo_to_dict(s.dsn);database='fieldwork_restore_'+runid;created=False
    try:
        from fieldwork.scoped_authority import check_private
        check_private(backup)
        check_private(restored)
        ledger=export_deletion_ledger(backup/'privacy-deletions')
        for path in sorted((backup/'privacy-deletions').iterdir()):
            relative='privacy-deletions/'+path.name
            data=path.read_bytes()
            entries[relative]={'bytes':len(data),'sha256':digest(data)}
        with s.connect() as c:
            c.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            c.execute("SET LOCAL lock_timeout='3s'")
            slot=c.execute('SELECT * FROM fw_slot WHERE id=1 FOR UPDATE').fetchone()
            if slot['run'] is not None:raise RuntimeError('Restore rehearsal waits for empty product heavy slot')
            c.execute('LOCK TABLE fw_runs,fw_checkpoints,fw_versions,fw_proposals,fw_accounts,fw_sessions IN SHARE MODE')
            snapshot=c.execute('SELECT pg_export_snapshot() AS id').fetchone()['id']
            checkpoints=c.execute('SELECT run,epoch,digest,path FROM fw_checkpoints ORDER BY run,epoch').fetchall()
            runs=c.execute('SELECT id,state,checkpoint FROM fw_runs ORDER BY id').fetchall()
            dump=subprocess.run(['docker','exec',PG_CONTAINER,'pg_dump','-U',params['user'],'-d',params['dbname'],'-Fc','--snapshot',snapshot],capture_output=True,check=True,timeout=30)
            (backup/'database.dump').write_bytes(dump.stdout)
            entries['database.dump']={'bytes':len(dump.stdout),'sha256':digest(dump.stdout)}
            for cp in checkpoints:
                source=Path(cp['path'])
                if digest((source/'manifest.json').read_bytes())!=cp['digest']:raise ValueError('Committed checkpoint anchor mismatch before backup')
                manifest=json.loads((source/'manifest.json').read_text())
                for name in ['manifest.json',*manifest['files']]:
                    relative='checkpoints/'+cp['digest']+'/'+name
                    if relative not in entries:inventory_copy(source/name,backup/relative,entries,relative)
                for name,item in manifest['files'].items():
                    copied=backup/'checkpoints'/cp['digest']/name
                    if copied.stat().st_size!=item['bytes'] or digest(copied.read_bytes())!=item['sha256']:raise ValueError('Checkpoint copy reconciliation')
            for source in (ROOT/'var/images').iterdir():
                relative='images/'+source.name;inventory_copy(source,backup/relative,entries,relative)
            for run in runs:
                source=ROOT/'var/runs'/run['id']
                files=[]
                for folder in ['bundle','evaluation']:
                    if (source/folder).exists():files.extend(p for p in (source/folder).rglob('*') if p.is_file())
                if (source/'fresh-process.json').exists():files.append(source/'fresh-process.json')
                for file in files:
                    relative='runs/'+run['id']+'/'+file.relative_to(source).as_posix();inventory_copy(file,backup/relative,entries,relative)
            manifest={'schema':1,'scope':'private-same-volume-rehearsal','as_of':datetime.now(timezone.utc).isoformat(),'files':entries,'checkpoints':checkpoints,'source_runs':len(runs),'privacy_deletion_ledger':ledger,'external_volume_disaster_recovery':False}
            (backup/'inventory.json').write_bytes(canonical(manifest))
        # Source dump/blobs are now stable; live service writes resume independently.
        with psycopg.connect(s.dsn,autocommit=True) as c:c.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(database)))
        created=True
        restore=subprocess.run(['docker','exec','-i',PG_CONTAINER,'pg_restore','-U',params['user'],'-d',database,'--no-owner','--exit-on-error'],input=(backup/'database.dump').read_bytes(),capture_output=True,check=True,timeout=30)
        for relative,item in entries.items():
            data=(backup/relative).read_bytes()
            if len(data)!=item['bytes'] or digest(data)!=item['sha256']:raise ValueError('Backup corruption before restore')
            target=restored/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        params['dbname']=database;copy=Store(dsn=make_conninfo(**params))
        with copy.connect() as c:
            before=c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n']
            assert before==len(runs)
            for cp in checkpoints:
                path=str(restored/'checkpoints'/cp['digest'])
                c.execute('UPDATE fw_checkpoints SET path=%s WHERE run=%s AND epoch=%s',(path,cp['run'],cp['epoch']))
                c.execute('UPDATE fw_runs SET checkpoint=%s WHERE id=%s AND checkpoint=%s',(path,cp['run'],cp['path']))
            c.execute("UPDATE fw_runs SET state=CASE WHEN state='cancel_requested' THEN 'cancelled' ELSE 'interrupted' END,fence=fence+1 WHERE state IN ('running','cancel_requested')")
            c.execute('UPDATE fw_slot SET run=NULL,pid=NULL WHERE id=1')
        copy.migrate();copy.migrate()
        privacy_restore=verify_apply_deletion_ledger(copy,restored/'privacy-deletions')
        with copy.connect() as c:
            after=c.execute('SELECT count(*) n FROM fw_runs').fetchone()['n'];rows=c.execute('SELECT digest,path FROM fw_checkpoints').fetchall()
            if before!=after or len(rows)!=len(checkpoints):raise ValueError('Migration changed restored population')
            for cp in rows:
                if digest((Path(cp['path'])/'manifest.json').read_bytes())!=cp['digest']:raise ValueError('Restored checkpoint anchor mismatch')
            role=c.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='fieldwork_api'").fetchone()
        result={'schema':1,'started_at':manifest['as_of'],'elapsed_seconds':time.monotonic()-started,'source_checkpoints':len(checkpoints),'restored_checkpoints':len(rows),'source_runs':len(runs),'verified_files':len(entries),'verified_bytes':sum(x['bytes'] for x in entries.values()),'privacy_deletion_ledger':privacy_restore,'migration_idempotent':True,'restored_database_isolated':True,'live_database_reset':False,'external_volume_disaster_recovery':False,'encrypted_external_backup':False,'fresh_model_inference_after_restore':False,'restore_generation_credentials_proven':False,'backup_directory':str(backup.relative_to(ROOT)),'restored_directory':str(restored.relative_to(ROOT)),'api_role_superuser':role['rolsuper'] if role else None,'api_role_bypassrls':role['rolbypassrls'] if role else None}
        __import__('fieldwork.evidence_out',fromlist=['x']).write_evidence(ROOT,'restore-rehearsal.json',canonical(result));return result
    finally:
        if created:
            with psycopg.connect(s.dsn,autocommit=True) as c:c.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(database)))

if __name__=='__main__':print(json.dumps(rehearse(),indent=2))
