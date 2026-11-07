"""Operator activation: migrations/004 + fw_checkpoint_read_v1 in ONE transaction, then
verify() as the API principal (read-only). Idempotent: an applied 004 is detected, an
installed helper is verified (never adopted/replaced). Never prints DSNs or logins.

Usage: python -m tools.activate_generation [--operator-dsn-file .local.json] [--api-dsn-file .local-api.json]
Take a backup first (pg_dump); this is an additive expand migration.
"""
import argparse,hashlib,json,sys,time
from pathlib import Path
import psycopg
from psycopg.rows import dict_row
from psycopg.conninfo import conninfo_to_dict
ROOT=Path(__file__).resolve().parents[1]
MIGRATION=ROOT/'migrations/004_cancel_generation.sql'


def statements():
    body='\n'.join(l for l in MIGRATION.read_text().splitlines() if not l.lstrip().startswith('--'))
    return [s.strip() for s in body.split(';') if s.strip() and s.strip().upper() not in ('BEGIN','COMMIT')]


def activate(operator_dsn,api_dsn):
    from fieldwork.checkpoint_read import install,verify,SIGNATURE
    login=conninfo_to_dict(api_dsn)['user'];out={'migration_004_sha256':hashlib.sha256(MIGRATION.read_bytes()).hexdigest()}
    with psycopg.connect(operator_dsn,row_factory=dict_row) as c:
        c.execute("SET lock_timeout='5s'")
        has=c.execute("SELECT count(*) n FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('fw_runs','fw_attempts') AND column_name='cancel_generation'").fetchone()['n']
        out['cancel_generation_columns_before']=has
        if has==0:
            for s in statements():c.execute(s)
            out['migration_004']='applied'
        elif has==2:out['migration_004']='already_applied'
        else:raise SystemExit('PARTIAL_004_STATE')
        out['helper_before']=bool(c.execute('SELECT pg_catalog.to_regprocedure(%s) h',(SIGNATURE,)).fetchone()['h'])
        install(c,login)
    with psycopg.connect(api_dsn,row_factory=dict_row) as c:
        c.execute('SET TRANSACTION READ ONLY')
        verify(c,c.execute('SELECT session_user AS l').fetchone()['l']);out['verify_as_api_principal']='passed'
    out['at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());return out


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--operator-dsn-file',default=str(ROOT/'.local.json'));ap.add_argument('--api-dsn-file',default=str(ROOT/'.local-api.json'))
    a=ap.parse_args();sys.path.insert(0,str(ROOT))
    print(json.dumps(activate(json.load(open(a.operator_dsn_file))['dsn'],json.load(open(a.api_dsn_file))['dsn'])))
