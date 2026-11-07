"""Additive v1 read/row-lock capability. Operator installation only.

The API never receives checkpoint UPDATE. A fresh non-login, non-bypass role
owns one fixed SELECT function and only the column privilege needed for SHARE.
No default Store, credentials, automatic installation or retained refresh here.
"""
import re
from psycopg import sql

SCHEMA='fw_checkpoint_read_v1'
SIGNATURE=SCHEMA+'.locked_digest(text,integer,text)'


def _body(login):
    # Literal role binding is server-quoted, never executable caller SQL.
    return sql.SQL('''BEGIN
    IF session_user <> {} OR p_workspace IS DISTINCT FROM
        pg_catalog.current_setting('fieldwork.workspace',true) THEN
        RAISE EXCEPTION 'CHECKPOINT_READ_DENIED' USING ERRCODE='42501';
    END IF;
    RETURN QUERY SELECT cp.digest FROM public.fw_checkpoints cp
        JOIN public.fw_runs r ON r.id=cp.run
        WHERE cp.run=p_run AND cp.epoch=p_epoch AND r.workspace=p_workspace
          AND r.state='succeeded' AND r.artifact_status='verified'
          AND r.result->'best'->>'epoch'=p_epoch::text
        FOR SHARE OF cp;
END''').format(sql.Literal(login))


def install(connection,login):
    """Install atomically inside the operator's db_security transaction.

    Never adopt an existing owner/schema or silently replace an installed body.
    Exact complete reinstallation is a read-only validation of this capability.
    """
    c=connection;owner=login+'_cp_lock'
    if len(owner.encode())>63:raise ValueError('CHECKPOINT_OWNER_NAME_TOO_LONG')
    role=c.execute('SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication FROM pg_catalog.pg_roles WHERE rolname=%s',(login,)).fetchone()
    if not role or any(role.values()):raise ValueError('UNSAFE_CHECKPOINT_API_ROLE')
    if c.execute('SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=%s',(SCHEMA,)).fetchone():
        # Review F4: a schema without our NOLOGIN owner role was not created by this
        # installer and is never adopted; an existing complete install is only verified.
        if not c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s',(owner,)).fetchone():
            raise ValueError('EXISTING_CHECKPOINT_SCHEMA_NOT_ADOPTED')
        verify(c,login);return
    if c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s',(owner,)).fetchone():
        raise ValueError('EXISTING_CHECKPOINT_OWNER_NOT_ADOPTED')
    c.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT').format(sql.Identifier(owner)))
    c.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(SCHEMA)))
    c.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(SCHEMA)))
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA public,{} TO {}').format(sql.Identifier(SCHEMA),sql.Identifier(owner)))
    c.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(SCHEMA),sql.Identifier(login)))
    c.execute(sql.SQL('GRANT SELECT ON public.fw_runs TO {}').format(sql.Identifier(owner)))
    c.execute(sql.SQL('GRANT SELECT ON public.fw_checkpoints TO {}').format(sql.Identifier(owner)))
    c.execute(sql.SQL('GRANT UPDATE(digest) ON public.fw_checkpoints TO {}').format(sql.Identifier(owner)))
    c.execute(sql.SQL('CREATE FUNCTION '+SIGNATURE.replace('(text,integer,text)','(p_run text,p_epoch integer,p_workspace text)')+' RETURNS TABLE(digest text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS {}').format(sql.Literal(_body(login).as_string(c))))
    c.execute(sql.SQL('ALTER FUNCTION '+SIGNATURE+' OWNER TO {}').format(sql.Identifier(owner)))
    c.execute(sql.SQL('REVOKE ALL ON FUNCTION '+SIGNATURE+' FROM PUBLIC'))
    c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION '+SIGNATURE+' TO {}').format(sql.Identifier(login)))
    verify(c,login)


def _fixed_path(config):
    """Parse exactly two SQL identifiers, preserving quoted identifier case.

    This is a deliberately bounded identifier-list grammar, not quote stripping
    or substring matching. Unquoted ASCII names fold to lower case; a quoted
    comma belongs to one identifier and cannot masquerade as a list separator.
    """
    if not config or len(config)!=1:return False
    ws=r'[ \t\n\r\f]*'
    identifier=r'(?:"(?:[^"\x00]|"")*"|[A-Za-z_][A-Za-z_0-9$]*)'
    match=re.fullmatch('search_path='+ws+'('+identifier+')'+ws+','+ws+'('+identifier+')'+ws,config[0])
    if not match:return False
    names=[item[1:-1].replace('""','"') if item.startswith('"') else item.lower()
           for item in match.groups()]
    return names==['pg_catalog','pg_temp']


def verify(c,login):
    """Fail closed on changed body/owner/path, unsafe memberships or API writes."""
    owner=login+'_cp_lock'
    # Validate the declared request login, also when verify is called by the
    # installation operator. Never substitute current_user for this principal.
    runtime=c.execute('''SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,
        rolreplication FROM pg_catalog.pg_roles WHERE rolname=%s''',(login,)).fetchone()
    if not runtime or any(runtime.values()):raise ValueError('UNSAFE_CHECKPOINT_API_ROLE')
    flags=c.execute('''SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,
        rolreplication,rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=%s''',(owner,)).fetchone()
    if not flags or any(flags.values()):raise ValueError('UNSAFE_CHECKPOINT_OWNER')
    members=c.execute('''SELECT 1 FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles r ON r.oid=m.member OR r.oid=m.roleid
        WHERE r.rolname=ANY(%s)''',([owner,login],)).fetchone()
    if members:raise ValueError('CHECKPOINT_ROLE_MEMBERSHIP')
    # Review F4: the schema must be owned by the trusted installer (superuser or the
    # database owner), nobody else may CREATE in it, and it must contain exactly this one
    # function, so no foreign overload can shadow the production call.
    schema=c.execute('''SELECT n.oid,r.rolsuper,n.nspowner=d.datdba AS dbowner,
        n.nspowner,n.nspacl IS NULL AS default_acl FROM pg_catalog.pg_namespace n
        JOIN pg_catalog.pg_roles r ON r.oid=n.nspowner
        JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()
        WHERE n.nspname=%s''',(SCHEMA,)).fetchone()
    if not schema or not (schema['rolsuper'] or schema['dbowner']):raise ValueError('CHECKPOINT_SCHEMA_OWNER')
    if c.execute('''SELECT 1 FROM pg_catalog.pg_namespace n,
        LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
        WHERE n.oid=%s AND a.privilege_type='CREATE' AND a.grantee<>n.nspowner''',(schema['oid'],)).fetchone():
        raise ValueError('CHECKPOINT_SCHEMA_CREATE_GRANTED')
    functions=c.execute('''SELECT count(*) n FROM pg_catalog.pg_proc WHERE pronamespace=%s''',(schema['oid'],)).fetchone()['n']
    others=c.execute('''SELECT count(*) n FROM pg_catalog.pg_class WHERE relnamespace=%s''',(schema['oid'],)).fetchone()['n']
    if functions!=1 or others:raise ValueError('CHECKPOINT_SCHEMA_FOREIGN_OBJECTS')
    fn=c.execute('''SELECT pg_catalog.pg_get_userbyid(proowner) AS owner,
        prosecdef,proconfig,prosrc,proacl::text,l.lanname,proretset,provolatile
        FROM pg_catalog.pg_proc JOIN pg_catalog.pg_language l ON l.oid=prolang
        WHERE pg_proc.oid=pg_catalog.to_regprocedure(%s)''',(SIGNATURE,)).fetchone()
    if (not fn or fn['owner']!=owner or not fn['prosecdef'] or fn['lanname']!='plpgsql'
            or not fn['proretset'] or fn['provolatile']!='v'
            or not _fixed_path(fn['proconfig'])
            or fn['prosrc']!=_body(login).as_string(c)):
        raise ValueError('CHECKPOINT_FUNCTION_MISMATCH')
    # NULL means PostgreSQL's built-in function ACL, not empty privileges.
    if c.execute('''SELECT 1 FROM pg_catalog.pg_proc p,
        LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,
            pg_catalog.acldefault('f',p.proowner))) a
        WHERE p.oid=pg_catalog.to_regprocedure(%s) AND a.grantee=0
            AND a.privilege_type='EXECUTE' ''',(SIGNATURE,)).fetchone():
        raise ValueError('CHECKPOINT_PUBLIC_EXECUTE')
    for table in ['fw_runs','fw_checkpoints']:
        row=c.execute('SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE oid=%s::regclass',('public.'+table,)).fetchone()
        if not row or not all(row.values()):raise ValueError('CHECKPOINT_RLS_REQUIRED')
    # Check effective dependencies as the declared definer, not as the operator
    # running install/verify. Column SELECT is sufficient; unrelated columns and
    # run UPDATE are not required. PostgreSQL SHARE needs UPDATE on any column.
    if not c.execute("SELECT pg_catalog.has_schema_privilege(%s,'public','USAGE') allowed",(owner,)).fetchone()['allowed']:
        raise ValueError('CHECKPOINT_OWNER_ACCESS_REQUIRED')
    for table,columns in [('fw_checkpoints',['run','epoch','digest']),
            ('fw_runs',['id','workspace','state','artifact_status','result'])]:
        for column in columns:
            if not c.execute("SELECT pg_catalog.has_column_privilege(%s,%s,%s,'SELECT') allowed",(owner,'public.'+table,column)).fetchone()['allowed']:
                raise ValueError('CHECKPOINT_OWNER_ACCESS_REQUIRED')
    if not c.execute("SELECT pg_catalog.has_any_column_privilege(%s,'public.fw_checkpoints','UPDATE') allowed",(owner,)).fetchone()['allowed']:
        raise ValueError('CHECKPOINT_OWNER_ACCESS_REQUIRED')
    if not c.execute('SELECT pg_catalog.has_schema_privilege(%s,%s,\'USAGE\') allowed',(login,SCHEMA)).fetchone()['allowed']:
        raise ValueError('CHECKPOINT_SCHEMA_USAGE_REQUIRED')
    for permission in ['INSERT','UPDATE','DELETE']:
        if c.execute('SELECT pg_catalog.has_table_privilege(%s,%s,%s) allowed',(login,'public.fw_checkpoints',permission)).fetchone()['allowed']:
            raise ValueError('CHECKPOINT_API_WRITE_FORBIDDEN')
        if permission in ['INSERT','UPDATE'] and c.execute("SELECT pg_catalog.has_any_column_privilege(%s,'public.fw_checkpoints',%s) allowed",(login,permission)).fetchone()['allowed']:
            raise ValueError('CHECKPOINT_API_COLUMN_WRITE_FORBIDDEN')
    if not c.execute('SELECT pg_catalog.has_function_privilege(%s,%s,\'EXECUTE\') allowed',(login,SIGNATURE)).fetchone()['allowed']:
        raise ValueError('CHECKPOINT_EXECUTE_REQUIRED')
