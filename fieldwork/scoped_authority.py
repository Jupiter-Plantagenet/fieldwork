"""Opt-in scoped PostgreSQL lease capability. No Store or default credentials."""
import os

SCHEMA = 'fw_lease_cap_v1'
MODE = 'scoped-machine-v1'


def validate(a):
    if any(k.startswith('PG') for k in os.environ):
        raise ValueError('LIBPQ_ENVIRONMENT_FORBIDDEN')
    if (not isinstance(a, dict) or set(a) != {'purpose','authority_mode','connection','capability_schema','capability_version','workspaces'}
            or a['purpose'] != 'fieldwork-training-lease-controller' or a['authority_mode'] != MODE
            or a['capability_schema'] != SCHEMA or a['capability_version'] != 1):
        raise ValueError('INVALID_MACHINE_AUTHORITY')
    import re
    c=a['connection']; scopes=a['workspaces']
    if (not isinstance(c,dict) or set(c) != {'host','port','dbname','user','password','sslmode'}
            or any(not isinstance(c[k],str) or not c[k].strip() for k in ['host','dbname','user','password'])
            or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,62}',c['dbname'])
            or type(a['capability_version']) is not int
            or c['host'] not in ('127.0.0.1','::1') or type(c['port']) is not int or not 1<=c['port']<=65535
            or c['sslmode'] != 'disable'
            or not isinstance(scopes,list) or not 1<=len(scopes)<=100
            or any(not isinstance(s,str) or not s for s in scopes)
            or ('*' in scopes and scopes!=['*'])
            or len(set(scopes))!=len(scopes)):
        raise ValueError('INVALID_MACHINE_AUTHORITY')
    return a


# Fixed, schema-qualified bodies; no dynamic SQL, caller-selected function, or GUC scope.
# Round 5: scope ['*'] = every workspace. Lease expiry is a liveness invariant over every
# leased run; a static allowlist silently left runs in unlisted (e.g. historical)
# workspaces 'running' forever. The controller still sees only six run columns and can
# only expire overdue leases.
ALLOWED = '''SELECT EXISTS(SELECT 1 FROM fw_lease_cap_v1.scope s
    WHERE s.principal=session_user AND ($1=ANY(s.workspaces) OR s.workspaces=ARRAY['*']::text[]))'''
INFO = '''SELECT jsonb_build_object('principal',s.principal,'workspaces',s.workspaces,
    'version',s.version,'database',current_database(),'owner',s.owner)
    FROM fw_lease_cap_v1.scope s WHERE s.principal=session_user'''
EXPIRE = '''DECLARE changed record; detail jsonb;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM fw_lease_cap_v1.scope s WHERE s.principal=session_user) THEN
        RAISE EXCEPTION 'CAPABILITY_DENIED';
    END IF;
    WITH locked AS (
        SELECT r.id FROM public.fw_runs r
        WHERE r.id=p_run AND fw_lease_cap_v1.allowed(r.workspace)
          AND r.fence=p_fence AND r.revision=p_revision AND r.state=p_state
          AND r.state IN ('leased','running','cancel_requested') AND r.lease<=clock_timestamp()
        FOR UPDATE SKIP LOCKED
    ) UPDATE public.fw_runs r SET
        state=CASE WHEN r.state='cancel_requested' THEN 'cancelled' ELSE 'interrupted' END,
        fence=r.fence+1,revision=r.revision+1
    FROM locked WHERE r.id=locked.id AND fw_lease_cap_v1.allowed(r.workspace)
        AND r.lease<=clock_timestamp()
    RETURNING r.id,r.workspace,r.state,r.fence,r.revision INTO changed;
    IF NOT FOUND THEN RETURN NULL; END IF;
    detail=jsonb_build_object('state',changed.state,'fence',changed.fence,
        'physical_slot','RETAINED_NOT_RECONCILED',
        'diagnosis','LOGICAL_EXPIRY_IS_NOT_PHYSICAL_EXIT','automatic_retry',false);
    INSERT INTO public.fw_events(workspace,run,kind,payload,object_revision)
        VALUES(changed.workspace,changed.id,'expired',detail,changed.revision);
    RETURN jsonb_build_object('run',changed.id)||detail;
END'''


def _role_safe(c, name, login):
    row=c.execute('''SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,
        rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=%s''',(name,)).fetchone()
    if not row or any(row[k] for k in ['rolsuper','rolbypassrls','rolcreatedb','rolcreaterole','rolreplication']) or row['rolcanlogin'] != login:
        raise ValueError('UNSAFE_CAPABILITY_ROLE')
    if c.execute('''SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r
        ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname=%s''',(name,)).fetchone():
        raise ValueError('ROLE_MEMBERSHIP_FORBIDDEN')


def provision(connect, authority):
    """Operator only. One capability installation per DB. Never modifies existing roles.

    Existing complete installation is verified, not repaired or rotated. Transactional
    CREATE ROLE ensures failed initial provisioning leaves no half-installed authority.
    """
    from psycopg import sql
    a=validate(authority);login=a['connection']['user'];owner=login+'_owner'
    if len(owner.encode())>63:raise ValueError('ROLE_NAME_TOO_LONG')
    with connect() as c:
        if (c.info.host!=a['connection']['host'] or c.info.port!=a['connection']['port']
                or c.execute('SELECT current_database() db').fetchone()['db'] != a['connection']['dbname']):
            raise ValueError('WRONG_OPERATOR_DATABASE')
        exists=c.execute('SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=%s',(SCHEMA,)).fetchone()
        if exists:
            row=c.execute('SELECT * FROM fw_lease_cap_v1.scope').fetchall()
            if len(row)!=1 or row[0] != {'principal':login,'workspaces':a['workspaces'],'version':1,'owner':owner}:
                raise ValueError('EXISTING_CAPABILITY_MISMATCH')
            _role_safe(c,login,True);_role_safe(c,owner,False)
        else:
            for role in [login,owner]:
                if c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s',(role,)).fetchone():
                    raise ValueError('EXISTING_ROLE_NOT_ADOPTED')
            # Do not alter API/tenant policies or globally revoke any existing grant.
            for table in ['fw_runs','fw_events']:
                row=c.execute('SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE oid=%s::regclass',('public.'+table,)).fetchone()
                if not row or not row['relrowsecurity'] or not row['relforcerowsecurity']:
                    raise ValueError('EXISTING_RLS_REQUIRED')
            c.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT PASSWORD {}').format(sql.Identifier(login),sql.Literal(a['connection']['password'])))
            c.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT').format(sql.Identifier(owner)))
            c.execute('CREATE SCHEMA fw_lease_cap_v1')
            c.execute('REVOKE ALL ON SCHEMA fw_lease_cap_v1 FROM PUBLIC')
            c.execute('CREATE TABLE fw_lease_cap_v1.scope(principal text PRIMARY KEY, workspaces text[] NOT NULL, version int NOT NULL, owner text NOT NULL)')
            c.execute('REVOKE ALL ON fw_lease_cap_v1.scope FROM PUBLIC')
            c.execute('INSERT INTO fw_lease_cap_v1.scope VALUES(%s,%s,1,%s)',(login,a['workspaces'],owner))
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA public,fw_lease_cap_v1 TO {},{}').format(sql.Identifier(login),sql.Identifier(owner)))
            c.execute(sql.SQL('GRANT SELECT ON fw_lease_cap_v1.scope TO {}').format(sql.Identifier(owner)))
            for name,signature,returns,language,body in [
                ('allowed','text','boolean','sql',ALLOWED),('info','','jsonb','sql',INFO),
                ('expire','p_run text,p_fence integer,p_revision integer,p_state text','jsonb','plpgsql',EXPIRE)]:
                c.execute(sql.SQL('CREATE FUNCTION fw_lease_cap_v1.{}('+signature+') RETURNS '+returns+' LANGUAGE '+language+' SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS {}').format(sql.Identifier(name),sql.Literal(body)))
                c.execute(sql.SQL('ALTER FUNCTION fw_lease_cap_v1.{}('+signature+') OWNER TO {}').format(sql.Identifier(name),sql.Identifier(owner)))
                c.execute(sql.SQL('REVOKE ALL ON FUNCTION fw_lease_cap_v1.{}('+signature+') FROM PUBLIC').format(sql.Identifier(name)))
                c.execute(sql.SQL('GRANT EXECUTE ON FUNCTION fw_lease_cap_v1.{}('+signature+') TO {}').format(sql.Identifier(name),sql.Identifier(login)))
            c.execute(sql.SQL('GRANT SELECT(id,workspace,fence,revision,state,lease) ON public.fw_runs TO {},{}').format(sql.Identifier(login),sql.Identifier(owner)))
            c.execute(sql.SQL('GRANT UPDATE(state,fence,revision) ON public.fw_runs TO {}').format(sql.Identifier(owner)))
            c.execute(sql.SQL('GRANT INSERT(workspace,run,kind,payload,object_revision) ON public.fw_events TO {}').format(sql.Identifier(owner)))
            c.execute(sql.SQL('GRANT USAGE ON SEQUENCE public.fw_events_seq_seq TO {}').format(sql.Identifier(owner)))
            for table,roles in [('fw_runs',[login,owner]),('fw_events',[owner])]:
                identifiers=sql.SQL(',').join(map(sql.Identifier,roles))
                for suffix,mode in [('allow','PERMISSIVE'),('bound','RESTRICTIVE')]:
                    c.execute(sql.SQL('CREATE POLICY {} ON public.{} AS '+mode+' FOR ALL TO {} USING (fw_lease_cap_v1.allowed(workspace)) WITH CHECK (fw_lease_cap_v1.allowed(workspace))').format(sql.Identifier('fw_cap_'+suffix),sql.Identifier(table),identifiers))
    # Read back on the actual nonowner authenticated connection, never SET ROLE.
    MachineBackend(a).verify()


class MachineBackend:
    def __init__(self, authority):
        self.authority=validate(authority)

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row
        validate(self.authority)
        # Explicit password disables passfile fallback. All PG* variables rejected.
        c=psycopg.connect(**self.authority['connection'],connect_timeout=1,
            options='-c search_path=pg_catalog,pg_temp',row_factory=dict_row,
            application_name='fieldwork-scoped-lease-controller')
        try:
            from .lease_recovery import PostgresBackend
            PostgresBackend._limits(c)
            self._verify(c)
            return c
        except BaseException:
            c.close();raise

    def verify(self):
        with self.connect():pass

    def _verify(self,c):
        a=self.authority;p=a['connection'];owner=p['user']+'_owner'
        row=c.execute('SELECT current_database() db,current_user::text usr,session_user::text session,current_setting(\'search_path\') path').fetchone()
        if row != {'db':p['dbname'],'usr':p['user'],'session':p['user'],'path':'pg_catalog,pg_temp'}:
            raise ValueError('IDENTITY_OR_PATH_MISMATCH')
        _role_safe(c,p['user'],True);_role_safe(c,owner,False)
        scope=c.execute('SELECT fw_lease_cap_v1.info() value').fetchone()['value']
        if scope != {'principal':p['user'],'workspaces':a['workspaces'],'version':1,'database':p['dbname'],'owner':owner}:
            raise ValueError('SCOPE_MISMATCH')
        funcs=c.execute('''SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,pg_catalog.pg_get_userbyid(p.proowner) owner
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='fw_lease_cap_v1' ORDER BY p.proname''').fetchall()
        if len(funcs)!=3:raise ValueError('CAPABILITY_FUNCTION_MISMATCH')
        for f in funcs:
            if (f['prosrc'] != {'allowed':ALLOWED,'info':INFO,'expire':EXPIRE}.get(f['proname']) or not f['prosecdef']
                    or f['proconfig'] != ['search_path=pg_catalog, pg_temp'] or f['owner']!=owner):
                raise ValueError('CAPABILITY_FUNCTION_MISMATCH')
        # The explicitly trusted installer is the database owner. Neither capability
        # role may own metadata/schema; column ACLs and PUBLIC/third-role grants
        # matter even when has_table_privilege reports false. Never repair drift.
        trusted=c.execute('SELECT datdba FROM pg_catalog.pg_database WHERE datname=current_database()').fetchone()['datdba']
        metadata=c.execute("SELECT relowner,relacl FROM pg_catalog.pg_class WHERE oid='fw_lease_cap_v1.scope'::regclass").fetchone()
        namespace=c.execute("SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='fw_lease_cap_v1'").fetchone()
        if metadata['relowner']!=trusted or namespace['nspowner']!=trusted:
            raise ValueError('UNPROTECTED_SCOPE_METADATA')
        acl=c.execute('''SELECT acl.*,NULL::text column_name FROM pg_catalog.pg_class t,
            LATERAL pg_catalog.aclexplode(coalesce(t.relacl,pg_catalog.acldefault('r',t.relowner))) acl
            WHERE t.oid='fw_lease_cap_v1.scope'::regclass
            UNION ALL SELECT acl.*,a.attname::text FROM pg_catalog.pg_attribute a,
            LATERAL pg_catalog.aclexplode(a.attacl) acl
            WHERE a.attrelid='fw_lease_cap_v1.scope'::regclass AND a.attnum>0 AND NOT a.attisdropped''').fetchall()
        owner_oid=c.execute('SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s',(owner,)).fetchone()['oid']
        # No nonserver principal may inherit or SET ROLE into the installer.
        if c.execute('''SELECT 1 FROM pg_catalog.pg_roles r WHERE NOT r.rolsuper
            AND r.oid<>%s AND pg_catalog.pg_has_role(r.oid,%s,'MEMBER')''',(trusted,trusted)).fetchone():
            raise ValueError('UNPROTECTED_SCOPE_METADATA')
        schemas=c.execute('''SELECT n.nspname,n.nspowner,acl.*,
            (SELECT oid FROM pg_catalog.pg_roles WHERE rolname='pg_database_owner') database_owner_role
            FROM pg_catalog.pg_namespace n,
            LATERAL pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) acl
            WHERE n.nspname IN ('public','fw_lease_cap_v1')''').fetchall()
        for entry in schemas:
            trusted_owners=[trusted]+([entry['database_owner_role']] if entry['nspname']=='public' else [])
            if entry['nspowner'] not in trusted_owners:
                raise ValueError('UNPROTECTED_SCOPE_SCHEMA')
            if entry['grantee'] in trusted_owners:continue
            if entry['privilege_type']=='CREATE' or entry['is_grantable']:
                raise ValueError('UNPROTECTED_SCOPE_SCHEMA')
            if entry['nspname']==SCHEMA and entry['grantee'] not in [owner_oid,
                    c.execute('SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s',(p['user'],)).fetchone()['oid']]:
                raise ValueError('UNPROTECTED_SCOPE_SCHEMA')
        for entry in acl:
            if entry['grantee']==trusted:continue
            if (entry['grantee']!=owner_oid or entry['privilege_type']!='SELECT'
                    or entry['is_grantable'] or entry['grantor']!=trusted):
                raise ValueError('UNPROTECTED_SCOPE_METADATA')
        for role in [p['user'],owner]:
            for privilege in ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']:
                actual=c.execute('SELECT has_table_privilege(%s,\'fw_lease_cap_v1.scope\',%s) v',(role,privilege)).fetchone()['v']
                if actual != (role==owner and privilege=='SELECT'):
                    raise ValueError('UNPROTECTED_SCOPE_METADATA')
        unsafe=c.execute('''SELECT 1 FROM pg_catalog.pg_proc f
            JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace,
            LATERAL pg_catalog.aclexplode(coalesce(f.proacl,pg_catalog.acldefault('f',f.proowner))) acl
            WHERE n.nspname='fw_lease_cap_v1' AND acl.privilege_type='EXECUTE'
              AND acl.grantee NOT IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=ANY(%s))''',([p['user'],owner],)).fetchone()
        if unsafe:raise ValueError('CROSS_PRINCIPAL_EXECUTE')
        for role in [p['user'],owner]:
            for function in ['allowed(text)','info()','expire(text,integer,integer,text)']:
                if not c.execute("SELECT has_function_privilege(%s,%s,'EXECUTE') v",(role,SCHEMA+'.'+function)).fetchone()['v']:
                    raise ValueError('CAPABILITY_EXECUTE_REQUIRED')
        for table,roles in [('fw_runs',[p['user'],owner]),('fw_events',[owner])]:
            rls=c.execute('SELECT relrowsecurity,relforcerowsecurity FROM pg_catalog.pg_class WHERE oid=%s::regclass',('public.'+table,)).fetchone()
            if not rls or not all(rls.values()):raise ValueError('RLS_REQUIRED')
            policies=c.execute('''SELECT polname,polpermissive,polcmd,
                pg_catalog.pg_get_expr(polqual,polrelid) qual,
                pg_catalog.pg_get_expr(polwithcheck,polrelid) chk,
                ARRAY(SELECT rolname::text FROM pg_catalog.pg_roles WHERE oid=ANY(polroles) ORDER BY rolname) roles
                FROM pg_catalog.pg_policy WHERE polrelid=%s::regclass AND polname IN ('fw_cap_allow','fw_cap_bound') ORDER BY polname''',('public.'+table,)).fetchall()
            expected=[{'polname':'fw_cap_'+suffix,'polpermissive':permissive,'polcmd':'*',
                       'qual':'fw_lease_cap_v1.allowed(workspace)','chk':'fw_lease_cap_v1.allowed(workspace)','roles':sorted(roles)}
                      for suffix,permissive in [('allow',True),('bound',False)]]
            if policies!=expected:raise ValueError('SCOPE_POLICY_MISMATCH')
        # Evaluate rights for BOTH identities, including inherited/PUBLIC rights.
        # Table grants cannot substitute for the exact column allowlist.
        roles=[p['user'],owner]
        rights=c.execute('''SELECT r.rolname,t.relname,x.privilege,
            has_table_privilege(r.oid,t.oid,x.privilege) actual,
            has_table_privilege(r.oid,t.oid,x.privilege||' WITH GRANT OPTION') delegation
            FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_class t
            JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
            CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) x(privilege)
            WHERE r.rolname=ANY(%s) AND n.nspname='public' AND t.relkind IN ('r','p','v','m','f')''',(roles,)).fetchall()
        if any(r['actual'] or r['delegation'] for r in rights):raise ValueError('DIRECT_MUTATION_FORBIDDEN')
        rights=c.execute('''SELECT r.rolname,t.relname,a.attname,x.privilege,
            has_column_privilege(r.oid,t.oid,a.attnum,x.privilege) actual,
            has_column_privilege(r.oid,t.oid,a.attnum,x.privilege||' WITH GRANT OPTION') delegation
            FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_class t
            JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
            JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
            CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) x(privilege)
            WHERE r.rolname=ANY(%s) AND n.nspname='public' AND t.relkind IN ('r','p','v','m','f')''',(roles,)).fetchall()
        for r in rights:
            expected=(r['relname']=='fw_runs' and
                ((r['privilege']=='SELECT' and r['attname'] in ['id','workspace','fence','revision','state','lease']) or
                 (r['rolname']==owner and r['privilege']=='UPDATE' and r['attname'] in ['state','fence','revision']))) or (
                r['rolname']==owner and r['relname']=='fw_events' and r['privilege']=='INSERT' and
                r['attname'] in ['workspace','run','kind','payload','object_revision'])
            if r['actual']!=expected or r['delegation']:raise ValueError('COLUMN_CAPABILITY_MISMATCH')
        rights=c.execute('''SELECT r.rolname,t.relname,x.privilege,
            has_sequence_privilege(r.oid,t.oid,x.privilege) actual,
            has_sequence_privilege(r.oid,t.oid,x.privilege||' WITH GRANT OPTION') delegation
            FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_class t
            JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
            CROSS JOIN unnest(ARRAY['USAGE','SELECT','UPDATE']) x(privilege)
            WHERE r.rolname=ANY(%s) AND n.nspname='public' AND t.relkind='S' ''',(roles,)).fetchall()
        for r in rights:
            expected=r['rolname']==owner and r['relname']=='fw_events_seq_seq' and r['privilege']=='USAGE'
            if r['actual']!=expected or r['delegation']:raise ValueError('SEQUENCE_CAPABILITY_MISMATCH')
        for role in roles:
            for schema in ['public',SCHEMA]:
                rights=c.execute('''SELECT has_schema_privilege(%s,%s,'USAGE') usage,
                    has_schema_privilege(%s,%s,'CREATE') create_right,
                    has_schema_privilege(%s,%s,'USAGE WITH GRANT OPTION') delegation''',(role,schema)*3).fetchone()
                if not rights['usage'] or rights['create_right'] or rights['delegation']:
                    raise ValueError('SCHEMA_CREATE_FORBIDDEN')
            if c.execute('''SELECT has_database_privilege(%s,current_database(),'CREATE') OR
                has_database_privilege(%s,current_database(),'CONNECT WITH GRANT OPTION') OR
                has_database_privilege(%s,current_database(),'TEMP WITH GRANT OPTION') v''',(role,)*3).fetchone()['v']:
                raise ValueError('DATABASE_CREATE_FORBIDDEN')
        # Function owners intrinsically control their own fixed functions. Explicit
        # grant options (including to that owner) are never part of the installation.
        if c.execute('''SELECT 1 FROM pg_catalog.pg_proc f
            JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace,
            LATERAL pg_catalog.aclexplode(f.proacl) acl
            WHERE n.nspname='fw_lease_cap_v1' AND acl.is_grantable''').fetchone():
            raise ValueError('CAPABILITY_DELEGATION_FORBIDDEN')

    def candidates(self,cursor,batch_size):
        with self.connect() as c:
            return c.execute('''SELECT id,fence,revision,state FROM public.fw_runs
                WHERE id>%s AND state IN ('leased','running','cancel_requested')
                AND lease<=clock_timestamp() ORDER BY id LIMIT %s''',(cursor,batch_size)).fetchall()

    def expire(self,candidate):
        with self.connect() as c:
            return c.execute('SELECT fw_lease_cap_v1.expire(%s,%s,%s,%s) value',
                (candidate['id'],candidate['fence'],candidate['revision'],candidate['state'])).fetchone()['value']


def upgrade(connect, authority, workspaces):
    """Round-5 in-place upgrade of an existing v1 installation (operator, one transaction).

    Replaces the three fixed function bodies with the current constants (adds the 'leased'
    state and the ['*'] all-workspaces scope) and sets the scope row. CREATE OR REPLACE keeps
    each function's owner and ACL. Returns the new authority dict; the caller rewrites the
    private authority file. The running controller must be restarted on the new source.
    """
    from psycopg import sql
    import copy
    a=copy.deepcopy(validate(authority));a['workspaces']=list(workspaces);validate(a)
    login=a['connection']['user'];owner=login+'_owner'
    with connect() as c:
        row=c.execute('SELECT * FROM fw_lease_cap_v1.scope').fetchall()
        if len(row)!=1 or row[0]['principal']!=login or row[0]['owner']!=owner:raise ValueError('EXISTING_CAPABILITY_MISMATCH')
        for name,signature,returns,language,body in [
            ('allowed','text','boolean','sql',ALLOWED),('info','','jsonb','sql',INFO),
            ('expire','p_run text,p_fence integer,p_revision integer,p_state text','jsonb','plpgsql',EXPIRE)]:
            c.execute(sql.SQL('CREATE OR REPLACE FUNCTION fw_lease_cap_v1.{}('+signature+') RETURNS '+returns+' LANGUAGE '+language+' SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS {}').format(sql.Identifier(name),sql.Literal(body)))
        c.execute('UPDATE fw_lease_cap_v1.scope SET workspaces=%s WHERE principal=%s',(a['workspaces'],login))
    MachineBackend(a).verify()
    return a


def _powershell(script):
    import base64,subprocess
    encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
    # Codex may itself run under PowerShell 7. Its PSModulePath is incompatible
    # with Windows PowerShell 5's Security module; let the native child discover
    # its own module roots instead of failing the mandatory ACL check.
    env={k:v for k,v in os.environ.items() if k.upper() not in {'PSMODULEPATH','PSMODULEANALYSISCACHEPATH','PSHOME'}}
    subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
                   check=True,capture_output=True,timeout=15,env=env)


def check_private(path):
    """Fail closed on broad ACLs; no secret content passed to a shell."""
    from pathlib import Path
    import stat
    path=Path(path)
    if path.is_symlink():raise ValueError('SYMLINK_AUTHORITY_FORBIDDEN')
    if os.name=='nt':
        p=str(path.resolve()).replace("'","''")
        _powershell("$ErrorActionPreference='Stop'; $p='"+p+"'; "
            "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$acl=Get-Acl -LiteralPath $p; "
            "$owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value; "
            "if($owner -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'owner'}; "
            "if(@($acl.Access).Count -eq 0){throw 'empty ACL'}; "
            "foreach($r in $acl.Access){$id=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; "
            "if($r.AccessControlType -eq 'Allow' -and $id -notin @($sid,'S-1-5-18','S-1-5-32-544','S-1-3-4')){throw 'broad ACL'}}")
    elif path.stat().st_uid!=os.getuid() or stat.S_IMODE(path.stat().st_mode)&0o077:
        raise ValueError('PRIVATE_AUTHORITY_REQUIRED')


def provision_file(connect, plan, path, *, existing_authority=None):
    """Explicit operator invocation only. Reuse exact credentials on every retry.

    File is staged privately before DB DDL so a failed/retried invocation never
    loses the only password. It is NOT evidence of activation/readiness by itself.
    """
    import copy,json,secrets
    from pathlib import Path
    path=Path(path);a=copy.deepcopy(plan)
    if not isinstance(a.get('connection'),dict) or 'password' in a['connection']:
        raise ValueError('NONSECRET_PLAN_REQUIRED')
    a['connection']['password']='validation-placeholder'
    validate(a)
    if path.exists():
        check_private(path)
        if path.stat().st_size>65536:raise ValueError('INVALID_AUTHORITY_FILE')
        existing=validate(json.loads(path.read_text()))
        expected=copy.deepcopy(existing);del expected['connection']['password']
        if expected!=plan:raise ValueError('EXISTING_FILE_MISMATCH')
        a=existing
    else:
        if not path.parent.exists():
            path.parent.mkdir(mode=0o700)
            if os.name=='nt':
                p=str(path.parent.resolve()).replace("'","''")
                _powershell("$ErrorActionPreference='Stop'; $p='"+p+"'; "
                    "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
                    "& icacls.exe $p /inheritance:r /grant:r ('*'+$sid.Value+':(OI)(CI)F') | Out-Null; "
                    "if($LASTEXITCODE -ne 0){throw 'ACL_FAILED'}")
        check_private(path.parent)
        if existing_authority is not None:
            a=validate(existing_authority)
            expected=copy.deepcopy(a);del expected['connection']['password']
            if expected!=plan:raise ValueError('EXISTING_FILE_MISMATCH')
        else:a['connection']['password']=secrets.token_urlsafe(48)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(a,f);f.flush();os.fsync(f.fileno())
        check_private(path)
    provision(connect,a)
    return {'authority_mode':MODE,'provisioned':True,'activated':False,'secret_printed':False}


def main(argv=None):
    """No default config paths; requires an explicit plan and explicit operator file."""
    import argparse,json
    from pathlib import Path
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operator-file',required=True)
    parser.add_argument('--plan-file',required=True)
    parser.add_argument('--authority-file',required=True)
    parser.add_argument('--confirm-provision',action='store_true',required=True)
    args=parser.parse_args(argv)
    try:
        import psycopg
        from psycopg.rows import dict_row
        check_private(args.operator_file)
        operator=json.loads(Path(args.operator_file).read_text())
        plan=json.loads(Path(args.plan_file).read_text())
        # Operator endpoint must exactly equal the approved target endpoint.
        test=dict(plan,connection=operator)
        validate(test)
        if any(operator[k]!=plan['connection'][k] for k in ['host','port','dbname','sslmode']):
            raise ValueError('OPERATOR_ENDPOINT_MISMATCH')
        def connect():return psycopg.connect(**operator,row_factory=dict_row,connect_timeout=1,
            options='-c search_path=pg_catalog,pg_temp')
        print(json.dumps(provision_file(connect,plan,args.authority_file)))
        return 0
    except Exception as exc:
        print(json.dumps({'code':'PROVISION_STOPPED','error_type':type(exc).__name__}))
        return 2


if __name__=='__main__':raise SystemExit(main())
