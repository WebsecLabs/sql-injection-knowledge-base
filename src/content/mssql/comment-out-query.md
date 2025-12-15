---
title: Comment Out Query
description: How to comment out the remainder of a query in MSSQL
category: Basics
order: 2
tags: ["basics", "syntax", "comments"]
lastUpdated: 2025-03-15
---

## Comment Out Query

In SQL injection attacks, commenting out the remainder of a query is often necessary to ensure that the injection payload works correctly without syntax errors. This technique is commonly known as "comment termination."

In Microsoft SQL Server (MSSQL), you can use the following methods to comment out the rest of a query:

| Comment Type         | Syntax    | Description                       |
| -------------------- | --------- | --------------------------------- |
| Single-line comment  | `--`      | Requires a space after the dashes |
| Inline/block comment | `/*...*/` | Can span multiple lines           |
| Batch separator      | `;`       | Terminates the current statement  |
| Nullbyte             | `;%00`    | Null byte terminates the query    |

### Examples

```sql
-- Example 1: Using -- to comment out the rest of the query
SELECT * FROM Users WHERE username = 'admin'-- ' AND password = 'password'

-- Example 2: Using /* */ for inline commenting
SELECT * FROM Users WHERE username = 'admin'/* ' AND password = 'password' */

-- Example 3: Using ; to terminate and start a new query
SELECT * FROM Users WHERE username = 'admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
```

### Notes

1. MSSQL requires a space or new line after the `--` comment syntax.
2. In some cases, MSSQL ignores comment syntax in strings, so ensure that your injection point has proper quoting.
3. Using the `;` batch separator can be particularly powerful as it allows execution of additional SQL statements.
4. When using batch separators, be aware that permissions and error handling may differ from the original query.
