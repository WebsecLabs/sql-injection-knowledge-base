---
title: Password Hashing
description: Understanding password hashing mechanisms in Microsoft SQL Server
category: Authentication
order: 17
tags: ["password hashing", "authentication", "security"]
lastUpdated: 2025-03-15
---

## Password Hashing

Microsoft SQL Server uses various password hashing algorithms depending on the version and authentication method. Understanding these mechanisms is important for security assessment and potential password cracking during penetration testing.

### SQL Server Authentication Types

SQL Server supports two primary authentication modes:

1. **Windows Authentication**: Uses Windows credentials, no passwords stored in SQL Server
2. **SQL Server Authentication**: Uses username/password stored within SQL Server

### Password Storage Evolution

Password storage in SQL Server has evolved over time:

| SQL Server Version | Hashing Algorithm | Description |
|-------------------|-------------------|-------------|
| SQL Server 2000 and earlier | Proprietary algorithm | Weak, reversible in some cases |
| SQL Server 2005 | SHA-1 | 160-bit SHA-1 hash with salt |
| SQL Server 2012+ | SHA-512 | Stronger algorithm with salt |
| SQL Server 2017+ | Additional encryption | Password encryption at rest |
| Azure SQL | SHA-256 or bcrypt | Cloud-specific implementations |

### SQL Server Password Hash Locations

SQL Server stores password hashes in several system tables:

```sql
-- Main location for SQL Server logins (2005+)
SELECT name, password_hash FROM sys.sql_logins;

-- Older SQL Server versions (2000)
SELECT name, password FROM sysxlogins;

-- Master database storage (SQL Server 2000 and earlier)
SELECT name, password FROM master.dbo.syslogins;
```

### Password Hash Format

SQL Server password hashes have specific formats:

#### SQL Server 2000 and Earlier

```
0x0100[16-byte hash]
```

Example: `0x0100B58E58130D2B6FF57F70737D3978`

#### SQL Server 2005 and Later

```
0x0200[SHA-1 hash of salt+password][salt]
```

Example: `0x020058CD420B993C1C32561C772608D549FCEDFA66C8B733C3270DD8D3D32385D6580A6D367B`

The format consists of:
- `0x0200`: Version identifier
- First 20 bytes: SHA-1 hash of (password + salt)
- Remaining bytes: The salt value

### SQL Server 2012+ Format

```
0x0200[SHA-512 hash][salt]
```

The salt is typically 32 bytes, and the resulting hash is significantly longer.

### Extracting Password Hashes

With appropriate permissions, password hashes can be extracted:

```sql
-- Basic extraction with sysadmin privileges
SELECT name, password_hash FROM sys.sql_logins;

-- Using CAST for readability
SELECT name, CAST(password_hash AS varbinary(256)) FROM sys.sql_logins;

-- Converting to hex string
SELECT name, CONVERT(varchar(max), password_hash, 2) FROM sys.sql_logins;
```

### SQL Server Authentication Process

When a user attempts to log in:

1. Client sends the username and password
2. SQL Server retrieves the stored salt for that user
3. Computes the hash using the provided password and stored salt
4. Compares the computed hash with the stored hash
5. Grants access if they match

### Password Policy Enforcement

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

### SQL Server Password Salting

SQL Server uses salting to prevent dictionary and rainbow table attacks:

1. Each password gets a unique salt
2. The salt is stored with the password hash
3. Even identical passwords produce different hash values

Example of how salting works:
```
User1: Password "Password123" + Salt "ABCDEF" = Hash1
User2: Password "Password123" + Salt "XYZABC" = Hash2
```

Even though both users have the same password, the stored hashes are different.

### Practical SQL Injection Examples

If you have SQL injection access to a database, you might be able to extract hashes:

```sql
-- UNION attack to extract hashes
' UNION SELECT name, CAST(password_hash AS nvarchar(max)), NULL FROM sys.sql_logins--

-- Error-based extraction
' AND 1=CONVERT(int, (SELECT TOP 1 name + ':' + CAST(password_hash AS nvarchar(max)) FROM sys.sql_logins))--

-- Blind extraction
' AND ASCII(SUBSTRING((SELECT TOP 1 CAST(password_hash AS nvarchar(max)) FROM sys.sql_logins), 1, 1)) > 65--
```

### Detecting Weak Password Implementations

Some signs of weak password storage:

1. No CHECK_POLICY enforcement
2. Using SQL Server 2000 or earlier hashing algorithms
3. Using third-party applications with custom authentication that may store passwords insecurely

To check password policy enforcement:

```sql
-- Check which logins don't have password policies enforced
SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0;
```

### Password Storage Best Practices

To secure SQL Server passwords:

1. Use Windows Authentication when possible to avoid storing passwords in SQL Server
2. Enable CHECK_POLICY and CHECK_EXPIRATION for all SQL logins
3. Use strong password complexity requirements
4. Use service account group managed service accounts (gMSA) for application connections
5. Implement Always Encrypted for sensitive data
6. Use the latest SQL Server version with stronger hashing algorithms
7. Regularly audit for weak password configurations

```sql
-- Setting strong password policies
CREATE LOGIN SecureUser WITH PASSWORD = 'C0mpl3xP@$$w0rd!',
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON,
    DEFAULT_DATABASE = master;
```

### Mitigations Against Hash Theft

To protect against password hash theft:

1. Use least privilege principles for database access
2. Restrict access to system tables and views
3. Implement transparent data encryption (TDE)
4. Use Extended Events to audit access to sys.sql_logins
5. Implement endpoint protection for the SQL Server machine
6. Use SQL Server Audit to monitor security-related events

```sql
-- Create audit to track access to login information
CREATE SERVER AUDIT SecurityAudit TO FILE (FILEPATH = 'C:\Audits\');

CREATE DATABASE AUDIT SPECIFICATION LoginAudit
FOR SERVER AUDIT SecurityAudit
ADD (SELECT ON sys.sql_logins BY public);

ALTER SERVER AUDIT SecurityAudit WITH (STATE = ON);
ALTER DATABASE AUDIT SPECIFICATION LoginAudit WITH (STATE = ON);
```
