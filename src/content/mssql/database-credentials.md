---
title: Database Credentials
description: How to extract database credentials from Microsoft SQL Server
category: Information Gathering
order: 4
tags: ["credentials", "authentication", "user data"]
lastUpdated: 2025-03-15
---

## Database Credentials

Extracting database credentials from Microsoft SQL Server can provide valuable information for lateral movement and privilege escalation during penetration testing.

### System Tables with Credential Information

| Information       | Tables/Views                                                      |
| ----------------- | ----------------------------------------------------------------- |
| SQL Server Logins | `sys.server_principals`, `sys.sql_logins`, `master.sys.syslogins` |
| SQL Server Roles  | `sys.server_role_members`                                         |
| Database Users    | `sys.database_principals`                                         |
| Database Roles    | `sys.database_role_members`                                       |
| Current User      | `USER_NAME()`, `CURRENT_USER`, `SYSTEM_USER`, `SUSER_NAME()`      |
| Current Login     | `SUSER_SNAME()`                                                   |

### Examples

#### Retrieving Current Identity Information

```sql
-- Get the current user context
SELECT USER_NAME();       -- Database user
SELECT CURRENT_USER;      -- Current database user context
SELECT SYSTEM_USER;       -- Current login
SELECT SUSER_NAME();      -- Current login with server access
SELECT USER;              -- Shorthand for USER_NAME()
SELECT SESSION_USER;      -- Current session user
```

#### Retrieving SQL Server Login Information

```sql
-- Get SQL Server logins (requires high privileges)
SELECT name, password_hash FROM sys.sql_logins;

-- More detailed login information
SELECT sp.name AS login,
       sp.type_desc AS login_type,
       sl.password_hash,
       sp.create_date,
       sp.modify_date,
       CASE WHEN sl.is_policy_checked = 1 THEN 'Yes' ELSE 'No' END AS is_policy_checked,
       CASE WHEN sl.is_expiration_checked = 1 THEN 'Yes' ELSE 'No' END AS is_expiration_checked
FROM sys.server_principals sp
LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
WHERE sp.type NOT IN ('G', 'R')
ORDER BY sp.name;
```

#### Retrieving Role Memberships

```sql
-- Get server role memberships
SELECT
    r.name AS role_name,
    m.name AS member_name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
ORDER BY r.name, m.name;

-- Get database role memberships
SELECT
    r.name AS role_name,
    m.name AS member_name
FROM sys.database_role_members rm
JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id
WHERE r.type = 'R'
ORDER BY r.name, m.name;
```

### Notes

1. Access to credential information typically requires high privileges (sysadmin or similar).
2. In newer versions of SQL Server (2012+), password hashes are stored in `sys.sql_logins` rather than directly in `master.dbo.syslogins`.
3. Password hashes in SQL Server are salted and difficult to crack without specialized tools.
4. SQL Server 2005 and later use a stronger hashing algorithm (SHA-1) compared to earlier versions.
