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

| Information       | Tables/Views                                                          |
| ----------------- | --------------------------------------------------------------------- |
| SQL Server Logins | `sys.server_principals`, `sys.sql_logins` (2005+)                     |
| Legacy Logins     | `master..syslogins` (deprecated 2005+, compatibility view only)       |
| Legacy Processes  | `master..sysprocesses` (deprecated 2005+, use `sys.dm_exec_sessions`) |
| SQL Server Roles  | `sys.server_role_members`                                             |
| Database Users    | `sys.database_principals`                                             |
| Database Roles    | `sys.database_role_members`                                           |
| Current User      | `USER_NAME()`, `CURRENT_USER`, `SYSTEM_USER`, `SUSER_NAME()`          |
| Current Login     | `SUSER_SNAME()`                                                       |
| Role Check        | `IS_SRVROLEMEMBER('sysadmin')`                                        |

**Key columns by view:**

- `sys.sql_logins`: `name`, `password_hash`, `is_disabled`, `is_policy_checked`
- `sys.server_principals`: `name`, `type_desc`, `is_disabled`, `create_date`
- `master..syslogins` (legacy): `name`, `loginname`, `password` (returns hash in 2005–2017, NULL in 2019+)
- `master..sysprocesses` (legacy): `loginame`, `spid`, `dbid`

### Legacy Credential Retrieval

```sql
-- Get current login from process list (deprecated since 2005, use sys.dm_exec_sessions)
SELECT loginame FROM master..sysprocesses WHERE spid=@@SPID;
-- Modern equivalent:
-- SELECT login_name FROM sys.dm_exec_sessions WHERE session_id=@@SPID;

-- Check if current user is sysadmin (returns 1, 0, or NULL)
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Legacy table (undocumented, removed in SQL Server 2005)
-- SELECT name, password FROM master.dbo.sysxlogins;
```

**Note:** `sysxlogins` was an undocumented system table in SQL Server 2000 and earlier; it was removed in SQL Server 2005. For modern instances, use `sys.sql_logins` or `sys.server_principals`:

```sql
-- Modern alternative (SQL Server 2005+)
-- Requires VIEW SERVER STATE (2019-) or VIEW SERVER PERFORMANCE STATE (2022+)
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S', 'U');
SELECT name, is_disabled, is_policy_checked FROM sys.sql_logins;
```

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
2. `sys.sql_logins` replaced `master.dbo.syslogins` in SQL Server 2005. The legacy view still exists for compatibility but `password` column returns NULL.
3. Password hashes in SQL Server are salted and difficult to crack without specialized tools.
4. SQL Server 2005+ uses SHA-1 hashing. SQL Server 2012+ uses SHA-512. SQL Server 2022+ introduced VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION as a granular alternative to CONTROL SERVER for viewing `password_hash`.
