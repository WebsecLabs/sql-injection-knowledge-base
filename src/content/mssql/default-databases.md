---
title: Default Databases
description: Information about MSSQL's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2026-10-08
---

MSSQL comes with several default databases that can be useful during SQL injection attacks.

| Database              | Description                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------- |
| `master`              | System-level metadata and configuration: logins, databases, linked servers; commonly targeted |
| `model`               | Template for new databases                                                                    |
| `msdb`                | SQL Server Agent jobs, backup history, Database Mail, SSIS packages                           |
| `tempdb`              | Temporary objects, recreated at every restart                                                 |
| `mssqlsystemresource` | Resource database (2005+, ID 32767): read-only system objects; hidden from `sys.databases`    |
| `pubs`                | Sample database installed by default up to SQL Server 2000, not from 2005 on                  |
| `northwind`           | Sample database installed by default up to SQL Server 2000, not from 2005 on                  |

`INFORMATION_SCHEMA` is not a database: it is a schema of ANSI views present in every database, describing that database only (for example `SELECT table_name FROM information_schema.tables`).

The `master` database contains system-level information, making it especially valuable during SQL injection. Database IDs 1 to 4 are always `master`, `tempdb`, `model` and `msdb`, so `DB_NAME(1)` returns `master` without needing quotes.
