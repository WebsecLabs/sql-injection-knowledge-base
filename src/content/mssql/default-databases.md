---
title: Default Databases
description: Information about MSSQL's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2025-03-16
---

MSSQL comes with several default databases that can be useful during SQL injection attacks.

| Database             | Description                                                         |
| -------------------- | ------------------------------------------------------------------- |
| `master`             | System-level metadata and configuration — commonly targeted in SQLi |
| `pubs`               | Legacy sample database (manual install, rarely on production)       |
| `model`              | Template for new databases                                          |
| `msdb`               | SQL Server Agent                                                    |
| `tempdb`             | Temporary objects                                                   |
| `northwind`          | Legacy sample database (manual install, rarely on production)       |
| `information_schema` | ANSI standard metadata (MSSQL 2000+)                                |

The `master` database contains system-level information, making it especially valuable during SQL injection.
