---
title: Default Databases
description: Information about MSSQL's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2023-03-16
---

MSSQL comes with several default databases that can be useful during SQL injection attacks.

| Database | Description |
|----------|-------------|
| `master` | Primary system database |
| `model` | Template for new databases |
| `msdb` | SQL Server Agent |
| `tempdb` | Temporary objects |

The `master` database contains system-level information, making it especially valuable during SQL injection.