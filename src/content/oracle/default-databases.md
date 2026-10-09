---
title: Default Databases
description: Information about Oracle's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2026-10-08
---

Oracle uses schemas (one per user) rather than separate databases. The important defaults are two schemas and two tablespaces that share similar names:

| Name     | Kind       | Description                                                  |
| -------- | ---------- | ------------------------------------------------------------ |
| `SYS`    | Schema     | Owns the data dictionary (`USER$`, `OBJ$`, the `DBA_` views) |
| `SYSTEM` | Schema     | Administrative account and tables                            |
| `SYSTEM` | Tablespace | Holds the data dictionary                                    |
| `SYSAUX` | Tablespace | Auxiliary system data (AWR, Oracle Text, Spatial and others) |

Since 12.1.0.2, `ALL_USERS.ORACLE_MAINTAINED` marks every schema Oracle created, which any user can query:

```sql
SELECT username FROM all_users WHERE oracle_maintained = 'Y';
```

See [Database Names](/oracle/database-names) for enumerating schemas through SQL injection.
