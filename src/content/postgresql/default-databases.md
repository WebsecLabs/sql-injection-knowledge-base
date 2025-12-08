---
title: Default Databases
description: Information about PostgreSQL's default database systems
category: Basics
order: 2
tags: ["basics", "database structure"]
lastUpdated: 2025-12-07
---

PostgreSQL comes with several default databases and schemas that can be useful during SQL injection attacks.

## Default Databases

| Database    | Description                                    |
| ----------- | ---------------------------------------------- |
| `postgres`  | Default administrative database, always exists |
| `template0` | Clean template database, cannot be modified    |
| `template1` | Template database used to create new databases |

## Important Schemas

| Schema               | Description                                                    |
| -------------------- | -------------------------------------------------------------- |
| `pg_catalog`         | System catalog containing metadata about all database objects  |
| `information_schema` | SQL-standard views for database metadata (portable across DBs) |
| `public`             | Default schema where user objects are created                  |

## Key System Tables

| Table/View                   | Description                         |
| ---------------------------- | ----------------------------------- |
| `pg_database`                | List of all databases               |
| `pg_user`                    | Database users                      |
| `pg_shadow`                  | User passwords (requires superuser) |
| `pg_tables`                  | All tables in the database          |
| `pg_catalog.pg_tables`       | System tables catalog               |
| `information_schema.tables`  | SQL-standard table listing          |
| `information_schema.columns` | SQL-standard column listing         |

The `information_schema` is portable across different database systems, while `pg_catalog` contains PostgreSQL-specific metadata and is often more detailed.
