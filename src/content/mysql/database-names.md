---
title: Database Names
description: How to extract database names from MySQL
category: Information Gathering
order: 6
tags: ["schema", "database names"]
lastUpdated: 2025-03-15
---

## Database Names

Extracting database names is often a crucial step in SQL injection attacks, as it helps to identify potential targets for further exploitation.

| Information | Query                                     |
| ----------- | ----------------------------------------- |
| Tables      | `information_schema.schemata`, `mysql.db` |
| Columns     | `schema_name`, `db`                       |
| Current DB  | `database()`, `schema()`                  |

### Examples

```sql
-- Get current database name
SELECT database();

-- List all databases on the server
SELECT schema_name FROM information_schema.schemata;

-- Alternative method (requires privileges)
SELECT DISTINCT(db) FROM mysql.db;
```

The `information_schema` database is available from MySQL version 5 and higher, and provides metadata about all databases on the server. Access to the `mysql.db` table typically requires elevated privileges.
