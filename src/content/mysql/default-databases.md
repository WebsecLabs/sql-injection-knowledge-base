---
title: Default Databases
description: Information about MySQL's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2025-03-15
---

MySQL comes with several default databases that can be useful during SQL injection attacks.

| Database             | Description                         |
| -------------------- | ----------------------------------- |
| `mysql`              | Requires root privileges            |
| `information_schema` | Available from version 5 and higher |

The `information_schema` database contains metadata about all databases and tables on the server, making it a valuable resource for an attacker who has gained access to it.
