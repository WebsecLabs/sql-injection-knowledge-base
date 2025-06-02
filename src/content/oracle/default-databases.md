---
title: Default Databases
description: Information about Oracle's default database systems
category: Basics
order: 1
tags: ["basics", "database structure"]
lastUpdated: 2025-03-16
---

Oracle uses the concept of schemas rather than separate databases, but there are several important default schemas:

| Schema | Description |
|--------|-------------|
| `SYSTEM` | Internal system database |
| `SYSAUX` | Auxiliary system database |

These schemas contain valuable information about the database structure and can be targeted during SQL injection attacks.
