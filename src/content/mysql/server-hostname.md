---
title: Server Hostname
description: How to retrieve the server hostname in MySQL
category: Information Gathering
order: 7
tags: ["hostname", "server information"]
lastUpdated: 2025-03-15
---

## Server Hostname

Retrieving the server hostname can provide useful information about the target environment during SQL injection testing. This information can be especially helpful for lateral movement or identifying the specific server in a network.

In MySQL, you can retrieve the server hostname using:

```sql
@@HOSTNAME
```

### Example

```sql
SELECT @@hostname;
```

This will return the hostname of the server where the MySQL database is running. This information can be valuable for reconnaissance and for understanding the server's environment.
