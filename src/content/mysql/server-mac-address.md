---
title: Server MAC Address
description: How to retrieve the server MAC address in MySQL
category: Information Gathering
order: 8
tags: ["MAC address", "UUID", "hardware information"]
lastUpdated: 2025-03-15
---

## Server MAC Address

The Universally Unique Identifier (UUID) in MySQL is a 128-bit number where the last 12 digits are formed from the network interface's MAC address. This can be used to identify the physical hardware running the MySQL server.

```sql
UUID()
```

### Example Output

```text
aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

In this output, the last part `eeeeeeeeeeee` represents the MAC address of the server's network interface.

### Note

On some operating systems, MySQL may return a 48-bit random string instead of the actual MAC address for security reasons. This behavior depends on the specific MySQL version and operating system configuration.
