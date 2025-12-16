---
title: Oracle Intro
description: Overview of Oracle SQL injection techniques and categories
category: Basics
order: 1
tags: ["introduction", "overview", "oracle"]
lastUpdated: 2025-12-16
---

This section provides a comprehensive collection of SQL injection techniques specific to Oracle databases.

## Oracle Syntax Specifics

Unlike MySQL or PostgreSQL, Oracle has strict requirements for SELECT statements:

1. **FROM Clause is Mandatory**: Every `SELECT` statement must have a `FROM` clause.
2. **DUAL Table**: Use the `dual` dummy table when you need to select literals or call functions without a real table (e.g., `SELECT 'A' FROM dual`).
3. **Concatenation**: Use `||` for string concatenation (e.g., `'A'||'B'`), not `+` (SQL Server) or space (MySQL).

The techniques are organized into the following categories:

## Basics

Fundamental concepts and techniques for Oracle injection:

- [**Default Databases**](/oracle/default-databases) - Understanding and targeting Oracle's default schemas and tablespaces
- [**Comment Out Query**](/oracle/comment-out-query) - Using Oracle comment syntax to modify queries
- [**Testing Version**](/oracle/testing-version) - Methods to determine Oracle database version

## Information Gathering

Techniques to extract information from Oracle databases:

- [**Database Names**](/oracle/database-names) - Retrieving available database names and schemas
- [**Server Hostname**](/oracle/server-hostname) - Obtaining the Oracle server hostname
- [**Tables and Columns**](/oracle/tables-and-columns) - Discovering table and column names
- [**Database Credentials**](/oracle/database-credentials) - Techniques to extract Oracle credentials

## Injection Techniques

Advanced methods for exploiting Oracle injection vulnerabilities:

- [**Avoiding Quotations**](/oracle/avoiding-quotations) - Bypassing quote filters in Oracle
- [**String Concatenation**](/oracle/string-concatenation) - Techniques to concatenate strings in Oracle
- [**Conditional Statements**](/oracle/conditional-statements) - Using CASE, DECODE, and other conditional expressions
- [**Timing**](/oracle/timing) - Time-based blind injection using Oracle-specific functions

## Advanced Techniques

Sophisticated attacks for extracting data and gaining system access:

- [**Privileges**](/oracle/privileges) - Determining and exploiting user privileges
- [**Out-of-Band Channeling**](/oracle/out-of-band-channeling) - Extracting data using Oracle's network capabilities
- [**Password Cracking**](/oracle/password-cracking) - Techniques to recover passwords from Oracle hashes

Browse the techniques using the sidebar navigation or select a specific category to explore.
