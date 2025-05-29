---
title: MSSQL Intro
description: Overview of Microsoft SQL Server SQL injection techniques and categories
category: Basics
order: 1
tags: ["introduction", "overview", "mssql", "sql server"]
lastUpdated: 2023-03-16
---

# Microsoft SQL Server Introduction

This section provides a comprehensive collection of SQL injection techniques specific to Microsoft SQL Server (MSSQL) databases. The techniques are organized into the following categories:

## Basics

Fundamental concepts and techniques for MSSQL injection:

- [**Default Databases**](/mssql/default-databases) - Understanding and targeting SQL Server's default databases
- [**Comment Out Query**](/mssql/comment-out-query) - Using SQL Server comment syntax to modify queries
- [**Testing Version**](/mssql/testing-version) - Methods to determine SQL Server version

## Information Gathering

Techniques to extract information from MSSQL databases:

- [**Database Names**](/mssql/database-names) - Retrieving available database names
- [**Server Hostname**](/mssql/server-hostname) - Obtaining the SQL Server hostname
- [**Tables and Columns**](/mssql/tables-and-columns) - Discovering table and column names
- [**Database Credentials**](/mssql/database-credentials) - Techniques to extract SQL Server credentials

## Injection Techniques

Advanced methods for exploiting MSSQL injection vulnerabilities:

- [**Avoiding Quotations**](/mssql/avoiding-quotations) - Bypassing quote filters in SQL Server
- [**String Concatenation**](/mssql/string-concatenation) - Techniques to concatenate strings in MSSQL
- [**Conditional Statements**](/mssql/conditional-statements) - Using IIF, CASE, and other conditional expressions
- [**Stacked Queries**](/mssql/stacked-queries) - Executing multiple statements in one injection
- [**Timing**](/mssql/timing) - Time-based blind injection methods
- [**Fuzzing/Obfuscation**](/mssql/fuzzing-obfuscation) - Techniques to bypass WAFs and filters

## Advanced Techniques

Sophisticated attacks for extracting data and gaining system access:

- [**System Command Execution**](/mssql/system-command-execution) - Using xp_cmdshell to run OS commands
- [**OPENROWSET Attacks**](/mssql/openrowset-attacks) - Leveraging OPENROWSET for remote connections
- [**Password Hashing**](/mssql/password-hashing) - Understanding and exploiting SQL Server password storage
- [**Password Cracking**](/mssql/password-cracking) - Techniques to recover passwords from hashes
- [**SP_PASSWORD Parameter**](/mssql/sp-password) - Using sp_password to hide queries from logs

Browse the techniques using the sidebar navigation or select a specific category to explore.