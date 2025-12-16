---
title: PostgreSQL Intro
description: Overview of PostgreSQL SQL injection techniques and categories
category: Basics
order: 1
tags: ["introduction", "overview", "postgresql"]
lastUpdated: 2025-12-16
---

This section provides a comprehensive collection of SQL injection techniques specific to PostgreSQL databases. The techniques are organized into the following categories:

## Basics

Fundamental concepts and techniques for PostgreSQL injection:

- [**Comment Out Query**](/postgresql/comment-out-query) - Using PostgreSQL comment syntax to modify queries
- [**Testing Injection**](/postgresql/testing-injection) - Methods to verify if a PostgreSQL injection point exists
- [**Default Databases**](/postgresql/default-databases) - Understanding PostgreSQL's default databases and schemas

## Information Gathering

Techniques to extract information from PostgreSQL databases:

- [**Testing Version**](/postgresql/testing-version) - Methods to determine PostgreSQL version
- [**Database Names**](/postgresql/database-names) - Retrieving available database names
- [**Server Hostname**](/postgresql/server-hostname) - Obtaining the PostgreSQL server hostname and IP
- [**Tables and Columns**](/postgresql/tables-and-columns) - Discovering table and column names
- [**Database Credentials**](/postgresql/database-credentials) - Techniques to extract PostgreSQL credentials

## Injection Techniques

Advanced methods for exploiting PostgreSQL injection vulnerabilities:

- [**Avoiding Quotations**](/postgresql/avoiding-quotations) - Bypassing quote filters
- [**String Concatenation**](/postgresql/string-concatenation) - Techniques to concatenate strings in PostgreSQL
- [**Conditional Statements**](/postgresql/conditional-statements) - Using CASE statements for advanced injections
- [**Stacked Queries**](/postgresql/stacked-queries) - Executing multiple statements in one injection
- [**Timing**](/postgresql/timing) - Time-based blind injection methods

## Advanced Techniques

Sophisticated attacks for extracting data and gaining system access:

- [**Privileges**](/postgresql/privileges) - Determining and exploiting user privileges
- [**Reading Files**](/postgresql/reading-files) - Techniques to read files from the server filesystem
- [**Writing Files**](/postgresql/writing-files) - Methods to write files to the server
- [**Command Execution**](/postgresql/command-execution) - Executing operating system commands
- [**Password Hashing**](/postgresql/password-hashing) - Understanding PostgreSQL password storage
- [**Password Cracking**](/postgresql/password-cracking) - Techniques to recover passwords from hashes

Browse the techniques using the sidebar navigation or select a specific category to explore.
