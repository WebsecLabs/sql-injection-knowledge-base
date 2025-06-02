---
title: MySQL Intro
description: Overview of MySQL SQL injection techniques and categories
category: Basics
order: 1
tags: ["introduction", "overview", "mysql"]
lastUpdated: 2025-03-16
---

# MySQL Introduction

This section provides a comprehensive collection of SQL injection techniques specific to MySQL databases. The techniques are organized into the following categories:

## Basics

Fundamental concepts and techniques for MySQL injection:

- [**Comment Out Query**](/mysql/comment-out-query) - Using MySQL comment syntax to modify queries
- [**Testing Injection**](/mysql/testing-injection) - Methods to verify if a MySQL injection point exists
- [**Constants**](/mysql/constants) - Working with MySQL constants in injection scenarios
- [**Operators**](/mysql/operators) - Leveraging MySQL operators for injection
- [**Default Databases**](/mysql/default-databases) - Understanding and targeting MySQL's default databases

## Information Gathering

Techniques to extract information from MySQL databases:

- [**Testing Version**](/mysql/testing-version) - Methods to determine MySQL version
- [**Database Names**](/mysql/database-names) - Retrieving available database names
- [**Server Hostname**](/mysql/server-hostname) - Obtaining the MySQL server hostname
- [**Server MAC Address**](/mysql/server-mac-address) - Extracting MAC address information
- [**Tables and Columns**](/mysql/tables-and-columns) - Discovering table and column names
- [**Database Credentials**](/mysql/database-credentials) - Techniques to extract MySQL credentials

## Injection Techniques

Advanced methods for exploiting MySQL injection vulnerabilities:

- [**Avoiding Quotations**](/mysql/avoiding-quotations) - Bypassing quote filters
- [**String Concatenation**](/mysql/string-concatenation) - Techniques to concatenate strings in MySQL
- [**Conditional Statements**](/mysql/conditional-statements) - Using IF and CASE statements for advanced injections
- [**Stacked Queries**](/mysql/stacked-queries) - Executing multiple statements in one injection
- [**MySQL-Specific Code**](/mysql/mysql-specific-code) - Exploiting unique MySQL functions and features
- [**Timing**](/mysql/timing) - Time-based blind injection methods
- [**Fuzzing/Obfuscation**](/mysql/fuzzing-obfuscation) - Techniques to bypass WAFs and filters

## Advanced Techniques

Sophisticated attacks for extracting data and gaining system access:

- [**Privileges**](/mysql/privileges) - Determining and exploiting user privileges
- [**Reading Files**](/mysql/reading-files) - Techniques to read files from the server filesystem
- [**Writing Files**](/mysql/writing-files) - Methods to write files to the server
- [**Out-of-Band Channeling**](/mysql/out-of-band-channeling) - Extracting data via alternative channels
- [**Password Hashing**](/mysql/password-hashing) - Understanding and exploiting MySQL password storage
- [**Password Cracking**](/mysql/password-cracking) - Techniques to recover passwords from hashes

Browse the techniques using the sidebar navigation or select a specific category to explore.
