---
title: Server MAC Address
description: Techniques to retrieve server hardware information in PostgreSQL
category: Information Gathering
order: 8
tags: ["MAC address", "hardware information", "network"]
lastUpdated: 2025-12-16
---

## Server MAC Address

Unlike MySQL, PostgreSQL does not expose the server's MAC address through the `UUID()` function. PostgreSQL uses different UUID generation methods that don't include hardware identifiers by default.

### PostgreSQL UUID Generation

PostgreSQL's UUID functions (when available) use random generation rather than MAC-based:

```sql
-- Generate random UUID (requires uuid-ossp or pgcrypto extension)
SELECT gen_random_uuid();  -- pgcrypto (PostgreSQL 13+)
SELECT uuid_generate_v4(); -- uuid-ossp extension (random)
```

### Alternative Hardware Information

While direct MAC address retrieval isn't available through SQL, other server information can be obtained:

#### Network Information

```sql
-- Server's listening address
SELECT inet_server_addr();

-- Server's listening port
SELECT inet_server_port();

-- Client's address
SELECT inet_client_addr();

-- Client's port
SELECT inet_client_port();
```

#### Server Identification

```sql
-- Server hostname (if resolvable)
SELECT current_setting('listen_addresses');

-- Check for unix socket path
SELECT current_setting('unix_socket_directories');

-- Server version
SELECT version();

-- PostgreSQL-specific system identifier (no special privileges required)
SELECT system_identifier FROM pg_control_system();
```

### File-Based MAC Address Retrieval

If file reading privileges exist, MAC addresses can be read from system files:

```sql
-- Linux: Read from /sys filesystem (requires pg_read_file privilege)
SELECT pg_read_file('/sys/class/net/eth0/address');

-- Alternative using large objects
SELECT lo_import('/sys/class/net/eth0/address');
-- Returns OID (e.g., 12345)
SELECT convert_from(lo_get(12345), 'UTF8');  -- Replace 12345 with actual OID
```

### Command Execution Methods

With appropriate privileges, system commands can retrieve MAC addresses:

```sql
-- Using COPY TO PROGRAM (requires superuser or pg_execute_server_program)
CREATE TEMP TABLE mac_output (line TEXT);
COPY mac_output FROM PROGRAM 'cat /sys/class/net/eth0/address';
SELECT * FROM mac_output;

-- Alternative: ip command
COPY mac_output FROM PROGRAM 'ip link show eth0';
```

### Using PL/Python (if available)

```sql
-- If PL/Python extension is installed
CREATE OR REPLACE FUNCTION get_mac() RETURNS TEXT AS $$
import subprocess
result = subprocess.run(['cat', '/sys/class/net/eth0/address'], capture_output=True, text=True, timeout=5)
return result.stdout.strip()
$$ LANGUAGE plpython3u;

SELECT get_mac();
```

### Network Interface Discovery

Before retrieving MAC addresses, discover available interfaces:

```sql
-- List network interfaces via /sys (use COPY FROM PROGRAM to capture output)
CREATE TEMP TABLE net_interfaces (name TEXT);
COPY net_interfaces FROM PROGRAM 'ls /sys/class/net/';
SELECT * FROM net_interfaces;

-- Or via ip command
COPY net_interfaces FROM PROGRAM 'ip -o link show | cut -d: -f2';
SELECT * FROM net_interfaces;
```

**Note:** `COPY TO PROGRAM` executes a command but discards its output. Use `COPY FROM PROGRAM` to capture command output into a table.

### Windows-Specific Methods

On Windows servers, use PowerShell via `COPY FROM PROGRAM`:

```sql
-- Get MAC address using PowerShell (requires superuser or pg_execute_server_program)
CREATE TEMP TABLE mac_output (line TEXT);
COPY mac_output FROM PROGRAM 'powershell -Command "Get-NetAdapter | Select-Object -First 1 -ExpandProperty MacAddress"';
SELECT * FROM mac_output;

-- List all adapters with their MAC addresses
COPY mac_output FROM PROGRAM 'powershell -Command "Get-NetAdapter | Select-Object Name, MacAddress | ConvertTo-Csv -NoTypeInformation"';
SELECT * FROM mac_output;
```

### Limitations

1. **No direct SQL function**: PostgreSQL doesn't expose MAC addresses through built-in functions
2. **Privilege requirements**: File reading or command execution requires elevated privileges
3. **Platform dependent**:
   - Linux: `/sys/class/net/` or `ip link` command
   - BSD: `/dev` or `sysctl`/`ifconfig` commands
   - macOS: `ifconfig` command
   - Windows: `Get-NetAdapter` PowerShell cmdlet (see example above)
4. **Network configuration**: Docker containers and VMs may have virtual/different MAC addresses
5. **Extension requirements**: Some methods require extensions like `plpython3u`

### Comparison with MySQL

| Feature              | MySQL                       | PostgreSQL                                                           |
| -------------------- | --------------------------- | -------------------------------------------------------------------- |
| UUID with MAC        | `UUID()` (older versions)   | Not available                                                        |
| Random UUID          | `UUID()` (newer versions)   | `gen_random_uuid()`                                                  |
| Direct MAC function  | Partial (version dependent) | Not available                                                        |
| File-based retrieval | `LOAD_FILE()`               | `pg_read_file()`                                                     |
| Command execution    | N/A                         | `COPY FROM PROGRAM` (capture output) / `COPY TO PROGRAM` (send data) |

### Security Considerations

MAC addresses can be useful for:

- Server fingerprinting
- Identifying physical or virtual infrastructure
- Tracking across multiple databases on same hardware

Organizations should:

- Restrict file reading privileges
- Disable `COPY FROM/TO PROGRAM` for non-admin users
- Consider using MAC address randomization on sensitive systems
- Monitor for unusual file access patterns
