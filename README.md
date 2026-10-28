# Find-DomainRemoteAccess

A PowerShell tool for enumerating local group memberships on Active Directory computers using PowerView. It identifies potential local administrator, Remote Desktop Protocol (RDP), and Windows Remote Management (WinRM) access for the current user.

## Features

- Enumerates local group memberships on Active Directory computers.
- Checks `Administrators`, `Remote Desktop Users`, and `Remote Management Users`.
- Displays `Local Group Name` and `MemberName`.
- Matches the current user SID and group SIDs in the current Windows token.
- Checks the domain's `Domain Users` SID.
- Displays only computers with matching group memberships.
- Optionally tests RDP port 3389 reachability.
- Optionally tests WinRM remote command execution.
- Supports computer name, search base, server, and workstation filters.

## Requirements

- Windows PowerShell.
- Active Directory PowerShell module.
- PowerView loaded into the current PowerShell session.
- Appropriate permissions and network connectivity for remote enumeration.
- WinRM configured and accessible for WinRM testing.

## Installation

### 1. Clone the Repository

```powershell
git clone <REPO-URL>
cd Find-DomainRemoteAccess
```

### 2. Import the Required Modules

Import the Active Directory module:

```powershell
Import-Module ActiveDirectory
```

Import PowerView:

```powershell
. .\PowerView.ps1
```

Replace `.\PowerView.ps1` with the actual path to your PowerView script.

### 3. Run the Script

```powershell
.\Find-DomainRemoteAccess.ps1
```

## Usage

### Basic Enumeration

```powershell
.\Find-DomainRemoteAccess.ps1
```

### Test RDP and WinRM Connectivity

```powershell
.\Find-DomainRemoteAccess.ps1 -TestConnection
```

### Enumerate a Specific Computer

```powershell
.\Find-DomainRemoteAccess.ps1 -ComputerName ACADEMY-EA-MS01
```

### Enumerate a Specific Computer and Test Connectivity

```powershell
.\Find-DomainRemoteAccess.ps1 -ComputerName ACADEMY-EA-MS01 -TestConnection
```

### Enumerate Multiple Computers

```powershell
.\Find-DomainRemoteAccess.ps1 -ComputerName ACADEMY-EA-MS01,ACADEMY-EA-DC01
```

### Enumerate Servers Only

```powershell
.\Find-DomainRemoteAccess.ps1 -ServersOnly
```

### Enumerate Workstations Only

```powershell
.\Find-DomainRemoteAccess.ps1 -WorkstationsOnly
```

### Specify an Active Directory Search Base

```powershell
.\Find-DomainRemoteAccess.ps1 -SearchBase "OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL"
```

### Combine Parameters

```powershell
.\Find-DomainRemoteAccess.ps1 -WorkstationsOnly -TestConnection
```

## Example Output

```text
============================================================
Target Computer : ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL
Current User    : INLANEFREIGHT\htb-student
============================================================

Matching Group Memberships:

  Local Group Name : Administrators
  MemberName       : INLANEFREIGHT\Domain Users
  Match Reason     : Matched a group SID in the current Windows token
  Interpretation   : Potential local administrator access

  Local Group Name : Remote Desktop Users
  MemberName       : INLANEFREIGHT\Domain Users
  Match Reason     : Matched a group SID in the current Windows token
  Interpretation   : Potential Remote Desktop (RDP) access

LocalAdmin         : Yes
RDP Group          : Yes
RDP Connection     : Yes
WinRM Group        : No
WinRM Connection   : No
```

*Example output only. Actual results depend on the target environment.*

## Output Fields

| Field | Description |
|---|---|
| `Target Computer` | Computer being enumerated |
| `Current User` | Identity running the script |
| `Local Group Name` | Name of the local group being checked |
| `MemberName` | User or group returned by PowerView |
| `Match Reason` | Reason the principal matched the current user or token |
| `Interpretation` | Potential access associated with the group |
| `LocalAdmin` | Whether a matching principal was found in `Administrators` |
| `RDP Group` | Whether a matching principal was found in `Remote Desktop Users` |
| `RDP Connection` | Whether TCP port 3389 is reachable |
| `WinRM Group` | Whether a matching principal was found in `Remote Management Users` |
| `WinRM Connection` | Whether the remote PowerShell command succeeded |

## Connection Test Details

### RDP

The script checks TCP port 3389.

- `Yes`: The port is reachable.
- `No`: The port check failed.
- `Not tested`: `-TestConnection` was not specified.

**A reachable RDP port does not guarantee successful authentication or an interactive RDP session.**

### WinRM

The script attempts to execute a remote PowerShell command.

- `Yes`: The remote command succeeded.
- `No`: The remote command failed.
- `Not tested`: `-TestConnection` was not specified.

A failed test may indicate connectivity, authentication, authorization, or configuration problems.

## Limitations

- Group membership does not guarantee effective access.
- Nested Active Directory group membership is not fully resolved.
- Enumeration failures can result in incomplete results.
- Server and workstation filtering depends on the `OperatingSystem` attribute in Active Directory.
- RDP testing checks port reachability only; it does not attempt authentication.

## Disclaimer

This tool is intended for authorized security assessments, Active Directory administration, penetration-testing labs, and educational use.

Only use it against systems you own or have explicit permission to assess.
