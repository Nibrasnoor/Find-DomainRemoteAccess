Find-RDPaccess

A PowerShell tool for enumerating local group memberships on Active Directory computers using PowerView. It identifies potential local administrator, Remote Desktop Protocol (RDP), and Windows Remote Management (WinRM) access for the current user.

The script also supports optional RDP port reachability and WinRM remote command execution tests.

Features

* Enumerates local group memberships on Active Directory computers.
* Checks the following local groups:
    * Administrators
    * Remote Desktop Users
    * Remote Management Users
* Displays Local Group Name and MemberName for matching entries.
* Matches the current user SID and group SIDs in the current Windows token.
* Checks the domain’s Domain Users SID.
* Displays only computers with at least one matching group membership.
* Optionally tests TCP port 3389 reachability for RDP.
* Optionally tests WinRM remote command execution.
* Supports filtering by computer name, AD search base, servers, and workstations.
* Processes computers sequentially and displays results after the requested checks finish.

Repository Structure

Find-RDPaccess/
├── README.md
└── Find-RDPaccess.ps1

Requirements

* Windows PowerShell.
* An Active Directory environment.
* The ActiveDirectory PowerShell module.
* PowerView loaded into the current PowerShell session.
* Appropriate permissions and network connectivity for remote enumeration.
* For WinRM testing, a working WinRM configuration and sufficient permissions to execute remote commands.

Installation

1. Clone the Repository

git clone <YOUR-REPOSITORY-URL>
cd Find-RDPaccess

Alternatively, download Find-RDPaccess.ps1 directly from the repository.

2. Import the Required Modules

Import the ActiveDirectory module:

Import-Module ActiveDirectory

Import PowerView from your local path:

. .\PowerView.ps1

Replace .\PowerView.ps1 with the actual path to your PowerView script.

3. Run the Script

.\Find-RDPaccess.ps1

Usage

1. Basic Enumeration

Enumerate domain computers and identify matching local group memberships.

.\Find-RDPaccess.ps1

Connection tests are not performed unless -TestConnection is specified.

2. Test RDP and WinRM Connectivity

.\Find-RDPaccess.ps1 -TestConnection

This runs the following checks on computers with matching group memberships:

Test	Method	Purpose
RDP Connection	TCP port 3389 check	Determines whether the RDP port is reachable
WinRM Connection	Remote PowerShell command	Determines whether remote command execution succeeds

Note: The RDP test checks port reachability only. It does not attempt authentication or establish an interactive RDP session.

3. Enumerate a Specific Computer

.\Find-RDPaccess.ps1 -ComputerName ACADEMY-EA-MS01

4. Enumerate a Specific Computer and Test Connectivity

.\Find-RDPaccess.ps1 -ComputerName ACADEMY-EA-MS01 -TestConnection

5. Enumerate Multiple Computers

.\Find-RDPaccess.ps1 -ComputerName ACADEMY-EA-MS01,ACADEMY-EA-DC01

6. Enumerate Servers Only

.\Find-RDPaccess.ps1 -ServersOnly

7. Enumerate Workstations Only

.\Find-RDPaccess.ps1 -WorkstationsOnly

8. Specify an Active Directory Search Base

.\Find-RDPaccess.ps1 -SearchBase "OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL"

Replace the example distinguished name with the OU or container you want to search.

9. Combine Parameters

Enumerate workstations and test connectivity:

.\Find-RDPaccess.ps1 -WorkstationsOnly -TestConnection

Target a specific computer and test connectivity:

.\Find-RDPaccess.ps1 -ComputerName ACADEMY-EA-MS01 -TestConnection

Example Output

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

The output above is illustrative. Actual results depend on the target environment, group memberships, permissions, and network configuration.

Output Fields

Field	Description
Target Computer	Computer being enumerated
Current User	Identity running the script
Local Group Name	Local group containing the enumerated principal
MemberName	User or group returned by PowerView
Match Reason	Reason the principal matched the current user’s identity or token
Interpretation	Potential access associated with the local group
LocalAdmin	Whether a matching principal was found in Administrators
RDP Group	Whether a matching principal was found in Remote Desktop Users
RDP Connection	Whether TCP port 3389 is reachable, or Not tested
WinRM Group	Whether a matching principal was found in Remote Management Users
WinRM Connection	Whether the remote PowerShell command succeeded, or Not tested

Understanding the Results

LocalAdmin

Yes indicates that a matching principal was found in the target’s local Administrators group.

RDP Group

Yes indicates that a matching principal was found in the target’s local Remote Desktop Users group.

RDP Connection

* Yes: TCP port 3389 is reachable.
* No: The port check did not succeed.
* Not tested: The -TestConnection parameter was not specified.

WinRM Group

Yes indicates that a matching principal was found in the target’s local Remote Management Users group.

WinRM Connection

* Yes: The remote PowerShell command succeeded.
* No: The remote command failed.
* Not tested: The -TestConnection parameter was not specified.

Important Limitations

* Group membership does not guarantee effective access. Actual access depends on permissions, policies, firewall rules, authentication, and other security controls.
* RDP testing checks port reachability only. It does not verify credentials or confirm that an RDP session can be established.
* WinRM testing attempts remote command execution. Failure may indicate connectivity, authentication, authorization, or configuration issues.
* Nested group membership is not fully resolved. The script checks the current user’s SID, group SIDs in the current Windows token, and the domain’s Domain Users SID. Other indirect memberships may not be identified.
* Enumeration errors can produce incomplete results. A group that cannot be enumerated may not appear in the output.
* Operating-system filters depend on Active Directory attributes. Missing or inaccurate OperatingSystem values can affect server and workstation filtering.

Disclaimer

This tool is intended for authorized security assessments, Active Directory administration, penetration-testing labs, and educational use.

Only run it against systems you own or have explicit permission to assess.

License

Add an appropriate open-source license before distributing or reusing this project.
