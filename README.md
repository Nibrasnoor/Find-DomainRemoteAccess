Find-DomainRemoteAccess

A PowerShell script for authorized Active Directory security assessments. It enumerates domain computers and checks selected local groups to identify potential Remote Desktop Protocol (RDP), local administrator, and Windows Remote Management (WinRM) access.

Features

* Enumerates computers in Active Directory.
* Checks the local Remote Desktop Users group for potential RDP access.
* Checks the local Administrators group for potential administrative access.
* Checks the local Remote Management Users group for potential WinRM access.
* Identifies matching entries associated with the current user, current token groups, and the Domain Users group.
* Tests whether the current account can execute a PowerShell command remotely through WinRM.
* Supports filtering by servers, workstations, or a specified Active Directory OU.
* Displays results in a readable PowerShell table.

Requirements

* Windows PowerShell.
* An Active Directory environment.
* The Active Directory PowerShell module.
* PowerView loaded, with Get-NetLocalGroupMember available.
* Appropriate permissions to enumerate target computers and their local group memberships.

Usage

First, load PowerView:

Import-Module .\PowerView.ps1

Run the script:

.\Find-DomainRemoteAccess.ps1

Check workstations only

.\Find-DomainRemoteAccess.ps1 -WorkstationsOnly

Check servers only

.\Find-DomainRemoteAccess.ps1 -ServersOnly

Search a specific OU

.\Find-DomainRemoteAccess.ps1 -SearchBase "OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL"

Replace the example distinguished name with an OU in your own environment.

Output

Field	Description
User	Account running the script
ComputerName	Target computer
LocalGroup	Local group being enumerated
MatchingPrincipal	Matching user or group entry
MatchType	Reason the entry matched
WinRM	Whether the current account successfully executed a remote PowerShell command

Local groups checked

Group	Purpose
Remote Desktop Users	Identifies potential RDP access
Administrators	Identifies potential local administrative access
Remote Management Users	Identifies potential WinRM access

Limitations

* Group membership indicates potential access; it does not guarantee effective RDP or administrative access.
* The WinRM check tests the current account, not every user or group discovered.
* The script does not fully resolve arbitrary nested Active Directory groups or calculate all effective permission paths.
* Results depend on network connectivity, target configuration, and the permissions of the account running the script.

Authorized Use

Use this script only in environments you own or are explicitly authorized to assess. Follow applicable rules of engagement and organizational security policies.

License

No license has been specified. Add a LICENSE file if you want to grant others explicit permission to use, modify, and redistribute this project.
