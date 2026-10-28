[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$SearchBase,
    [switch]$ServersOnly,
    [switch]$WorkstationsOnly,
    [switch]$TestConnection
)

# ------------------------------------------------------------
# Validate prerequisites
# ------------------------------------------------------------

if (-not (Get-Command Get-NetLocalGroupMember -ErrorAction SilentlyContinue)) {
    Write-Error "Get-NetLocalGroupMember was not found. Import PowerView before running this script."
    return
}

if (-not (Get-Command Get-ADComputer -ErrorAction SilentlyContinue)) {
    Write-Error "Get-ADComputer was not found. Import the ActiveDirectory module first."
    return
}

if ($ServersOnly -and $WorkstationsOnly) {
    Write-Error "Use either -ServersOnly or -WorkstationsOnly, not both."
    return
}

# ------------------------------------------------------------
# Get current user and token SIDs
# ------------------------------------------------------------

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentUser = $Identity.Name
$UserSID = $Identity.User.Value

$CurrentSIDs = @(
    $Identity.Groups | ForEach-Object {
        $_.Value
    }
)

# ------------------------------------------------------------
# Get the Domain Users SID
# ------------------------------------------------------------

$DomainUsersSID = $null

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainUsersSID = "$($Domain.DomainSID.Value)-513"
}
catch {
    Write-Warning "Could not determine the current domain's Domain Users SID."
}

# ------------------------------------------------------------
# Discover target computers
# ------------------------------------------------------------

$ADComputerParams = @{
    Filter      = '*'
    ErrorAction = 'Stop'
}

if ($SearchBase) {
    $ADComputerParams.SearchBase = $SearchBase
}

try {
    if ($ComputerName) {
        $Computers = foreach ($Name in $ComputerName) {
            try {
                Get-ADComputer -Identity $Name -Properties DNSHostName, OperatingSystem -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not find computer '$Name' in Active Directory."
            }
        }
    }
    else {
        $Computers = Get-ADComputer @ADComputerParams -Properties DNSHostName, OperatingSystem
    }
}
catch {
    Write-Error "Failed to enumerate computers from Active Directory: $($_.Exception.Message)"
    return
}

# ------------------------------------------------------------
# Apply optional operating-system filters
# ------------------------------------------------------------

if ($ServersOnly) {
    $Computers = $Computers | Where-Object {
        $_.OperatingSystem -match 'Server'
    }
}

if ($WorkstationsOnly) {
    $Computers = $Computers | Where-Object {
        $_.OperatingSystem -notmatch 'Server'
    }
}

if (-not $Computers) {
    Write-Warning "No matching computer objects were found."
    return
}

# ------------------------------------------------------------
# Local groups to enumerate
# ------------------------------------------------------------

$GroupsToCheck = @(
    [PSCustomObject]@{
        GroupName      = 'Administrators'
        ResultProperty = 'LocalAdmin'
        Description    = 'Potential local administrator access'
    },
    [PSCustomObject]@{
        GroupName      = 'Remote Desktop Users'
        ResultProperty = 'RDPGroup'
        Description    = 'Potential Remote Desktop (RDP) access'
    },
    [PSCustomObject]@{
        GroupName      = 'Remote Management Users'
        ResultProperty = 'WinRMGroup'
        Description    = 'Potential WinRM access'
    }
)

# ------------------------------------------------------------
# Enumerate each computer sequentially
# ------------------------------------------------------------

foreach ($Computer in $Computers) {

    $Target = if ($Computer.DNSHostName) {
        $Computer.DNSHostName
    }
    else {
        $Computer.Name
    }

    $Matches = @()
    $LocalAdmin = $false
    $RDPGroup = $false
    $WinRMGroup = $false

    # --------------------------------------------------------
    # Enumerate local group membership
    # --------------------------------------------------------

    foreach ($Check in $GroupsToCheck) {

        try {
            $Members = @(
                Get-NetLocalGroupMember `
                    -ComputerName $Target `
                    -GroupName $Check.GroupName `
                    -ErrorAction Stop
            )
        }
        catch {
            Write-Verbose "Could not enumerate '$($Check.GroupName)' on '$Target': $($_.Exception.Message)"
            continue
        }

        foreach ($Member in $Members) {

            if (-not $Member.SID) {
                continue
            }

            $MemberSID = if ($Member.SID -is [System.Security.Principal.SecurityIdentifier]) {
                $Member.SID.Value
            }
            else {
                [string]$Member.SID
            }

            $MatchReason = $null

            if ($MemberSID -eq $UserSID) {
                $MatchReason = 'Direct user SID match'
            }
            elseif ($CurrentSIDs -contains $MemberSID) {
                $MatchReason = 'Matched a group SID in the current Windows token'
            }
            elseif ($DomainUsersSID -and $MemberSID -eq $DomainUsersSID) {
                $MatchReason = 'Domain Users group SID'
            }

            if ($MatchReason) {

                $Matches += [PSCustomObject]@{
                    LocalGroupName = $Check.GroupName
                    MemberName     = $Member.MemberName
                    MatchReason    = $MatchReason
                    Interpretation = $Check.Description
                }

                switch ($Check.ResultProperty) {
                    'LocalAdmin' { $LocalAdmin = $true }
                    'RDPGroup'   { $RDPGroup = $true }
                    'WinRMGroup' { $WinRMGroup = $true }
                }
            }
        }
    }

    # --------------------------------------------------------
    # Skip computers without matching group memberships
    # --------------------------------------------------------

    if ($Matches.Count -eq 0) {
        continue
    }

    # --------------------------------------------------------
    # Optional connection tests
    # --------------------------------------------------------

    $RDPConnection = 'Not tested'
    $WinRMConnection = 'Not tested'

    if ($TestConnection) {

        # RDP: test TCP port 3389 reachability.
        try {
            $RDPReachable = Test-NetConnection `
                -ComputerName $Target `
                -Port 3389 `
                -InformationLevel Quiet `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop

            if ($RDPReachable) {
                $RDPConnection = 'Yes'
            }
            else {
                $RDPConnection = 'No'
            }
        }
        catch {
            $RDPConnection = 'No'
        }

        # WinRM: attempt to execute a remote PowerShell command.
        try {
            Invoke-Command `
                -ComputerName $Target `
                -ScriptBlock { $env:COMPUTERNAME } `
                -ErrorAction Stop | Out-Null

            $WinRMConnection = 'Yes'
        }
        catch {
            $WinRMConnection = 'No'
        }
    }

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    Write-Host ''
    Write-Host '============================================================'
    Write-Host "Target Computer : $Target"
    Write-Host "Current User    : $CurrentUser"
    Write-Host '============================================================'

    Write-Host ''
    Write-Host 'Matching Group Memberships:'
    Write-Host ''

    foreach ($Match in $Matches) {
        Write-Host "  Local Group Name : $($Match.LocalGroupName)"
        Write-Host "  MemberName       : $($Match.MemberName)"
        Write-Host "  Match Reason     : $($Match.MatchReason)"
        Write-Host "  Interpretation   : $($Match.Interpretation)"
        Write-Host ''
    }

    Write-Host "LocalAdmin         : $(if ($LocalAdmin) { 'Yes' } else { 'No' })"
    Write-Host "RDP Group          : $(if ($RDPGroup) { 'Yes' } else { 'No' })"
    Write-Host "RDP Connection     : $RDPConnection"
    Write-Host "WinRM Group        : $(if ($WinRMGroup) { 'Yes' } else { 'No' })"
    Write-Host "WinRM Connection   : $WinRMConnection"
    Write-Host ''
}
