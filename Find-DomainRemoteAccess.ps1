[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [string]$SearchBase,

    [switch]$ServersOnly,

    [switch]$WorkstationsOnly,

    [switch]$TestConnection,

    [System.Management.Automation.PSCredential]$Credential
)

# ------------------------------------------------------------
# Prerequisites
# ------------------------------------------------------------
# - ActiveDirectory module
# - PowerView loaded, including Get-NetLocalGroupMember
# ------------------------------------------------------------

Import-Module ActiveDirectory -ErrorAction Stop

# ------------------------------------------------------------
# Helper: Build parameters for AD queries
# ------------------------------------------------------------

$ADParams = @{}

if ($Credential) {
    $ADParams['Credential'] = $Credential
}

# ------------------------------------------------------------
# Get current user's SID and group SIDs
# ------------------------------------------------------------

$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$UserSID = $CurrentIdentity.User.Value

$CurrentSIDs = @(
    $CurrentIdentity.Groups | ForEach-Object {
        $_.Value
    }
)

# ------------------------------------------------------------
# Get Domain Users SID
# ------------------------------------------------------------

try {
    $DomainInfo = Get-ADDomain @ADParams -ErrorAction Stop
    $DomainSID = $DomainInfo.DomainSID.Value
    $DomainUsersSID = "$DomainSID-513"
}
catch {
    Write-Warning "Unable to retrieve the domain SID: $($_.Exception.Message)"
    $DomainUsersSID = $null
}

# ------------------------------------------------------------
# Enumerate target computers
# ------------------------------------------------------------

$Computers = @()

if ($ComputerName) {

    foreach ($Computer in $ComputerName) {
        $Computers += [PSCustomObject]@{
            Name = $Computer
        }
    }

}
else {

    $ComputerParams = @{}

    if ($SearchBase) {
        $ComputerParams['SearchBase'] = $SearchBase
    }

    $ComputerParams['Filter'] = '*'
    $ComputerParams['Properties'] = @('OperatingSystem')

    foreach ($Key in $ADParams.Keys) {
        $ComputerParams[$Key] = $ADParams[$Key]
    }

    try {
        $Computers = Get-ADComputer @ComputerParams -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to enumerate AD computers: $($_.Exception.Message)"
        return
    }

    # --------------------------------------------------------
    # Optional OS filtering
    # --------------------------------------------------------

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
}

if (-not $Computers) {
    Write-Warning "No computers found."
    return
}

# ------------------------------------------------------------
# Define local groups to check
# ------------------------------------------------------------

$GroupsToCheck = @(
    @{
        GroupName   = 'Administrators'
        Description = 'Potential local administrator access'
    },
    @{
        GroupName   = 'Remote Desktop Users'
        Description = 'Member of the local Remote Desktop Users group'
    },
    @{
        GroupName   = 'Remote Management Users'
        Description = 'Member of the local Remote Management Users group'
    }
)

# ------------------------------------------------------------
# Enumerate local group membership on each computer
# ------------------------------------------------------------

$Results = @()

foreach ($Computer in $Computers) {

    $Target = $Computer.Name

    Write-Host "`n[*] Checking $Target" -ForegroundColor Cyan

    $ComputerResults = @()

    foreach ($Check in $GroupsToCheck) {

        try {

            $GroupParams = @{
                ComputerName = $Target
                GroupName    = $Check.GroupName
                ErrorAction  = 'Stop'
            }

            if ($Credential) {
                $GroupParams['Credential'] = $Credential
            }

            $Members = Get-NetLocalGroupMember @GroupParams

            foreach ($Member in $Members) {

                $MemberSID = $null

                if ($Member.SID -is [System.Security.Principal.SecurityIdentifier]) {
                    $MemberSID = $Member.SID.Value
                }
                elseif ($Member.SID) {
                    $MemberSID = [string]$Member.SID
                }

                if (-not $MemberSID) {
                    continue
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

                    $ComputerResults += [PSCustomObject]@{
                        ComputerName   = $Target
                        LocalGroupName = $Check.GroupName
                        MemberName     = $Member.MemberName
                        SID            = $MemberSID
                        MatchReason    = $MatchReason
                        Interpretation = $Check.Description
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not enumerate '$($Check.GroupName)' on $Target : $($_.Exception.Message)"
        }
    }

    # Skip computers with no matching memberships
    if (-not $ComputerResults) {
        Write-Host "[-] No matching memberships found on $Target" -ForegroundColor DarkGray
        continue
    }

    # --------------------------------------------------------
    # Optional connectivity tests
    # --------------------------------------------------------

    $RDPConnection = 'Not tested'
    $WinRMConnection = 'Not tested'

    if ($TestConnection) {

        # Check whether TCP port 3389 is reachable.
        try {
            $RDPTest = Test-NetConnection `
                -ComputerName $Target `
                -Port 3389 `
                -WarningAction SilentlyContinue

            if ($RDPTest.TcpTestSucceeded) {
                $RDPConnection = 'Yes'
            }
            else {
                $RDPConnection = 'No'
            }
        }
        catch {
            $RDPConnection = 'Error'
        }

        # Test whether a remote PowerShell command can execute.
        try {

            $InvokeParams = @{
                ComputerName = $Target
                ScriptBlock  = { $env:COMPUTERNAME }
                ErrorAction  = 'Stop'
            }

            if ($Credential) {
                $InvokeParams['Credential'] = $Credential
            }

            $null = Invoke-Command @InvokeParams

            $WinRMConnection = 'Yes'
        }
        catch {
            $WinRMConnection = 'No'
        }
    }

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    $HasAdminAccess = (
        $ComputerResults.LocalGroupName -contains 'Administrators'
    )

    $HasRDPGroup = (
        $ComputerResults.LocalGroupName -contains 'Remote Desktop Users'
    )

    $HasWinRMGroup = (
        $ComputerResults.LocalGroupName -contains 'Remote Management Users'
    )

    Write-Host "`nComputer: $Target" -ForegroundColor Green
    Write-Host "LocalAdmin: $HasAdminAccess"
    Write-Host "RDP Group: $HasRDPGroup"
    Write-Host "RDP Connection: $RDPConnection"
    Write-Host "WinRM Group: $HasWinRMGroup"
    Write-Host "WinRM Connection: $WinRMConnection"

    $Results += $ComputerResults
}

# ------------------------------------------------------------
# Display matching membership details
# ------------------------------------------------------------

if ($Results) {

    Write-Host "`n========== Matching Group Memberships ==========" -ForegroundColor Cyan

    $Results |
        Sort-Object ComputerName, LocalGroupName, MemberName -Unique |
        Format-Table ComputerName, LocalGroupName, MemberName, SID, MatchReason -AutoSize
}
else {
    Write-Host "`nNo matching group memberships were found." -ForegroundColor Yellow
}
