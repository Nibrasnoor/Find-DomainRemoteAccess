[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [string]$SearchBase,

    [switch]$ServersOnly,

    [switch]$WorkstationsOnly,

    [switch]$TestConnection,

    [System.Management.Automation.PSCredential]$Credential
)

# ============================================================
# Find-DomainRemoteAccess.ps1
#
# Enumerates local Administrators, Remote Desktop Users, and
# Remote Management Users group memberships on AD computers.
#
# Requirements:
#   - Windows PowerShell
#   - ActiveDirectory module
#   - PowerView loaded into the current session
# ============================================================

# ------------------------------------------------------------
# Validate parameters and prerequisites
# ------------------------------------------------------------

if ($ServersOnly -and $WorkstationsOnly) {
    throw "Use either -ServersOnly or -WorkstationsOnly, not both."
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Get-Command Get-NetLocalGroupMember -ErrorAction SilentlyContinue)) {
    throw "Get-NetLocalGroupMember was not found. Load PowerView.ps1 before running this script."
}

# ------------------------------------------------------------
# Determine the current Windows identity
# ------------------------------------------------------------
# Credential is used for remote operations and AD queries.
# The current user's identity remains the identity of the
# PowerShell process running this script.
# ------------------------------------------------------------

$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

$CurrentUser = $CurrentIdentity.Name
$UserSID = $CurrentIdentity.User.Value

$CurrentSIDs = @(
    $CurrentIdentity.Groups | ForEach-Object {
        $_.Value
    }
)

# ------------------------------------------------------------
# Build Active Directory query parameters
# ------------------------------------------------------------

$ADParams = @{}

if ($Credential) {
    $ADParams['Credential'] = $Credential
}

# ------------------------------------------------------------
# Retrieve domain SID and Domain Users SID
# ------------------------------------------------------------

$DomainUsersSID = $null

try {
    $DomainInfo = Get-ADDomain @ADParams -ErrorAction Stop

    $DomainSID = $DomainInfo.DomainSID.Value
    $DomainUsersSID = "$DomainSID-513"
}
catch {
    Write-Warning "Unable to retrieve domain SID: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# Enumerate target computers
# ------------------------------------------------------------

$Computers = @()

if ($ComputerName) {

    foreach ($Computer in $ComputerName) {

        if ([string]::IsNullOrWhiteSpace($Computer)) {
            continue
        }

        $Computers += [PSCustomObject]@{
            Name            = $Computer
            OperatingSystem = $null
        }
    }
}
else {

    $ComputerParams = @{
        Filter     = '*'
        Properties = @('OperatingSystem')
        ErrorAction = 'Stop'
    }

    if ($SearchBase) {
        $ComputerParams['SearchBase'] = $SearchBase
    }

    foreach ($Key in $ADParams.Keys) {
        $ComputerParams[$Key] = $ADParams[$Key]
    }

    try {
        $Computers = @(Get-ADComputer @ComputerParams)
    }
    catch {
        Write-Error "Failed to enumerate AD computers: $($_.Exception.Message)"
        return
    }

    if ($ServersOnly) {
        $Computers = @(
            $Computers | Where-Object {
                $_.OperatingSystem -match 'Server'
            }
        )
    }

    if ($WorkstationsOnly) {
        $Computers = @(
            $Computers | Where-Object {
                $_.OperatingSystem -and
                $_.OperatingSystem -notmatch 'Server'
            }
        )
    }
}

if (-not $Computers -or $Computers.Count -eq 0) {
    Write-Warning "No computers found."
    return
}

# ------------------------------------------------------------
# Define local groups to enumerate
# ------------------------------------------------------------

$GroupsToCheck = @(
    @{
        GroupName   = 'Administrators'
        Description = 'Potential local administrator access'
    },
    @{
        GroupName   = 'Remote Desktop Users'
        Description = 'Potential Remote Desktop (RDP) access'
    },
    @{
        GroupName   = 'Remote Management Users'
        Description = 'Potential Windows Remote Management (WinRM) access'
    }
)

# ------------------------------------------------------------
# Enumerate each target
# ------------------------------------------------------------

$AllResults = @()

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

            $Members = @(Get-NetLocalGroupMember @GroupParams)

            foreach ($Member in $Members) {

                # Extract the member SID.
                $MemberSID = $null

                if (
                    $Member.SID -is
                    [System.Security.Principal.SecurityIdentifier]
                ) {
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
                elseif (
                    $DomainUsersSID -and
                    $MemberSID -eq $DomainUsersSID
                ) {

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

            Write-Warning (
                "Could not enumerate '$($Check.GroupName)' on " +
                "$Target : $($_.Exception.Message)"
            )
        }
    }

    # Only report computers with matching group memberships.
    if ($ComputerResults.Count -eq 0) {

        Write-Host "[-] No matching memberships found on $Target" `
            -ForegroundColor DarkGray

        continue
    }

    # --------------------------------------------------------
    # Optional RDP and WinRM connectivity tests
    # --------------------------------------------------------

    $RDPConnection = 'Not tested'
    $WinRMConnection = 'Not tested'

    if ($TestConnection) {

        # RDP: Check TCP port 3389.
        try {

            $RDPTest = Test-NetConnection `
                -ComputerName $Target `
                -Port 3389 `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop

            if ($RDPTest.TcpTestSucceeded) {
                $RDPConnection = 'Yes'
            }
            else {
                $RDPConnection = 'No'
            }
        }
        catch {
            $RDPConnection = 'No'
        }

        # WinRM: Attempt to execute a remote PowerShell command.
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
    # Calculate status fields
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

    # --------------------------------------------------------
    # Display results in README format
    # --------------------------------------------------------

    Write-Host "`n============================================================" `
        -ForegroundColor Cyan

    Write-Host "Target Computer : $Target" -ForegroundColor Cyan
    Write-Host "Current User    : $CurrentUser" -ForegroundColor Cyan

    Write-Host "============================================================" `
        -ForegroundColor Cyan

    Write-Host "`nMatching Group Memberships:" -ForegroundColor Yellow

    foreach (
        $Result in (
            $ComputerResults |
            Sort-Object LocalGroupName, MemberName -Unique
        )
    ) {

        Write-Host "`n  Local Group Name : $($Result.LocalGroupName)"
        Write-Host "  MemberName       : $($Result.MemberName)"
        Write-Host "  Match Reason     : $($Result.MatchReason)"
        Write-Host "  Interpretation   : $($Result.Interpretation)"
    }

    Write-Host ""

    Write-Host ("LocalAdmin         : " + $(if ($HasAdminAccess) { 'Yes' } else { 'No' }))
    Write-Host ("RDP Group          : " + $(if ($HasRDPGroup) { 'Yes' } else { 'No' }))
    Write-Host "RDP Connection     : $RDPConnection"
    Write-Host ("WinRM Group        : " + $(if ($HasWinRMGroup) { 'Yes' } else { 'No' }))
    Write-Host "WinRM Connection   : $WinRMConnection"

    # Store matching results for optional downstream processing.
    $AllResults += $ComputerResults
}

# ------------------------------------------------------------
# Return structured results to the PowerShell pipeline
# ------------------------------------------------------------

$AllResults |
    Sort-Object ComputerName, LocalGroupName, MemberName -Unique
