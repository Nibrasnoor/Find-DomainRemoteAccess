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
# Enumerates local group memberships on domain computers:
#   - Administrators
#   - Remote Desktop Users
#   - Remote Management Users
#
# Matches local group members against the assessment user's
# SID and AD security-group SIDs.
#
# Optional connectivity tests:
#   - RDP: TCP port 3389
#   - WinRM: remote PowerShell command execution
#
# Requires:
#   - ActiveDirectory PowerShell module
#   - PowerView (Get-NetLocalGroupMember)
#   - Appropriate permissions and authorized access
# ============================================================

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================
# 1. Validate prerequisites
# ============================================================

if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
    throw "ActiveDirectory PowerShell module is unavailable. Import it before running this script."
}

if (-not (Get-Command Get-NetLocalGroupMember -ErrorAction SilentlyContinue)) {
    throw "Get-NetLocalGroupMember was not found. Import PowerView before running this script."
}

if ($ServersOnly -and $WorkstationsOnly) {
    throw "Use either -ServersOnly or -WorkstationsOnly, not both."
}

# ============================================================
# 2. Determine the assessment identity
# ============================================================

$ProcessIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$ProcessUser = $ProcessIdentity.Name

if ($Credential) {
    $AssessmentUser = $Credential.UserName
    $SamAccountName = ($Credential.UserName -split '\\')[-1]
}
else {
    $AssessmentUser = $ProcessUser
    $SamAccountName = ($ProcessUser -split '\\')[-1]
}

Write-Host ""
Write-Host "[*] Assessment identity: $AssessmentUser" -ForegroundColor Cyan

# ============================================================
# 3. Build AD parameters
# ============================================================

$ADParams = @{}

if ($Credential) {
    $ADParams['Credential'] = $Credential
}

if ($SearchBase) {
    $ADParams['SearchBase'] = $SearchBase
}

# ============================================================
# 4. Discover the domain
# ============================================================

try {
    $DomainInfo = Get-ADDomain @(
        $ADParams
    )
}
catch {
    # Retry using standard PowerShell splatting.
    $DomainInfo = Get-ADDomain @ADParams
}

$DomainSID = $DomainInfo.DomainSID.Value
$DomainName = $DomainInfo.NetBIOSName
$DomainDNSName = $DomainInfo.DNSRoot
$DomainController = $DomainInfo.PDCEmulator

Write-Host "[*] Domain: $DomainDNSName" -ForegroundColor Cyan

# ============================================================
# 5. Resolve the assessment user and group SIDs
# ============================================================

try {
    $UserParams = @{
        Identity    = $SamAccountName
        Server      = $DomainController
        ErrorAction = 'Stop'
    }

    if ($Credential) {
        $UserParams['Credential'] = $Credential
    }

    $AssessmentADUser = Get-ADUser @UserParams

    $AssessmentUserSID = $AssessmentADUser.SID.Value

    $GroupParams = @{
        Identity    = $AssessmentADUser
        Server      = $DomainController
        ErrorAction = 'Stop'
    }

    if ($Credential) {
        $GroupParams['Credential'] = $Credential
    }

    $AssessmentGroups = @(
        Get-ADPrincipalGroupMembership @GroupParams
    )

    $AssessmentGroupSIDs = @(
        $AssessmentGroups |
            ForEach-Object { $_.SID.Value } |
            Where-Object { $_ }
    )

    # Include the user's own SID and the SIDs of their AD groups.
    $AssessmentSIDs = @(
        $AssessmentUserSID
        $AssessmentGroupSIDs
    ) | Sort-Object -Unique

    if (-not $AssessmentUserSID) {
        throw "Could not resolve the assessment user's SID."
    }

    Write-Host "[+] Assessment account resolved: $($AssessmentADUser.SamAccountName)" -ForegroundColor Green
    Write-Host "[+] Account SID: $AssessmentUserSID" -ForegroundColor Green
    Write-Host "[+] AD group SIDs collected: $($AssessmentGroupSIDs.Count)" -ForegroundColor Green
}
catch {
    throw "Could not resolve the assessment user's SID or AD group memberships. $($_.Exception.Message)"
}

# ============================================================
# 6. Discover target computers
# ============================================================

if ($ComputerName -and $ComputerName.Count -gt 0) {

    $Computers = foreach ($Name in $ComputerName) {
        try {
            $ComputerParams = @{
                Identity    = $Name
                Server      = $DomainController
                Properties  = @(
                    'DNSHostName',
                    'OperatingSystem',
                    'DistinguishedName'
                )
                ErrorAction = 'Stop'
            }

            if ($Credential) {
                $ComputerParams['Credential'] = $Credential
            }

            Get-ADComputer @ComputerParams
        }
        catch {
            Write-Warning "Could not resolve computer '$Name' in AD: $($_.Exception.Message)"
        }
    }
}
else {
    $ComputerParams = @{
        Filter      = '*'
        Server      = $DomainController
        Properties  = @(
            'DNSHostName',
            'OperatingSystem',
            'DistinguishedName'
        )
        ErrorAction = 'Stop'
    }

    if ($SearchBase) {
        $ComputerParams['SearchBase'] = $SearchBase
    }

    if ($Credential) {
        $ComputerParams['Credential'] = $Credential
    }

    $Computers = @(Get-ADComputer @ComputerParams)
}

if ($ServersOnly) {
    $Computers = @(
        $Computers | Where-Object {
            $_.OperatingSystem -like '*Server*'
        }
    )
}
elseif ($WorkstationsOnly) {
    $Computers = @(
        $Computers | Where-Object {
            $_.OperatingSystem -and
            $_.OperatingSystem -notlike '*Server*'
        }
    )
}

if (-not $Computers -or @($Computers).Count -eq 0) {
    Write-Warning "No target computers were found."
    return
}

# ============================================================
# 7. Define the local groups to enumerate
# ============================================================

$LocalGroups = @(
    'Administrators'
    'Remote Desktop Users'
    'Remote Management Users'
)

# ============================================================
# 8. Process each computer
# ============================================================

foreach ($Computer in $Computers) {

    $Target = if ($Computer.DNSHostName) {
        $Computer.DNSHostName
    }
    else {
        $Computer.Name
    }

    Write-Host ""
    Write-Host "[*] Checking $Target" -ForegroundColor Cyan

    $MatchingMemberships = @()

    # --------------------------------------------------------
    # Enumerate each local group
    # --------------------------------------------------------

    foreach ($Group in $LocalGroups) {

        try {
            $LocalGroupParams = @{
                ComputerName = $Target
                GroupName    = $Group
                ErrorAction  = 'Stop'
            }

            if ($Credential) {
                $LocalGroupParams['Credential'] = $Credential
            }

            # OPTION 3:
            # Suppress only the warning stream from this invocation.
            # Normal results and errors remain available.
            $Members = @(
                Get-NetLocalGroupMember @LocalGroupParams 3>$null
            )
        }
        catch {
            Write-Verbose "Could not enumerate '$Group' on '$Target': $($_.Exception.Message)"
            continue
        }

        foreach ($Member in $Members) {

            $MemberSID = [string]$Member.SID

            if (-not $MemberSID) {
                continue
            }

            $MatchReason = $null
            $Interpretation = $null

            # Direct match against the assessment user's SID.
            if ($MemberSID -eq $AssessmentUserSID) {

                $MatchReason = 'Direct assessment user SID match'

            }
            # Match against any AD group SID belonging to the
            # assessment user.
            elseif ($AssessmentGroupSIDs -contains $MemberSID) {

                $MatchReason = 'Matched an AD group SID of the assessment user'

            }

            if (-not $MatchReason) {
                continue
            }

            switch ($Group) {

                'Administrators' {
                    $Interpretation = 'Potential local administrator access'
                }

                'Remote Desktop Users' {
                    $Interpretation = 'Potential Remote Desktop (RDP) access'
                }

                'Remote Management Users' {
                    $Interpretation = 'Potential Windows Remote Management (WinRM) access'
                }
            }

            $MatchingMemberships += [PSCustomObject]@{
                ComputerName   = $Target
                LocalGroupName = $Group
                MemberName     = $Member.MemberName
                MemberSID      = $MemberSID
                MatchReason    = $MatchReason
                Interpretation = $Interpretation
            }
        }
    }

    # --------------------------------------------------------
    # Skip computers with no matching memberships
    # --------------------------------------------------------

    if ($MatchingMemberships.Count -eq 0) {
        Write-Host "[-] No matching memberships found on $Target" -ForegroundColor DarkYellow
        continue
    }

    # --------------------------------------------------------
    # Summarize group matches
    # --------------------------------------------------------

    $HasLocalAdmin = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Administrators' }
    )

    $HasRDPGroup = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Remote Desktop Users' }
    )

    $HasWinRMGroup = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Remote Management Users' }
    )

    # --------------------------------------------------------
    # Optional connectivity tests
    # --------------------------------------------------------

    $RDPConnection = 'Not Tested'
    $WinRMConnection = 'Not Tested'

    if ($TestConnection) {

        # RDP: TCP connectivity only; does not verify login access.
        try {
            $RDPResult = Test-NetConnection `
                -ComputerName $Target `
                -Port 3389 `
                -WarningAction SilentlyContinue `
                -ErrorAction Stop

            if ($RDPResult.TcpTestSucceeded) {
                $RDPConnection = 'Yes'
            }
            else {
                $RDPConnection = 'No'
            }
        }
        catch {
            $RDPConnection = 'Error'
        }

        # WinRM: attempts an authenticated remote command.
        try {
            $RemoteCommandParams = @{
                ComputerName = $Target
                ScriptBlock  = { $env:COMPUTERNAME }
                ErrorAction  = 'Stop'
            }

            if ($Credential) {
                $RemoteCommandParams['Credential'] = $Credential
            }

            $null = Invoke-Command @RemoteCommandParams
            $WinRMConnection = 'Yes'
        }
        catch {
            $WinRMConnection = 'No'
            Write-Verbose "WinRM test failed on '$Target': $($_.Exception.Message)"
        }
    }

    # --------------------------------------------------------
    # Display results in README-style format
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Target Computer : $Target"
    Write-Host "Current User    : $AssessmentUser"
    Write-Host "============================================================"

    Write-Host ""
    Write-Host "Matching Group Memberships:"
    Write-Host ""

    foreach ($Match in $MatchingMemberships) {

        Write-Host "  Local Group Name : $($Match.LocalGroupName)"
        Write-Host "  MemberName       : $($Match.MemberName)"
        Write-Host "  Match Reason     : $($Match.MatchReason)"
        Write-Host "  Interpretation   : $($Match.Interpretation)"
        Write-Host ""
    }

    Write-Host "LocalAdmin         : $(if ($HasLocalAdmin) { 'Yes' } else { 'No' })"
    Write-Host "RDP Group          : $(if ($HasRDPGroup) { 'Yes' } else { 'No' })"

    if ($TestConnection) {
        Write-Host "RDP Connection     : $RDPConnection"
    }

    Write-Host "WinRM Group        : $(if ($HasWinRMGroup) { 'Yes' } else { 'No' })"

    if ($TestConnection) {
        Write-Host "WinRM Connection   : $WinRMConnection"
    }

    Write-Host ""
}
