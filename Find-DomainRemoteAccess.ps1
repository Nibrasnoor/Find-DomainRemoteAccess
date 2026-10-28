[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$SearchBase,
    [switch]$ServersOnly,
    [switch]$WorkstationsOnly,
    [switch]$TestConnection,
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

# ============================================================
# 1. Validate prerequisites
# ============================================================

if (-not (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) {
    throw "ActiveDirectory module not found. Import the module first."
}

if (-not (Get-Command Get-NetLocalGroupMember -ErrorAction SilentlyContinue)) {
    throw "Get-NetLocalGroupMember not found. Import PowerView first."
}

if ($ServersOnly -and $WorkstationsOnly) {
    throw "Use either -ServersOnly or -WorkstationsOnly, not both."
}

# ============================================================
# 2. Determine assessment identity
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
# 3. Discover domain
# ============================================================

$DomainParams = @{}

if ($Credential) {
    $DomainParams['Credential'] = $Credential
}

try {
    $DomainInfo = Get-ADDomain @DomainParams

    $DomainController = $DomainInfo.PDCEmulator
    $DomainDNSName = $DomainInfo.DNSRoot

    Write-Host "[*] Domain: $DomainDNSName" -ForegroundColor Cyan
}
catch {
    throw "Unable to discover the AD domain: $($_.Exception.Message)"
}

# ============================================================
# 4. Resolve assessment user and group SIDs
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
    $AssessmentUserSID = [string]$AssessmentADUser.SID.Value

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

    # Keep the group SIDs as strings for exact comparison.
    $AssessmentGroupSIDs = @(
        $AssessmentGroups |
            ForEach-Object {
                [string]$_.SID.Value
            } |
            Where-Object { $_ }
    )

    $AssessmentGroupSIDs = @(
        $AssessmentGroupSIDs | Sort-Object -Unique
    )

    Write-Host "[+] Assessment account resolved: $($AssessmentADUser.SamAccountName)" -ForegroundColor Green
    Write-Host "[+] Account SID: $AssessmentUserSID" -ForegroundColor Green
    Write-Host "[+] AD group SIDs collected: $($AssessmentGroupSIDs.Count)" -ForegroundColor Green
}
catch {
    throw "Unable to resolve the assessment account or its group memberships: $($_.Exception.Message)"
}

# ============================================================
# 5. Discover target computers
# ============================================================

if ($ComputerName -and $ComputerName.Count -gt 0) {

    $Computers = @(
        foreach ($Name in $ComputerName) {

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
                Write-Warning "Could not resolve computer '$Name': $($_.Exception.Message)"
            }
        }
    )
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

if (-not $Computers -or $Computers.Count -eq 0) {
    Write-Warning "No target computers found."
    return
}

# ============================================================
# 6. Local groups to enumerate
# ============================================================

$LocalGroups = @(
    'Administrators',
    'Remote Desktop Users',
    'Remote Management Users'
)

# ============================================================
# 7. Enumerate each computer
# ============================================================

foreach ($Computer in $Computers) {

    # Use the short name for PowerView enumeration.
    $Target = [string]$Computer.Name

    # Use FQDN for reporting and connectivity tests when available.
    $TargetFQDN = if ($Computer.DNSHostName) {
        [string]$Computer.DNSHostName
    }
    else {
        $Target
    }

    Write-Host ""
    Write-Host "[*] Checking $TargetFQDN" -ForegroundColor Cyan

    $MatchingMemberships = @()

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

            # Suppress only warning stream 3 for this invocation.
            $Members = @(
                Get-NetLocalGroupMember @LocalGroupParams 3>$null
            )
        }
        catch {
            Write-Warning "Failed to enumerate '$Group' on '$Target': $($_.Exception.Message)"
            continue
        }

        # ----------------------------------------------------
        # 8. Match direct user SID and AD group SIDs
        # ----------------------------------------------------

        foreach ($Member in $Members) {

            $MemberSID = [string]$Member.SID

            if ([string]::IsNullOrWhiteSpace($MemberSID)) {
                continue
            }

            $MatchReason = $null

            if ($MemberSID -eq [string]$AssessmentUserSID) {
                $MatchReason = 'Direct assessment user SID match'
            }
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
                ComputerName   = $TargetFQDN
                LocalGroupName = $Group
                MemberName     = [string]$Member.MemberName
                MemberSID      = $MemberSID
                MatchReason    = $MatchReason
                Interpretation = $Interpretation
            }
        }
    }

    # ========================================================
    # 9. Report computers without matching memberships
    # ========================================================

    if ($MatchingMemberships.Count -eq 0) {
        Write-Host "[-] No matching memberships found on $TargetFQDN" -ForegroundColor DarkYellow
        continue
    }

    # ========================================================
    # 10. Summarize matching memberships
    # ========================================================

    $HasLocalAdmin = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Administrators' } |
            Select-Object -First 1
    )

    $HasRDPGroup = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Remote Desktop Users' } |
            Select-Object -First 1
    )

    $HasWinRMGroup = [bool](
        $MatchingMemberships |
            Where-Object { $_.LocalGroupName -eq 'Remote Management Users' } |
            Select-Object -First 1
    )

    # ========================================================
    # 11. Optional connection tests
    # ========================================================

    $RDPConnection = 'Not Tested'
    $WinRMConnection = 'Not Tested'

    if ($TestConnection) {

        # RDP: checks TCP port 3389 reachability only.
        try {
            $RDPResult = Test-NetConnection `
                -ComputerName $TargetFQDN `
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
            Write-Verbose "RDP connectivity test failed: $($_.Exception.Message)"
        }

        # WinRM: tests authenticated remote PowerShell execution.
        try {
            $RemoteCommandParams = @{
                ComputerName = $TargetFQDN
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
            Write-Verbose "WinRM test failed on '$TargetFQDN': $($_.Exception.Message)"
        }
    }

    # ========================================================
    # 12. Display results
    # ========================================================

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Target Computer : $TargetFQDN"
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
