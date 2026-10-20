<#
.SYNOPSIS
    License assignment problems: users/groups with license errors, service plans stuck in PendingInput/Error, licensed users without usage location, disabled users holding licenses.

.DESCRIPTION
    Two modes:
      Tenant scan (default): scans users (up to -MaxUsers) and group-based licensing errors.
      Specific users: pass -UserPrincipalName or pick a CSV/TXT file - shows per-plan provisioning status.

.PARAMETER UserPrincipalName
    One or more users for detailed per-plan output. Prompted (Enter = tenant scan, F = file picker).

.PARAMETER MaxUsers
    Max users to scan in tenant mode (default 25000).

.EXAMPLE
    .\Get-LicensingDiagnostics.ps1
    .\Get-LicensingDiagnostics.ps1 -UserPrincipalName jane@contoso.com,bob@contoso.com

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader, License Administrator or User Administrator (read)
    Scopes     : Organization.Read.All, User.Read.All, Group.Read.All, Directory.Read.All
    Read-only  : HTTP GET requests only.
#>
[CmdletBinding()]
param(
    [string[]]$UserPrincipalName,
    [int]$MaxUsers = 25000,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $PSBoundParameters.ContainsKey('UserPrincipalName')) {
    $raw = Read-Host -Prompt '  Specific user(s) (comma separated), F = pick CSV/TXT file, Enter = scan whole tenant'
    if ($raw -match '^\s*(f|file)\s*$') {
        $path = Select-DiagFile -Title 'Select a CSV or TXT file with users' -Filter 'CSV or text (*.csv;*.txt)|*.csv;*.txt|All files (*.*)|*.*'
        if ($path) { $UserPrincipalName = Import-DiagIdentityFile -Path $path }
    }
    elseif ($raw) { $UserPrincipalName = @($raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
}
$mode = if ($UserPrincipalName) { 'Users' } else { 'Tenant' }

Start-DiagRun -Name 'Get-LicensingDiagnostics' -Title "Entra ID - Licensing Diagnostics ($mode)" -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Mode = $mode; Users = ($UserPrincipalName -join ', '); MaxUsers = $MaxUsers })
$errorHelp = @{
    CountViolation                      = 'Not enough licenses available for the SKU.'
    MutuallyExclusiveViolation          = 'Two assigned plans conflict (e.g. Exchange Online Plan 1 and 2). Disable one plan.'
    DependencyViolation                 = 'A plan requires another plan that is disabled/not assigned.'
    ProhibitedInUsageLocationViolation  = 'Service not offered in the user''s usage location.'
    UniquenessViolation                 = 'Duplicate proxy address / attribute conflict prevents provisioning.'
    Other                               = 'Generic failure - often proxy address conflict; check the user in the admin center.'
}
try {
    Connect-DiagGraph -Scopes 'Organization.Read.All', 'User.Read.All', 'Group.Read.All', 'Directory.Read.All' -TenantId $TenantId

    $skuMap = @{}; $planMap = @{}
    $skus = Invoke-DiagStep -Name 'Subscribed SKUs' -Area 'Licensing' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/subscribedSkus' -All }
    foreach ($s in @($skus)) {
        $skuMap[[string]$s.skuId] = $s.skuPartNumber
        foreach ($sp in @($s.servicePlans)) { $planMap[[string]$sp.servicePlanId] = $sp.servicePlanName }
    }
    Add-DiagData -Section 'SKUs' -Data @($skus | ForEach-Object { [pscustomobject]@{ Sku = $_.skuPartNumber; Status = $_.capabilityStatus; Enabled = $_.prepaidUnits.enabled; Consumed = $_.consumedUnits; Available = ([int]$_.prepaidUnits.enabled - [int]$_.consumedUnits) } })

    if ($mode -eq 'Users') {
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($upn in $UserPrincipalName) {
            Invoke-DiagStep -Name "User $upn" -Area 'User' -ScriptBlock {
                $u = Invoke-DiagGraph -Uri ("v1.0/users/" + [uri]::EscapeDataString($upn) + '?$select=id,displayName,userPrincipalName,accountEnabled,usageLocation,licenseAssignmentStates')
                Register-DiagSensitiveValue -Value $u.displayName -Category name
                $details = @(Invoke-DiagGraph -Uri "v1.0/users/$($u.id)/licenseDetails" -All)
                $groupState = @{}
                foreach ($st in @($u.licenseAssignmentStates)) {
                    $via = if ($st.assignedByGroup) { "Group $($st.assignedByGroup)" } else { 'Direct' }
                    $groupState[[string]$st.skuId] = "$via / $($st.state) / $($st.error)"
                    if ($st.error -and $st.error -ne 'None') {
                        Add-DiagFinding -Severity Critical -Area $upn -Title "$($skuMap[[string]$st.skuId]) assignment error: $($st.error)" -Recommendation $errorHelp[[string]$st.error]
                    }
                }
                foreach ($d in $details) {
                    foreach ($p in @($d.servicePlans)) {
                        $all.Add([pscustomobject]@{
                                User = $u.userPrincipalName; Sku = $d.skuPartNumber; Assignment = $groupState[[string]$d.skuId]; ServicePlan = $p.servicePlanName
                                Status = $p.provisioningStatus; AppliesTo = $p.appliesTo
                            })
                        if ($p.provisioningStatus -in 'Error', 'PendingInput') {
                            Add-DiagFinding -Severity Warning -Area $upn -Title "Service plan $($p.servicePlanName) is $($p.provisioningStatus)" -Recommendation 'PendingInput usually means the usage location or a prerequisite is missing; Error usually means a provisioning conflict (e.g. duplicate proxy address).'
                        }
                    }
                }
                if (-not $u.usageLocation -and $details.Count -gt 0) { Add-DiagFinding -Severity Warning -Area $upn -Title 'No usage location set' }
                if ($details.Count -eq 0) { Add-DiagFinding -Severity Info -Area $upn -Title 'No licenses assigned' }
            } | Out-Null
        }
        Add-DiagData -Section 'Service plan status per user' -Data $all.ToArray()
    }
    else {
        $users = Invoke-DiagStep -Name "Scanning users (max $MaxUsers)" -Area 'Tenant' -ScriptBlock {
            Invoke-DiagGraph -Uri 'v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,usageLocation,assignedLicenses,licenseAssignmentStates,userType&$top=999' -All -MaxItems $MaxUsers
        }
        $users = @($users)
        $errRows = New-Object System.Collections.Generic.List[object]
        $noLoc = New-Object System.Collections.Generic.List[object]
        $disabled = New-Object System.Collections.Generic.List[object]
        $dupe = New-Object System.Collections.Generic.List[object]
        foreach ($u in $users) {
            foreach ($st in @($u.licenseAssignmentStates)) {
                if ($st.error -and $st.error -ne 'None') {
                    $errRows.Add([pscustomobject]@{ User = $u.userPrincipalName; Sku = $skuMap[[string]$st.skuId]; Error = $st.error; AssignedVia = if ($st.assignedByGroup) { "Group $($st.assignedByGroup)" } else { 'Direct' }; State = $st.state; LastUpdated = $st.lastUpdatedDateTime; Meaning = $errorHelp[[string]$st.error] })
                }
            }
            $lic = @($u.assignedLicenses).Count
            if ($lic -gt 0 -and -not $u.usageLocation) { $noLoc.Add([pscustomobject]@{ User = $u.userPrincipalName; Licenses = $lic }) }
            if ($lic -gt 0 -and $u.accountEnabled -eq $false) { $disabled.Add([pscustomobject]@{ User = $u.userPrincipalName; Licenses = (@($u.assignedLicenses | ForEach-Object { $skuMap[[string]$_.skuId] }) -join ', ') }) }
            $bySku = @($u.licenseAssignmentStates | Group-Object skuId | Where-Object { $_.Count -gt 1 -and @($_.Group | Where-Object { -not $_.assignedByGroup }).Count -gt 0 })
            foreach ($b in $bySku) { $dupe.Add([pscustomobject]@{ User = $u.userPrincipalName; Sku = $skuMap[[string]$b.Name]; Assignments = $b.Count }) }
        }
        Add-DiagData -Section 'Users with license errors' -Data $errRows.ToArray()
        Add-DiagData -Section 'Licensed users without usage location' -Data $noLoc.ToArray()
        Add-DiagData -Section 'Disabled users holding licenses' -Data $disabled.ToArray()
        Add-DiagData -Section 'Direct + group assigned (same SKU)' -Data $dupe.ToArray() -Description 'Not an error, but removing the group will not remove the license; cleanup candidates.'

        Add-DiagFinding -Severity Info -Area 'Tenant' -Title "Scanned $($users.Count) users" -Quiet
        if ($errRows.Count -gt 0) {
            foreach ($g in ($errRows | Group-Object Error)) { Add-DiagFinding -Severity Critical -Area 'Tenant' -Title "$($g.Count) user license assignment(s) failing with $($g.Name)" -Recommendation $errorHelp[[string]$g.Name] }
        }
        else { Add-DiagFinding -Severity OK -Area 'Tenant' -Title 'No user license assignment errors' }
        if ($noLoc.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Tenant' -Title "$($noLoc.Count) licensed user(s) have no usage location" -Recommendation 'Set usageLocation (or a tenant default via group-based licensing) - some services will not provision.' }
        if ($disabled.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Tenant' -Title "$($disabled.Count) disabled user(s) still hold licenses" -Recommendation 'Possible cost saving - but check for mailboxes on hold / shared mailbox conversion first.' }
        if ($users.Count -ge $MaxUsers) { Add-DiagFinding -Severity Warning -Area 'Tenant' -Title "User scan capped at $MaxUsers" -Recommendation 'Re-run with -MaxUsers larger for full coverage.' }

        Invoke-DiagStep -Name 'Groups with license errors (group-based licensing)' -Area 'Groups' -ScriptBlock {
            $groups = @(Invoke-DiagGraph -Uri 'v1.0/groups?$filter=hasMembersWithLicenseErrors eq true&$select=id,displayName' -All)
            $rows = foreach ($g in $groups) {
                $members = @(Invoke-DiagGraph -Uri "v1.0/groups/$($g.id)/membersWithLicenseErrors?`$select=id,userPrincipalName" -All -MaxItems 1000)
                [pscustomobject]@{ Group = $g.displayName; GroupId = $g.id; MembersWithErrors = $members.Count; Sample = (@($members | Select-Object -First 10 | ForEach-Object { $_.userPrincipalName }) -join ', ') }
                Add-DiagFinding -Severity Warning -Area 'Groups' -Title "Group '$($g.displayName)' has $($members.Count) member(s) with license errors" -Recommendation 'Admin center > Billing > Licenses > (product) > Groups shows the error per member; usually CountViolation or conflicting plans.'
            }
            Add-DiagData -Section 'Groups with license errors' -Data @($rows)
        } | Out-Null
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
