<#
.SYNOPSIS
    OneDrive diagnostics for one or more users: provisioned or not, lock state, storage vs quota, sharing, who has admin access, deleted/orphaned OneDrive, and the tenant OneDrive defaults.

.DESCRIPTION
    Typical tickets: "OneDrive not provisioned / user sees 'we're setting up OneDrive'", "OneDrive full",
    "access denied to a leaver's OneDrive", "OneDrive locked", "who can access this OneDrive".
    Accepts a single UPN, several, or a CSV/TXT file (file picker).

.PARAMETER UserPrincipalName
    One or more UPNs. Prompted if omitted (F = file picker).

.EXAMPLE
    .\Get-OneDriveUserDiagnostics.ps1 -UserPrincipalName jane@contoso.com

.NOTES
    Connection : SharePoint Online Management Shell (Connect-SPOService)
    Roles      : SharePoint Administrator
    Read-only  : Only Get-SPO* cmdlets are called. (Pre-provisioning with Request-SPOPersonalSite is a change and is NOT run.)
#>
[CmdletBinding()]
param(
    [string[]]$UserPrincipalName,
    [string]$TenantName,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $UserPrincipalName) { $UserPrincipalName = Read-DiagIdentityList -Prompt 'OneDrive user(s) (UPN)' }

Start-DiagRun -Name 'Get-OneDriveUserDiagnostics' -Title 'OneDrive - User Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Users = ($UserPrincipalName -join ', ') })
try {
    if (-not $TenantName) {
        $dom = ($UserPrincipalName[0] -split '@')[-1]
        if ($dom -match '^([a-z0-9\-]+)\.onmicrosoft\.com$') { $TenantName = $Matches[1] }
    }
    $spo = Connect-DiagSharePoint -TenantName $TenantName
    $myHost = "https://$($spo.TenantName)-my.sharepoint.com"

    $t = Invoke-DiagStep -Name 'Tenant OneDrive defaults' -Area 'Tenant' -ScriptBlock { Get-SPOTenant -ErrorAction Stop }
    if ($t) {
        Add-DiagData -Section 'Tenant OneDrive settings' -Data ($t | Select-DiagObject -Property OneDriveStorageQuota, OrphanedPersonalSitesRetentionPeriod, OneDriveForGuestsEnabled, OneDriveSharingCapability, ODBMembersCanShare, ODBAccessRequests, NotifyOwnersWhenItemsReshared, DefaultSharingLinkType, RequireAnonymousLinksExpireInDays, OneDriveDefaultShareLinkScope, OneDriveLoopSharingCapability, ConditionalAccessPolicy, OneDriveRequestFilesLinkEnabled, EnableAutoNewsDigest)
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($upn in $UserPrincipalName) {
        Write-DiagInfo $upn -Level Header
        $expected = "$myHost/personal/" + ($upn.ToLowerInvariant() -replace '[@\.]', '_')
        $site = Invoke-DiagStep -Name 'Locating OneDrive' -Area $upn -ScriptBlock {
            try { Get-SPOSite -Identity $expected -ErrorAction Stop }
            catch {
                $prefix = ($expected -replace '_[^_/]*$', '')
                @(Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '$prefix'" -ErrorAction Stop | Where-Object { [string]$_.Owner -eq $upn }) | Select-Object -First 1
            }
        }
        if (-not $site) {
            $deleted = @()
            try { $deleted = @(Get-SPODeletedSite -IncludeOnlyPersonalSite -Limit All -ErrorAction Stop | Where-Object { [string]$_.Url -like "$expected*" }) } catch { Write-DiagInfo "Deleted-site check: $($_.Exception.Message)" -Level Dim }
            if ($deleted.Count -gt 0) {
                Add-DiagFinding -Severity Critical -Area $upn -Title "OneDrive was DELETED on $($deleted[0].DeletionTime) ($($deleted[0].DaysRemaining) days left to restore)" -Recommendation 'Restore with Restore-SPODeletedSite (a change) before it is purged.'
                $rows.Add([pscustomobject]@{ User = $upn; Status = 'Deleted'; Url = $deleted[0].Url; UsedGB = ''; QuotaGB = ''; UsedPct = ''; LockState = ''; Admins = '' })
            }
            else {
                Add-DiagFinding -Severity Warning -Area $upn -Title 'OneDrive is NOT provisioned' -Recommendation 'It is created when the user first opens OneDrive (license with SharePoint plan required). Admins can pre-provision with Request-SPOPersonalSite (a change). Check the license with Get-LicensingDiagnostics.ps1 (SHAREPOINTSTANDARD/ENTERPRISE plan must be Success).'
                $rows.Add([pscustomobject]@{ User = $upn; Status = 'Not provisioned'; Url = ''; UsedGB = ''; QuotaGB = ''; UsedPct = ''; LockState = ''; Admins = '' })
            }
            continue
        }
        $usedPct = if ($site.StorageQuota -gt 0) { [math]::Round(100 * [double]$site.StorageUsageCurrent / [double]$site.StorageQuota, 1) } else { $null }
        Add-DiagData -Section "$upn - OneDrive" -Data ($site | Select-DiagObject -Property Url, Owner, Status, LockState, LockIssue, StorageQuota, StorageUsageCurrent, StorageQuotaWarningLevel, LastContentModifiedDate, SharingCapability, ConditionalAccessPolicy, SensitivityLabel, Template)

        $script:odAdmins = @()
        Invoke-DiagStep -Name 'Site admins (who can access everything)' -Area $upn -ScriptBlock {
            $script:odAdmins = @(Get-SPOUser -Site $site.Url -Limit 500 -ErrorAction Stop | Where-Object IsSiteAdmin)
            Add-DiagData -Section "$upn - Admins" -Data @($script:odAdmins | Select-DiagObject -Property DisplayName, LoginName, IsGroup)
        } | Out-Null
        $admins = @($script:odAdmins)
        $others = @($admins | Where-Object { [string]$_.LoginName -notmatch [regex]::Escape($upn) })
        if ($others.Count -gt 0) { Add-DiagFinding -Severity Info -Area $upn -Title "$($others.Count) other admin(s) have full access to this OneDrive" -Detail ((@($others | ForEach-Object { $_.LoginName })) -join ', ') -Recommendation 'Expected for leaver access (manager) or eDiscovery; otherwise review.' }

        if ([string]$site.LockState -eq 'NoAccess') { Add-DiagFinding -Severity Critical -Area $upn -Title 'OneDrive is locked (NoAccess)' -Detail 'Typical after the user account is deleted/blocked, or retention processing.' }
        elseif ([string]$site.LockState -eq 'ReadOnly') { Add-DiagFinding -Severity Critical -Area $upn -Title 'OneDrive is read-only' -Detail "LockIssue: $($site.LockIssue)" }
        if ($usedPct -ge 98) { Add-DiagFinding -Severity Critical -Area $upn -Title "OneDrive is full ($usedPct%)" -Recommendation 'Sync stops and uploads fail. Empty the recycle bins / version history or raise the quota.' }
        elseif ($usedPct -ge 90) { Add-DiagFinding -Severity Warning -Area $upn -Title "OneDrive at $usedPct% of quota" }
        $rows.Add([pscustomobject]@{ User = $upn; Status = $site.Status; Url = $site.Url; UsedGB = [math]::Round($site.StorageUsageCurrent / 1024, 2); QuotaGB = [math]::Round($site.StorageQuota / 1024, 2); UsedPct = $usedPct; LockState = $site.LockState; Admins = $admins.Count })
    }
    Add-DiagData -Section 'Summary' -Data $rows.ToArray()
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
