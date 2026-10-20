<#
.SYNOPSIS
    SharePoint/OneDrive tenant settings: external sharing levels, default links, unmanaged-device and legacy-auth access, sync client restrictions, storage pool usage, locked/near-quota sites and hub sites.

.DESCRIPTION
    Typical tickets: "nobody can share externally", "anyone links missing", "sync client blocked on this PC/domain",
    "file type won't sync", "tenant storage full", plus a quick scan for locked or nearly full sites.

.PARAMETER SkipSiteScan
    Skip the scan of all site collections (faster on very large tenants).

.EXAMPLE
    .\Get-SharePointTenantSettings.ps1

.NOTES
    Connection : SharePoint Online Management Shell (Connect-SPOService)
    Roles      : SharePoint Administrator
    Read-only  : Only Get-SPO* cmdlets are called.
#>
[CmdletBinding()]
param(
    [string]$TenantName,
    [switch]$SkipSiteScan,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

Start-DiagRun -Name 'Get-SharePointTenantSettings' -Title 'SharePoint Online - Tenant Settings' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
try {
    $spo = Connect-DiagSharePoint -TenantName $TenantName

    $t = Invoke-DiagStep -Name 'Tenant settings' -Area 'Tenant' -ScriptBlock { Get-SPOTenant -ErrorAction Stop }
    if (-not $t) { throw 'Could not read tenant settings (SharePoint Administrator role required).' }
    Add-DiagData -Section 'Sharing settings' -Data ($t | Select-DiagObject -Property SharingCapability, OneDriveSharingCapability, DefaultSharingLinkType, DefaultLinkPermission, FileAnonymousLinkType, FolderAnonymousLinkType, RequireAnonymousLinksExpireInDays, ExternalUserExpirationRequired, ExternalUserExpireInDays,
        SharingDomainRestrictionMode, SharingAllowedDomainList, SharingBlockedDomainList, PreventExternalUsersFromResharing, RequireAcceptingAccountMatchInvitedAccount, ShowEveryoneClaim, ShowEveryoneExceptExternalUsersClaim, ShowAllUsersClaim, EnableAzureADB2BIntegration, EmailAttestationRequired, EmailAttestationReAuthDays, CoreSharingCapability)
    Add-DiagData -Section 'Access control' -Data ($t | Select-DiagObject -Property ConditionalAccessPolicy, AllowDownloadingNonWebViewableFiles, LimitedAccessFileType, LegacyAuthProtocolsEnabled, LegacyBrowserAuthProtocolsEnabled, BlockAccessOnUnmanagedDevices, IPAddressEnforcement, IPAddressAllowList, BrowserIdleSignout, DisableCustomAppAuthentication, SignInAccelerationDomain, EnableRestrictedAccessControl, NoAccessRedirectUrl, DelayDenyAddAndCustomizePagesEnforcement, DenyAddAndCustomizePages, CommentsOnFilesDisabled)
    Add-DiagData -Section 'Storage & OneDrive' -Data ($t | Select-DiagObject -Property StorageQuota, StorageQuotaAllocated, ResourceQuota, OneDriveStorageQuota, OrphanedPersonalSitesRetentionPeriod, OneDriveForGuestsEnabled, EnableAutoExpirationVersionTrim, MajorVersionLimit, ExpireVersionsAfterDays, ArchiveRedirectUrl, MarkNewFilesSensitiveByDefault)

    $lvl = @{ Disabled = 0; ExistingExternalUserSharingOnly = 1; ExternalUserSharingOnly = 2; ExternalUserAndGuestSharing = 3 }
    if ([string]$t.SharingCapability -eq 'Disabled') { Add-DiagFinding -Severity Warning -Area 'Sharing' -Title 'External sharing is DISABLED for SharePoint (tenant-wide)' -Detail 'No site or OneDrive can share outside the organization.' }
    elseif ([string]$t.SharingCapability -eq 'ExternalUserAndGuestSharing') { Add-DiagFinding -Severity Info -Area 'Sharing' -Title 'Anyone (anonymous) links are allowed tenant-wide' -Detail "Expiry: $($t.RequireAnonymousLinksExpireInDays) days (-1/0 = never)." }
    if ($lvl[[string]$t.OneDriveSharingCapability] -gt $lvl[[string]$t.SharingCapability]) { Add-DiagFinding -Severity Info -Area 'Sharing' -Title 'OneDrive sharing level is higher than SharePoint (capped by the SharePoint level)' -Quiet }
    if ($t.SharingDomainRestrictionMode -and [string]$t.SharingDomainRestrictionMode -ne 'None') { Add-DiagFinding -Severity Info -Area 'Sharing' -Title "External sharing is domain-restricted ($($t.SharingDomainRestrictionMode))" -Detail "Allowed: $($t.SharingAllowedDomainList)  Blocked: $($t.SharingBlockedDomainList)" -Recommendation 'Explains "can share with partner A but not partner B".' }
    if ($t.RequireAcceptingAccountMatchInvitedAccount) { Add-DiagFinding -Severity Info -Area 'Sharing' -Title 'Guests must sign in with the exact invited account' -Detail 'Guests redeeming with a different email get "access denied".' -Quiet }
    if ($t.LegacyAuthProtocolsEnabled) { Add-DiagFinding -Severity Warning -Area 'Access' -Title 'Legacy authentication protocols are ENABLED for SharePoint' -Recommendation 'Allows apps that cannot do modern auth (and bypass MFA/CA). Disable unless a specific legacy app still needs it.' }
    if ([string]$t.ConditionalAccessPolicy -ne 'AllowFullAccess') { Add-DiagFinding -Severity Info -Area 'Access' -Title "Unmanaged device access: $($t.ConditionalAccessPolicy)" -Detail 'Users on personal devices get limited (web-only) or no access.' }
    if ($t.IPAddressEnforcement) { Add-DiagFinding -Severity Warning -Area 'Access' -Title 'Network location (IP) restriction is ON for SharePoint/OneDrive' -Detail "Allowed: $($t.IPAddressAllowList)" -Recommendation 'Users outside these IP ranges (home, VPN split tunnel) are blocked.' }
    if ($t.NoAccessRedirectUrl) { Add-DiagFinding -Severity Info -Area 'Access' -Title 'NoAccess redirect URL configured' -Detail 'Users hitting NoAccess-locked sites are redirected - can look like "site redirects somewhere else".' }
    if ($t.StorageQuota -gt 0) {
        $usedMb = $null
        try { $usedMb = (@(Get-SPOSite -Limit All -ErrorAction Stop) | Measure-Object -Property StorageUsageCurrent -Sum).Sum } catch { $usedMb = $null }
        if ($usedMb) {
            $pct = [math]::Round(100 * $usedMb / $t.StorageQuota, 1)
            Add-DiagData -Section 'Tenant storage' -Data ([ordered]@{ QuotaGB = [math]::Round($t.StorageQuota / 1024, 1); UsedGB = [math]::Round($usedMb / 1024, 1); UsedPercent = $pct; Note = 'Used = sum of SharePoint site usage (excludes OneDrive).' })
            if ($pct -ge 95) { Add-DiagFinding -Severity Critical -Area 'Storage' -Title "Tenant SharePoint storage at $pct%" -Recommendation 'At 100% sites become read-only. Buy storage, enable version trimming, or archive inactive sites.' }
            elseif ($pct -ge 85) { Add-DiagFinding -Severity Warning -Area 'Storage' -Title "Tenant SharePoint storage at $pct%" }
        }
    }

    Invoke-DiagStep -Name 'Sync client restrictions' -Area 'Sync' -ScriptBlock {
        $s = Get-SPOTenantSyncClientRestriction -ErrorAction Stop
        Add-DiagData -Section 'Sync client restrictions' -Data ($s | Select-DiagObject -Property TenantRestrictionEnabled, AllowedDomainList, BlockMacSync, DisableReportProblemDialog, ExcludedFileExtensions, OptOutOfGrooveBlock, OptOutOfGrooveSoftBlock)
        if ($s.TenantRestrictionEnabled) { Add-DiagFinding -Severity Warning -Area 'Sync' -Title 'OneDrive sync is restricted to PCs joined to specific AD domains' -Detail "AllowedDomainList: $($s.AllowedDomainList)" -Recommendation 'Non-domain-joined/Entra-only PCs cannot sync.' }
        if (@($s.ExcludedFileExtensions).Count -gt 0 -and [string]$s.ExcludedFileExtensions) { Add-DiagFinding -Severity Info -Area 'Sync' -Title "File types blocked from sync: $(@($s.ExcludedFileExtensions) -join ', ')" }
        if ($s.BlockMacSync) { Add-DiagFinding -Severity Info -Area 'Sync' -Title 'OneDrive sync on macOS is blocked' }
    } | Out-Null

    if (-not $SkipSiteScan) {
        Invoke-DiagStep -Name 'Scanning sites for locks and quota' -Area 'Sites' -ScriptBlock {
            $sites = @(Get-SPOSite -Limit All -ErrorAction Stop)
            $locked = @($sites | Where-Object { [string]$_.LockState -ne 'Unlock' })
            $near = @($sites | Where-Object { $_.StorageQuota -gt 0 -and ($_.StorageUsageCurrent / $_.StorageQuota) -ge 0.9 })
            Add-DiagData -Section 'Locked sites' -Data @($locked | Select-DiagObject -Property Url, LockState, LockIssue, Template, Owner)
            Add-DiagData -Section 'Sites at 90%+ of quota' -Data @($near | ForEach-Object { [pscustomobject]@{ Url = $_.Url; UsedMB = $_.StorageUsageCurrent; QuotaMB = $_.StorageQuota; UsedPct = [math]::Round(100 * $_.StorageUsageCurrent / $_.StorageQuota, 1) } })
            Add-DiagData -Section 'Largest sites (top 25)' -Data @($sites | Sort-Object StorageUsageCurrent -Descending | Select-Object -First 25 | Select-DiagObject -Property Url, StorageUsageCurrent, StorageQuota, Template, LastContentModifiedDate)
            Add-DiagFinding -Severity Info -Area 'Sites' -Title "$($sites.Count) site collections scanned" -Quiet
            if ($locked.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Sites' -Title "$($locked.Count) site(s) are locked (ReadOnly/NoAccess)" }
            if ($near.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Sites' -Title "$($near.Count) site(s) are at 90%+ of their storage quota" }
        } | Out-Null
    }

    Invoke-DiagStep -Name 'Hub sites' -Area 'Hubs' -ScriptBlock {
        Add-DiagData -Section 'Hub sites' -Data @(Get-SPOHubSite -ErrorAction Stop | Select-DiagObject -Property Title, SiteUrl, ID, ParentHubSiteId, RequiresJoinApproval)
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
