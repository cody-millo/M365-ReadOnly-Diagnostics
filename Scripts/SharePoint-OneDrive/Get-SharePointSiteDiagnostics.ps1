<#
.SYNOPSIS
    SharePoint site diagnostics: lock state (read-only/no access), storage vs quota, sharing settings, group/hub/template, sensitivity label, archive state, site admins and SharePoint groups - and the recycle bin if the site is missing.

.DESCRIPTION
    Typical tickets: "site is read-only", "access denied for everyone", "can't share externally",
    "site storage full", "site disappeared", "who owns this site?".

.PARAMETER SiteUrl
    Full site URL (https://contoso.sharepoint.com/sites/Finance). Prompted if omitted.

.EXAMPLE
    .\Get-SharePointSiteDiagnostics.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Finance

.NOTES
    Connection : SharePoint Online Management Shell (Connect-SPOService)
    Roles      : SharePoint Administrator (Global Reader is not supported by the SPO shell)
    Read-only  : Only Get-SPO* cmdlets are called.
#>
[CmdletBinding()]
param(
    [string]$SiteUrl,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $SiteUrl) { $SiteUrl = Read-DiagValue -Prompt 'Site URL (https://tenant.sharepoint.com/sites/name)' -Pattern '^https://[^/]+\.sharepoint\.[a-z]+(/.*)?$' -PatternHint 'Enter the full https://... sharepoint URL' }
$SiteUrl = $SiteUrl.TrimEnd('/')

Start-DiagRun -Name 'Get-SharePointSiteDiagnostics' -Title 'SharePoint Online - Site Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ SiteUrl = $SiteUrl })
try {
    $spo = Connect-DiagSharePoint -TenantName $SiteUrl

    $site = Invoke-DiagStep -Name 'Site properties' -Area 'Site' -ScriptBlock {
        try { Get-SPOSite -Identity $SiteUrl -Detailed -WarningAction SilentlyContinue -ErrorAction Stop }
        catch { if ($_.Exception.Message -match 'parameter') { Get-SPOSite -Identity $SiteUrl -ErrorAction Stop } else { throw } }
    }
    if (-not $site) {
        Invoke-DiagStep -Name 'Checking the site recycle bin' -Area 'Site' -ScriptBlock {
            $del = @(Get-SPODeletedSite -Identity $SiteUrl -ErrorAction Stop)
            if ($del.Count -gt 0) {
                Add-DiagData -Section 'Deleted site' -Data @($del | Select-DiagObject -Property Url, DeletionTime, DaysRemaining, Status, StorageQuota)
                Add-DiagFinding -Severity Critical -Area 'Site' -Title "Site is in the SharePoint recycle bin (deleted $($del[0].DeletionTime), $($del[0].DaysRemaining) days left)" -Recommendation 'Restore from Admin center > Sites > Deleted sites (or restore the Microsoft 365 group if group-connected).'
            }
        } | Out-Null
        throw "Site '$SiteUrl' not found (also check spelling / redirect sites)."
    }

    Register-DiagSensitiveValue -Value ([string]$site.Title) -Category name
    Add-DiagData -Section 'Site' -Data ($site | Select-DiagObject -Property Url, Title, Template, Status, LockState, LockIssue, Owner, GroupId, RelatedGroupId, IsHubSite, HubSiteId, IsTeamsConnected, IsTeamsChannelConnected, TeamsChannelType,
        StorageQuota, StorageUsageCurrent, StorageQuotaWarningLevel, StorageQuotaType, ResourceQuota, LastContentModifiedDate, WebsCount, LocaleId,
        SharingCapability, SiteDefinedSharingCapability, DisableSharingForNonOwnersStatus, DefaultSharingLinkType, DefaultLinkPermission, DefaultLinkToExistingAccess, AnonymousLinkExpirationInDays, ExternalUserExpirationInDays, OverrideTenantAnonymousLinkExpirationPolicy, SharingDomainRestrictionMode, SharingAllowedDomainList, SharingBlockedDomainList,
        ConditionalAccessPolicy, AllowDownloadingNonWebViewableFiles, LimitedAccessFileType, SensitivityLabel, RestrictedAccessControl, RestrictedAccessControlGroups, DenyAddAndCustomizePages, ArchiveState, LockReason, InformationSegmentMode, BlockDownloadPolicy, ExcludeBlockDownloadPolicySiteOwners, VersionPolicyFileTypeOverride, EnableAutoExpirationVersionTrim, MajorVersionLimit)

    # Lock & status
    switch ([string]$site.LockState) {
        'NoAccess' { Add-DiagFinding -Severity Critical -Area 'Site' -Title 'Site is LOCKED - NoAccess (everyone gets access denied / redirected)' -Detail "LockIssue: $($site.LockIssue)" -Recommendation 'Set by an admin, by retention/legal processes or by tenant NoAccessRedirectUrl. Unlock only after confirming why it was locked.' }
        'ReadOnly' { Add-DiagFinding -Severity Critical -Area 'Site' -Title 'Site is LOCKED - ReadOnly' -Detail "LockIssue: $($site.LockIssue)" -Recommendation 'Common causes: storage quota exceeded, admin lock, or the site is being moved/archived.' }
        'Unlock' { Add-DiagFinding -Severity OK -Area 'Site' -Title 'Site is not locked' -Quiet }
    }
    if ($site.PSObject.Properties['ArchiveState'] -and $site.ArchiveState -and $site.ArchiveState -ne 'NotArchived') { Add-DiagFinding -Severity Warning -Area 'Site' -Title "Site is in Microsoft 365 Archive state: $($site.ArchiveState)" -Detail 'Archived sites are inaccessible to users until reactivated.' }
    if ($site.Status -and $site.Status -ne 'Active') { Add-DiagFinding -Severity Warning -Area 'Site' -Title "Site status is $($site.Status)" }

    # Storage
    if ($site.StorageQuota -gt 0) {
        $pct = [math]::Round(100 * [double]$site.StorageUsageCurrent / [double]$site.StorageQuota, 1)
        Add-DiagData -Section 'Storage' -Data ([ordered]@{ UsedMB = $site.StorageUsageCurrent; QuotaMB = $site.StorageQuota; UsedPercent = $pct; WarningLevelMB = $site.StorageQuotaWarningLevel; QuotaType = $site.StorageQuotaType })
        if ($pct -ge 100) { Add-DiagFinding -Severity Critical -Area 'Storage' -Title "Site storage is FULL ($pct%)" -Recommendation 'Uploads/edits fail and the site may become read-only. Increase quota, clean up versions/recycle bin, or enable version trimming.' }
        elseif ($pct -ge 90) { Add-DiagFinding -Severity Warning -Area 'Storage' -Title "Site storage at $pct% of quota" }
    }

    # Sharing
    $sh = [string]$site.SharingCapability
    $shText = @{ Disabled = 'internal only'; ExistingExternalUserSharingOnly = 'existing guests only'; ExternalUserSharingOnly = 'new and existing guests (sign-in required)'; ExternalUserAndGuestSharing = 'anyone links allowed' }[$sh]
    Add-DiagFinding -Severity Info -Area 'Sharing' -Title "Site sharing: $sh ($shText)" -Detail 'Site sharing can never be more permissive than the tenant setting (Get-SharePointTenantSettings.ps1).' -Quiet
    if ($sh -eq 'Disabled') { Add-DiagFinding -Severity Info -Area 'Sharing' -Title 'External sharing is disabled for this site' -Detail 'Explains "Share" only offering internal people / guests losing access.' }
    if ($site.DisableSharingForNonOwnersStatus) { Add-DiagFinding -Severity Info -Area 'Sharing' -Title 'Only site owners can share (members cannot)' }
    if ($site.SharingDomainRestrictionMode -and $site.SharingDomainRestrictionMode -ne 'None') { Add-DiagFinding -Severity Info -Area 'Sharing' -Title "Sharing is domain-restricted ($($site.SharingDomainRestrictionMode))" -Detail "Allowed: $($site.SharingAllowedDomainList)  Blocked: $($site.SharingBlockedDomainList)" }
    if ($site.ConditionalAccessPolicy -and $site.ConditionalAccessPolicy -ne 'AllowFullAccess') { Add-DiagFinding -Severity Info -Area 'Access' -Title "Unmanaged device access is limited ($($site.ConditionalAccessPolicy))" -Detail 'Users on personal devices get browser-only/no-download access or are blocked.' }
    if ($site.PSObject.Properties['RestrictedAccessControl'] -and $site.RestrictedAccessControl) { Add-DiagFinding -Severity Info -Area 'Access' -Title 'Restricted Access Control is ON for this site' -Detail 'Only members of the configured groups can access, regardless of sharing.' }
    if ($site.SensitivityLabel) { Add-DiagFinding -Severity Info -Area 'Access' -Title "Sensitivity label applied ($($site.SensitivityLabel))" -Detail 'Labels can enforce privacy, external sharing and unmanaged device restrictions.' -Quiet }
    if ($site.GroupId -and [string]$site.GroupId -ne '00000000-0000-0000-0000-000000000000') { Add-DiagFinding -Severity Info -Area 'Site' -Title 'Site is connected to a Microsoft 365 group' -Detail 'Membership is managed through the group/team, not SharePoint groups. Deleting the group deletes the site.' -Quiet }

    # Admins and groups
    Invoke-DiagStep -Name 'Site collection admins & users' -Area 'Permissions' -ScriptBlock {
        $users = @(Get-SPOUser -Site $SiteUrl -Limit 5000 -ErrorAction Stop)
        $admins = @($users | Where-Object IsSiteAdmin)
        Add-DiagData -Section 'Site collection admins' -Data @($admins | Select-DiagObject -Property DisplayName, LoginName, IsGroup, UserType)
        $ext = @($users | Where-Object { $_.LoginName -match '#ext#|urn%3aspo%3aguest' })
        Add-DiagData -Section 'User summary' -Data ([ordered]@{ UsersInSite = $users.Count; SiteAdmins = $admins.Count; ExternalUsers = $ext.Count })
        if ($admins.Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Permissions' -Title 'No site collection admins listed' }
        if ($ext.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Permissions' -Title "$($ext.Count) external user(s) have been granted access" -Quiet }
    } | Out-Null
    Invoke-DiagStep -Name 'SharePoint groups' -Area 'Permissions' -ScriptBlock {
        $groups = @(Get-SPOSiteGroup -Site $SiteUrl -Limit 200 -ErrorAction Stop)
        Add-DiagData -Section 'SharePoint groups' -Data @($groups | ForEach-Object { [pscustomobject]@{ Group = $_.Title; Roles = (@($_.Roles) -join ', '); Members = @($_.Users).Count; Owner = $_.OwnerTitle } })
    } | Out-Null

    if ($site.HubSiteId -and [string]$site.HubSiteId -ne '00000000-0000-0000-0000-000000000000') {
        Invoke-DiagStep -Name 'Hub association' -Area 'Hub' -ScriptBlock {
            $hub = Get-SPOHubSite -Identity $site.HubSiteId -ErrorAction Stop
            Add-DiagData -Section 'Hub site' -Data ($hub | Select-DiagObject -Property Title, SiteUrl, ID, ParentHubSiteId, RequiresJoinApproval)
        } | Out-Null
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
