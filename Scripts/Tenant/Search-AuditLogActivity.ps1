<#
.SYNOPSIS
    Searches the Microsoft 365 unified audit log ("who did what?") with ready-made presets: deleted files, inbox rule changes, mailbox permission changes, sharing, Teams membership, admin role changes.

.DESCRIPTION
    Uses Search-UnifiedAuditLog (read-only) and flattens the AuditData JSON into readable columns.
    Also checks whether audit ingestion is enabled for the tenant.

.PARAMETER Preset
    FileDeletion, InboxRules, MailboxPermissions, MailDeletion, Sharing, TeamsMembership, AdminRoles, SignIns, Custom.

.PARAMETER UserIds
    Limit to these users (UPNs). Prompted (optional) if omitted.

.PARAMETER Operations
    Custom operations list (used with -Preset Custom).

.PARAMETER Days
    How many days back to search (default 7, max 180 depending on license).

.PARAMETER MaxResults
    Stop after this many records (default 5000, max 50000).

.EXAMPLE
    .\Search-AuditLogActivity.ps1 -Preset InboxRules -UserIds jane@contoso.com -Days 30

.NOTES
    Connection : Exchange Online (Search-UnifiedAuditLog)
    Roles      : View-Only Audit Logs / Audit Logs role (e.g. Compliance Administrator, Security Reader may not be enough)
    Read-only  : Exchange session is restricted to Get-/Search- cmdlets.
#>
[CmdletBinding()]
param(
    [ValidateSet('FileDeletion', 'InboxRules', 'MailboxPermissions', 'MailDeletion', 'Sharing', 'TeamsMembership', 'AdminRoles', 'SignIns', 'Custom')]
    [string]$Preset,
    [string[]]$UserIds,
    [string[]]$Operations,
    [ValidateRange(1, 180)][int]$Days = 7,
    [ValidateRange(1, 50000)][int]$MaxResults = 5000,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

$presets = [ordered]@{
    FileDeletion       = @{ Label = 'Files deleted / recycled (SharePoint & OneDrive)'; Ops = @('FileDeleted', 'FileRecycled', 'FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin', 'FolderDeleted', 'FolderRecycled') }
    InboxRules         = @{ Label = 'Inbox rule & forwarding changes (compromise check)'; Ops = @('New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule', 'UpdateInboxRules', 'Set-Mailbox', 'Set-MailboxJunkEmailConfiguration') }
    MailboxPermissions = @{ Label = 'Mailbox / Send-As permission changes'; Ops = @('Add-MailboxPermission', 'Remove-MailboxPermission', 'Add-RecipientPermission', 'Remove-RecipientPermission', 'Add-MailboxFolderPermission', 'Set-MailboxFolderPermission', 'AddFolderPermissions', 'UpdateFolderPermissions') }
    MailDeletion       = @{ Label = 'Mail items deleted (mailbox auditing)'; Ops = @('SoftDelete', 'HardDelete', 'MoveToDeletedItems') }
    Sharing            = @{ Label = 'Sharing links & invitations'; Ops = @('SharingSet', 'SharingInvitationCreated', 'AnonymousLinkCreated', 'CompanyLinkCreated', 'SecureLinkCreated', 'AddedToSecureLink', 'SharingRevoked') }
    TeamsMembership    = @{ Label = 'Teams created/deleted & membership changes'; Ops = @('TeamCreated', 'TeamDeleted', 'MemberAdded', 'MemberRemoved', 'MemberRoleChanged', 'ChannelAdded', 'ChannelDeleted', 'TeamSettingChanged') }
    AdminRoles         = @{ Label = 'Admin role & app consent changes'; Ops = @('Add member to role.', 'Remove member from role.', 'Consent to application.', 'Add app role assignment grant to user.', 'Add delegated permission grant.', 'Add service principal.') }
    SignIns            = @{ Label = 'Sign-ins recorded in the audit log'; Ops = @('UserLoggedIn', 'UserLoginFailed') }
    Custom             = @{ Label = 'Custom operations list'; Ops = @() }
}

if (-not $Preset) {
    $opts = foreach ($k in $presets.Keys) { [pscustomobject]@{ Label = $presets[$k].Label; Value = $k } }
    $Preset = Read-DiagChoice -Prompt 'What do you want to investigate?' -Options $opts
}
if ($Preset -eq 'Custom' -and -not $Operations) {
    $Operations = @((Read-DiagValue -Prompt 'Operations (comma separated, e.g. FileDeleted,New-InboxRule)') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
if ($Preset -ne 'Custom') { $Operations = $presets[$Preset].Ops }
if (-not $PSBoundParameters.ContainsKey('UserIds')) {
    $u = Read-DiagValue -Prompt 'Limit to user(s) - UPNs comma separated' -Optional
    if ($u) { $UserIds = @($u -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
}
if (-not $PSBoundParameters.ContainsKey('Days')) { $Days = [int](Read-DiagValue -Prompt 'Days back to search' -Default '7' -Pattern '^\d{1,3}$') }

$params = [ordered]@{ Preset = $Preset; Operations = ($Operations -join ', '); UserIds = ($UserIds -join ', '); Days = $Days; MaxResults = $MaxResults }
Start-DiagRun -Name 'Search-AuditLogActivity' -Title "Unified Audit Log - $($presets[$Preset].Label)" -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $params
try {
    Connect-DiagExchange -CommandName 'Search-UnifiedAuditLog', 'Get-AdminAuditLogConfig'

    Invoke-DiagStep -Name 'Audit ingestion status' -Area 'Audit' -ScriptBlock {
        $cfg = Get-AdminAuditLogConfig -ErrorAction Stop
        Add-DiagData -Section 'Audit configuration' -Data ($cfg | Select-DiagObject -Property UnifiedAuditLogIngestionEnabled, UnifiedAuditLogFirstOptInDate, AdminAuditLogEnabled, AdminAuditLogAgeLimit)
        if ($cfg.UnifiedAuditLogIngestionEnabled -eq $false) {
            Add-DiagFinding -Severity Critical -Area 'Audit' -Title 'Unified audit log ingestion is DISABLED' -Recommendation 'No audit records are being collected. Enable auditing in the Purview portal (requires a change by an admin).'
        }
    } | Out-Null

    $end = (Get-Date).ToUniversalTime()
    $start = $end.AddDays(-$Days)
    $records = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    Invoke-DiagStep -Name "Searching audit log $($start.ToString('yyyy-MM-dd')) .. $($end.ToString('yyyy-MM-dd')) UTC" -Area 'Audit' -ScriptBlock {
        $sessionId = [guid]::NewGuid().ToString()
        $p = @{ StartDate = $start; EndDate = $end; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($Operations) { $p['Operations'] = $Operations }
        if ($UserIds) { $p['UserIds'] = $UserIds }
        $page = 0
        while ($records.Count -lt $MaxResults) {
            $page++
            $batch = @(Search-UnifiedAuditLog @p)
            if ($batch.Count -eq 0) { break }
            $new = 0
            foreach ($r in $batch) { if ($seen.Add([string]$r.Identity)) { $records.Add($r); $new++ } }
            Write-DiagInfo "page $page : $($records.Count) of $($batch[0].ResultCount) record(s)" -Level Dim
            if ($new -eq 0 -or $records.Count -ge [int]$batch[0].ResultCount) { break }
        }
    } | Out-Null

    $rows = foreach ($r in ($records | Select-Object -First $MaxResults)) {
        $a = $null
        try { $a = $r.AuditData | ConvertFrom-Json } catch { $a = $null }
        $target = $null
        if ($a) {
            $target = $a.ObjectId
            if (-not $target -and $a.Parameters) { $target = (@($a.Parameters | Where-Object { $_.Name -eq 'Identity' }) | Select-Object -First 1).Value }
            if (-not $target -and $a.Item) { $target = $a.Item.Subject }
        }
        $paramText = ''
        if ($a -and $a.Parameters) { $paramText = (@($a.Parameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ') }
        [pscustomobject]@{
            TimeUtc    = (ConvertTo-DiagDate $r.CreationDate)
            Operation  = $r.Operations
            User       = $r.UserIds
            Workload   = if ($a) { $a.Workload } else { $r.RecordType }
            Result     = if ($a) { $a.ResultStatus } else { '' }
            ClientIP   = if ($a) { $a.ClientIP } else { '' }
            Target     = $target
            Site       = if ($a) { $a.SiteUrl } else { '' }
            Parameters = $paramText
            UserAgent  = if ($a) { $a.UserAgent } else { '' }
            RecordType = $r.RecordType
        }
    }
    $rows = @($rows | Sort-Object TimeUtc -Descending)
    Add-DiagData -Section 'Audit records' -Data $rows -Description 'Most recent first. Full AuditData was flattened; Parameters shows cmdlet parameters for admin/mailbox operations.'
    $byOp = @($rows | Group-Object Operation | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Operation = $_.Name; Count = $_.Count; Users = (@($_.Group.User | Select-Object -Unique) -join ', ') } })
    Add-DiagData -Section 'Summary by operation' -Data $byOp
    $byUser = @($rows | Group-Object User | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object { [pscustomobject]@{ User = $_.Name; Count = $_.Count; Operations = (@($_.Group.Operation | Select-Object -Unique) -join ', ') } })
    Add-DiagData -Section 'Summary by user' -Data $byUser

    if ($rows.Count -eq 0) {
        Add-DiagFinding -Severity Info -Area 'Audit' -Title 'No matching audit records' -Recommendation 'Widen the date range / remove the user filter. Audit records can take 30 min to 24 h to appear; mailbox auditing must be on for mail item actions.'
    }
    else {
        Add-DiagFinding -Severity Info -Area 'Audit' -Title "$($rows.Count) audit record(s) found" -Quiet
        if ($records.Count -ge $MaxResults) { Add-DiagFinding -Severity Warning -Area 'Audit' -Title "Result limit of $MaxResults reached - output is truncated" -Recommendation 'Narrow the date range or user filter.' }
    }

    # Compromise heuristics for inbox rule changes
    if ($Preset -eq 'InboxRules') {
        foreach ($r in @($rows | Where-Object { $_.Parameters -match 'ForwardTo|RedirectTo|ForwardAsAttachmentTo|ForwardingSmtpAddress|DeleteMessage=True' })) {
            Add-DiagFinding -Severity Warning -Area 'Audit' -Title "$($r.Operation) by $($r.User) at $($r.TimeUtc) sets forwarding/deletion" -Detail $r.Parameters -Recommendation 'Verify with the user. Forward/delete rules created from unfamiliar IPs are a classic sign of account compromise.'
        }
    }
    if ($Preset -eq 'FileDeletion') {
        $mass = @($rows | Group-Object User | Where-Object { $_.Count -ge 200 })
        foreach ($m in $mass) { Add-DiagFinding -Severity Warning -Area 'Audit' -Title "$($m.Name) deleted $($m.Count) items in the period" -Recommendation 'Possible mass deletion (sync client, user error or ransomware). Restore from the site/OneDrive recycle bin or "Restore your OneDrive".' }
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
