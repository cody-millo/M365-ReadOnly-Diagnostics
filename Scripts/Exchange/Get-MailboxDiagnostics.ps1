<#
.SYNOPSIS
    Mailbox health: type/licensing, size vs quota, Recoverable Items, holds, archive, forwarding, inbox rules (incl. hidden), delegates/permissions, protocols, mobile devices, auto-reply and migration state. Single mailbox or bulk (CSV/TXT picker).

.DESCRIPTION
    Covers the common tickets: "mailbox full / can't send", "can't delete items", "mail disappears/forwards",
    "Outlook can't connect", "delegate can't open mailbox", "phone not syncing", "mailbox missing after migration",
    and quick compromise checks (external forwarding, suspicious rules).
    Bulk mode (multiple identities) runs the key checks per mailbox and outputs a summary table.

.PARAMETER Identity
    One or more mailboxes (UPN/SMTP). Prompted if omitted (type F to pick a CSV/TXT file).

.PARAMETER Detailed
    In bulk mode, also collect folder statistics/permissions/devices for every mailbox (slower).

.EXAMPLE
    .\Get-MailboxDiagnostics.ps1 -Identity jane@contoso.com

.NOTES
    Connection : Exchange Online
    Roles      : Global Reader or View-Only Organization Management
    Read-only  : Exchange session restricted to the Get- cmdlets listed in the script.
#>
[CmdletBinding()]
param(
    [string[]]$Identity,
    [switch]$Detailed,
    [string]$UserPrincipalName,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Identity) { $Identity = Read-DiagIdentityList -Prompt 'Mailbox(es) (UPN or email)' }
$bulk = @($Identity).Count -gt 1
$full = (-not $bulk) -or $Detailed

Start-DiagRun -Name 'Get-MailboxDiagnostics' -Title 'Exchange Online - Mailbox Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Identity = ($Identity -join ', '); Count = @($Identity).Count; Detailed = [bool]$full })
$commands = 'Get-Mailbox', 'Get-MailboxStatistics', 'Get-MailboxFolderStatistics', 'Get-CASMailbox', 'Get-InboxRule', 'Get-MailboxPermission',
'Get-RecipientPermission', 'Get-Recipient', 'Get-User', 'Get-MailboxAutoReplyConfiguration', 'Get-MailboxJunkEmailConfiguration',
'Get-MobileDeviceStatistics', 'Get-MoveRequest', 'Get-MoveRequestStatistics', 'Get-MailboxFolderPermission', 'Get-RemoteDomain', 'Get-HostedOutboundSpamFilterPolicy'

function Get-HoldText {
    param([string]$Hold)
    switch -Regex ($Hold) {
        '^UniH' { 'eDiscovery case hold' }
        '^mbx' { 'Microsoft 365 retention policy (Exchange-specific)' }
        '^skp' { 'Retention policy (Skype/Teams)' }
        '^cld' { 'Retention policy (cloud / group)' }
        '^-' { 'Excluded from org-wide retention policy' }
        default { 'In-Place Hold / retention policy' }
    }
}

try {
    Connect-DiagExchange -CommandName $commands -UserPrincipalName $UserPrincipalName
    $internal = @(Get-AcceptedDomain | ForEach-Object { [string]$_.DomainName })
    $summary = New-Object System.Collections.Generic.List[object]

    # Tenant forwarding controls (explains whether external forwarding actually works)
    $fwdPolicy = Invoke-DiagStep -Name 'Tenant external forwarding controls' -Area 'Tenant' -ScriptBlock {
        $out = Get-HostedOutboundSpamFilterPolicy | Select-DiagObject -Property Name, IsDefault, AutoForwardingMode
        $rd = Get-RemoteDomain -Identity Default | Select-DiagObject -Property DomainName, AutoForwardEnabled, AllowedOOFType
        [pscustomobject]@{ OutboundPolicies = @($out); DefaultRemoteDomain = $rd }
    }
    if ($fwdPolicy) { Add-DiagData -Section 'Tenant forwarding controls' -Data $fwdPolicy -Description 'AutoForwardingMode Automatic/Off blocks external forwarding (NDR 5.7.520) unless a custom policy allows it.' }

    $n = 0
    foreach ($id in $Identity) {
        $n++
        Write-DiagInfo "[$n/$(@($Identity).Count)] $id" -Level Header
        $row = [ordered]@{ Identity = $id; Type = ''; Licensed = ''; SizeGB = ''; QuotaUsedPct = ''; RecoverableGB = ''; Archive = ''; Holds = ''; Forwarding = ''; ExternalRuleForwards = 0 }
        $script:calendarPath = $null

        $mbx = Invoke-DiagStep -Name 'Mailbox' -Area $id -ScriptBlock { Get-Mailbox -Identity $id -ErrorAction Stop }
        if (-not $mbx) {
            $rcp = Invoke-DiagStep -Name 'Recipient lookup (no mailbox found)' -Area $id -ScriptBlock { Get-Recipient -Identity $id -ErrorAction Stop }
            if ($rcp) {
                Add-DiagData -Section "$id - Recipient" -Data ($rcp | Select-DiagObject -Property DisplayName, RecipientType, RecipientTypeDetails, PrimarySmtpAddress, ExternalEmailAddress, WhenCreated)
                Add-DiagFinding -Severity Critical -Area $id -Title "No Exchange Online mailbox - object is a $($rcp.RecipientTypeDetails)" -Recommendation 'MailUser = mailbox still on-premises (hybrid) or license not applied yet; check license, migration batches and Get-LicensingDiagnostics.ps1.'
                $row.Type = [string]$rcp.RecipientTypeDetails
            }
            $summary.Add([pscustomobject]$row)
            continue
        }
        $upn = [string]$mbx.UserPrincipalName
        Register-DiagSensitiveValue -Value ([string]$mbx.DisplayName) -Category name
        Register-DiagSensitiveValue -Value ([string]$mbx.Alias) -Category name
        $row.Type = [string]$mbx.RecipientTypeDetails

        Add-DiagData -Section "$id - Mailbox" -Data ($mbx | Select-DiagObject -Property DisplayName, UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, WhenMailboxCreated, IsMailboxEnabled, AccountDisabled, SKUAssigned, UsageLocation,
            HiddenFromAddressListsEnabled, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, GrantSendOnBehalfTo, MessageCopyForSentAsEnabled, MessageCopyForSendOnBehalfEnabled,
            ProhibitSendQuota, ProhibitSendReceiveQuota, IssueWarningQuota, RecoverableItemsQuota, RecoverableItemsWarningQuota, MaxSendSize, MaxReceiveSize,
            LitigationHoldEnabled, LitigationHoldDuration, InPlaceHolds, ComplianceTagHoldApplied, DelayHoldApplied, DelayReleaseHoldApplied, RetentionHoldEnabled, ElcProcessingDisabled, RetentionPolicy, SingleItemRecoveryEnabled, RetainDeletedItemsFor,
            ArchiveStatus, ArchiveState, AutoExpandingArchiveEnabled, ArchiveQuota, AuditEnabled, EmailAddresses, ExchangeGuid, ExternalDirectoryObjectId)

        # Licensing / state
        if ($mbx.RecipientTypeDetails -eq 'UserMailbox' -and $mbx.PSObject.Properties['SKUAssigned'] -and $mbx.SKUAssigned -eq $false) {
            Add-DiagFinding -Severity Critical -Area $id -Title 'User mailbox has no Exchange license (SKUAssigned = False)' -Recommendation 'Unlicensed mailboxes are disabled after the 30-day grace period. Assign a license, or convert to shared mailbox (if < 50 GB, no archive/hold).'
            $row.Licensed = 'No'
        }
        elseif ($mbx.PSObject.Properties['SKUAssigned']) { $row.Licensed = [string]$mbx.SKUAssigned }
        if ($mbx.AccountDisabled -and $mbx.RecipientTypeDetails -eq 'UserMailbox') { Add-DiagFinding -Severity Warning -Area $id -Title 'Account is disabled but mailbox type is UserMailbox' -Recommendation 'If this is a leaver, consider shared mailbox conversion; if not, re-enable the account.' }
        if ($mbx.HiddenFromAddressListsEnabled) { Add-DiagFinding -Severity Info -Area $id -Title 'Mailbox is hidden from address lists (GAL)' -Detail 'Explains "cannot find user in the address book".' }

        # Forwarding
        $fwd = @($mbx.ForwardingSmtpAddress, $mbx.ForwardingAddress) | Where-Object { $_ }
        if ($fwd) {
            $row.Forwarding = ($fwd -join ', ')
            $ext = @(Get-DiagEmailAddress -Value $mbx.ForwardingSmtpAddress | Where-Object { Test-DiagExternalAddress -Address $_ -InternalDomains $internal })
            $keep = if ($mbx.DeliverToMailboxAndForward) { 'copy kept in mailbox' } else { 'NO copy kept in mailbox' }
            if ($ext.Count -gt 0) { Add-DiagFinding -Severity Critical -Area $id -Title "Mailbox forwards externally to $($ext -join ', ') ($keep)" -Recommendation 'Confirm this is intended. Unexpected external forwarding is a top indicator of compromise; it is also blocked by the default outbound policy (NDR 5.7.520).' }
            else { Add-DiagFinding -Severity Warning -Area $id -Title "Mailbox forwarding is set: $($fwd -join ', ') ($keep)" }
        }

        # Statistics & quota
        $stats = Invoke-DiagStep -Name 'Mailbox size and quota' -Area $id -ScriptBlock { Get-MailboxStatistics -Identity $upn -ErrorAction Stop }
        if ($stats) {
            $size = ConvertTo-DiagBytes $stats.TotalItemSize
            $del = ConvertTo-DiagBytes $stats.TotalDeletedItemSize
            $quota = ConvertTo-DiagBytes $mbx.ProhibitSendQuota
            $pct = if ($size -and $quota) { [math]::Round(100 * $size / $quota, 1) } else { $null }
            $row.SizeGB = if ($size) { [math]::Round($size / 1GB, 2) } else { '' }
            $row.QuotaUsedPct = $pct
            Add-DiagData -Section "$id - Statistics" -Data ([ordered]@{
                    TotalItemSize = Format-DiagBytes $size; ItemCount = $stats.ItemCount; DeletedItemSize = Format-DiagBytes $del; DeletedItemCount = $stats.DeletedItemCount
                    ProhibitSendQuota = Format-DiagBytes $quota; QuotaUsedPercent = $pct; LastLogonTime = $stats.LastLogonTime; MailboxTypeDetail = $stats.MailboxTypeDetail
                })
            if ($pct -ge 98) { Add-DiagFinding -Severity Critical -Area $id -Title "Mailbox is $pct% of the send quota ($(Format-DiagBytes $size) of $(Format-DiagBytes $quota))" -Recommendation 'User cannot send (and soon receive). Enable/clean up archive, empty Deleted Items, or raise the license tier.' }
            elseif ($pct -ge 90) { Add-DiagFinding -Severity Warning -Area $id -Title "Mailbox is $pct% of the send quota" -Recommendation 'Enable archive + an archive retention tag, or clean up large folders.' }
        }

        # Recoverable items & folders
        if ($full) {
            $ri = Invoke-DiagStep -Name 'Recoverable Items folders' -Area $id -ScriptBlock { Get-MailboxFolderStatistics -Identity $upn -FolderScope RecoverableItems -ErrorAction Stop }
            if ($ri) {
                $riRoot = @($ri | Where-Object { $_.FolderType -eq 'RecoverableItemsRoot' -or $_.Name -eq 'Recoverable Items' }) | Select-Object -First 1
                $riSize = if ($riRoot) { ConvertTo-DiagBytes $riRoot.FolderAndSubfolderSize } else { ($ri | ForEach-Object { ConvertTo-DiagBytes $_.FolderSize } | Measure-Object -Sum).Sum }
                $riQuota = ConvertTo-DiagBytes $mbx.RecoverableItemsQuota
                $row.RecoverableGB = if ($riSize) { [math]::Round($riSize / 1GB, 2) } else { 0 }
                Add-DiagData -Section "$id - Recoverable Items" -Data @($ri | ForEach-Object { [pscustomobject]@{ Folder = $_.Name; FolderType = $_.FolderType; Items = $_.ItemsInFolder; Size = Format-DiagBytes (ConvertTo-DiagBytes $_.FolderSize) } })
                if ($riSize -and $riQuota) {
                    $riPct = [math]::Round(100 * $riSize / $riQuota, 1)
                    if ($riPct -ge 90) { Add-DiagFinding -Severity Critical -Area $id -Title "Recoverable Items is $riPct% full ($(Format-DiagBytes $riSize) of $(Format-DiagBytes $riQuota))" -Recommendation 'Users cannot delete items when this is full. Usually caused by holds - enable auto-expanding archive or review holds (removing holds needs a compliance admin).' }
                }
            }

            $folders = Invoke-DiagStep -Name 'Folder statistics (top 20 by size)' -Area $id -ScriptBlock { Get-MailboxFolderStatistics -Identity $upn -ErrorAction Stop }
            if ($folders) {
                $folders = @($folders)
                $top = @($folders | Sort-Object { ConvertTo-DiagBytes $_.FolderAndSubfolderSize } -Descending | Select-Object -First 20 | ForEach-Object {
                        [pscustomobject]@{ Folder = $_.FolderPath; Type = $_.FolderType; Items = $_.ItemsInFolder; ItemsInclSub = $_.ItemsInFolderAndSubfolders; Size = Format-DiagBytes (ConvertTo-DiagBytes $_.FolderSize); SizeInclSub = Format-DiagBytes (ConvertTo-DiagBytes $_.FolderAndSubfolderSize) }
                    })
                Add-DiagData -Section "$id - Largest folders" -Data $top
                if ($folders.Count -gt 9000) { Add-DiagFinding -Severity Warning -Area $id -Title "Mailbox has $($folders.Count) folders (limit 10,000)" -Recommendation 'Outlook performance and sync suffer; consolidate folders.' }
                foreach ($f in @($folders | Where-Object { [int]$_.ItemsInFolder -gt 1000000 })) { Add-DiagFinding -Severity Warning -Area $id -Title "Folder '$($f.FolderPath)' has $($f.ItemsInFolder) items (limit 1,000,000)" }
                $cal = $folders | Where-Object { $_.FolderType -eq 'Calendar' } | Select-Object -First 1
                $script:calendarPath = if ($cal) { $cal.FolderPath.TrimStart('/') -replace '/', '\' } else { 'Calendar' }
            }
        }

        # Archive
        if ($mbx.ArchiveStatus -eq 'Active' -or ($mbx.ArchiveGuid -and [string]$mbx.ArchiveGuid -ne '00000000-0000-0000-0000-000000000000')) {
            $as = Invoke-DiagStep -Name 'Archive statistics' -Area $id -ScriptBlock { Get-MailboxStatistics -Identity $upn -Archive -ErrorAction Stop }
            if ($as) {
                $aSize = ConvertTo-DiagBytes $as.TotalItemSize; $aQuota = ConvertTo-DiagBytes $mbx.ArchiveQuota
                $row.Archive = "$(Format-DiagBytes $aSize)"
                Add-DiagData -Section "$id - Archive" -Data ([ordered]@{ Size = Format-DiagBytes $aSize; Items = $as.ItemCount; Quota = Format-DiagBytes $aQuota; AutoExpanding = $mbx.AutoExpandingArchiveEnabled })
                if ($aSize -and $aQuota -and ($aSize / $aQuota) -gt 0.9 -and -not $mbx.AutoExpandingArchiveEnabled) { Add-DiagFinding -Severity Warning -Area $id -Title 'Archive is over 90% of its quota and auto-expanding archive is off' }
            }
        }
        else { $row.Archive = 'None' }

        # Holds
        $holds = @()
        if ($mbx.LitigationHoldEnabled) { $holds += 'Litigation hold' }
        foreach ($h in @($mbx.InPlaceHolds)) { if ($h) { $holds += "$h ($(Get-HoldText $h))" } }
        if ($mbx.DelayHoldApplied) { $holds += 'Delay hold (30 days after a hold was removed)' }
        if ($mbx.DelayReleaseHoldApplied) { $holds += 'Delay release hold (cloud data)' }
        if ($mbx.ComplianceTagHoldApplied) { $holds += 'Retention label hold' }
        if ($mbx.RetentionHoldEnabled) { $holds += 'Retention HOLD enabled (MRM paused)' }
        $row.Holds = ($holds -join '; ')
        if ($holds.Count -gt 0) { Add-DiagFinding -Severity Info -Area $id -Title "Holds on mailbox: $($holds.Count)" -Detail ($holds -join '; ') -Recommendation 'Holds keep deleted items in Recoverable Items and block mailbox removal/conversion. Get-OrganizationConfig InPlaceHolds shows org-wide policies.' }
        if ($mbx.ElcProcessingDisabled) { Add-DiagFinding -Severity Warning -Area $id -Title 'Managed Folder Assistant processing is disabled (ElcProcessingDisabled)' -Detail 'Retention/archive policies will not move or delete items.' }

        # Inbox rules (always - cheap and key for compromise checks)
        $rules = Invoke-DiagStep -Name 'Inbox rules (including hidden)' -Area $id -ScriptBlock {
            try { Get-InboxRule -Mailbox $upn -IncludeHidden -ErrorAction Stop } catch { Get-InboxRule -Mailbox $upn -ErrorAction Stop }
        }
        $rules = @($rules)
        if ($rules.Count -gt 0) {
            $rrows = foreach ($r in $rules) {
                $targets = @(Get-DiagEmailAddress -Value @($r.ForwardTo, $r.ForwardAsAttachmentTo, $r.RedirectTo))
                $extT = @($targets | Where-Object { Test-DiagExternalAddress -Address $_ -InternalDomains $internal })
                [pscustomobject]@{
                    Name = $r.Name; Enabled = $r.Enabled; Priority = $r.Priority; InError = $r.InError; ErrorType = $r.ErrorType
                    From = (@($r.From) -join '; '); SubjectOrBodyContains = (@($r.SubjectOrBodyContainsWords) + @($r.SubjectContainsWords) -join '; ')
                    MoveToFolder = $r.MoveToFolder; MarkAsRead = $r.MarkAsRead; Delete = $r.DeleteMessage; StopProcessing = $r.StopProcessingRules
                    ForwardRedirect = ($targets -join '; '); ExternalTargets = ($extT -join '; '); Description = ([string]$r.Description -replace '\s+', ' ')
                }
            }
            $rrows = @($rrows)
            Add-DiagData -Section "$id - Inbox rules" -Data $rrows
            foreach ($r in @($rrows | Where-Object { $_.ExternalTargets -and $_.Enabled })) {
                $row.ExternalRuleForwards++
                Add-DiagFinding -Severity Critical -Area $id -Title "Inbox rule '$($r.Name)' forwards/redirects externally to $($r.ExternalTargets)" -Recommendation 'Verify with the user. If unexpected: treat as compromise (reset password, revoke sessions, remove rule).'
            }
            foreach ($r in @($rrows | Where-Object { $_.Enabled -and ($_.Delete -or ($_.MarkAsRead -and $_.MoveToFolder -match 'RSS|Archive|Conversation History|Junk|Deleted')) })) {
                Add-DiagFinding -Severity Warning -Area $id -Title "Inbox rule '$($r.Name)' deletes or hides mail (moves to '$($r.MoveToFolder)' / marks read)" -Recommendation 'Common attacker technique to hide replies; also explains "missing emails".'
            }
            foreach ($r in @($rrows | Where-Object { $_.InError })) { Add-DiagFinding -Severity Warning -Area $id -Title "Inbox rule '$($r.Name)' is in error ($($r.ErrorType))" -Recommendation 'Usually the target folder was deleted. Rule must be fixed or recreated by the user.' }
            if ($rules.Count -gt 200) { Add-DiagFinding -Severity Warning -Area $id -Title "$($rules.Count) inbox rules - near the 256 KB rules quota" }
        }

        if ($full) {
            # Protocols
            $cas = Invoke-DiagStep -Name 'Client protocols (CAS mailbox)' -Area $id -ScriptBlock { Get-CASMailbox -Identity $upn -ErrorAction Stop }
            if ($cas) {
                Add-DiagData -Section "$id - Protocols" -Data ($cas | Select-DiagObject -Property OWAEnabled, OWAforDevicesEnabled, MAPIEnabled, EwsEnabled, ActiveSyncEnabled, PopEnabled, ImapEnabled, SmtpClientAuthenticationDisabled, UniversalOutlookEnabled, OutlookMobileEnabled, MacOutlookEnabled, OneWinNativeOutlookEnabled, ActiveSyncAllowedDeviceIDs, ActiveSyncBlockedDeviceIDs)
                if ($cas.MAPIEnabled -eq $false) { Add-DiagFinding -Severity Warning -Area $id -Title 'MAPI disabled - Outlook for Windows cannot connect' }
                if ($cas.EwsEnabled -eq $false) { Add-DiagFinding -Severity Warning -Area $id -Title 'EWS disabled - Teams calendar/free-busy, Mac Outlook and some add-ins break' }
                if ($cas.OWAEnabled -eq $false) { Add-DiagFinding -Severity Info -Area $id -Title 'Outlook on the web (OWA) is disabled' }
                if ($cas.ActiveSyncEnabled -eq $false) { Add-DiagFinding -Severity Info -Area $id -Title 'Exchange ActiveSync is disabled (native phone mail apps cannot sync)' }
                if ($cas.PSObject.Properties['OneWinNativeOutlookEnabled'] -and $cas.OneWinNativeOutlookEnabled -eq $false) { Add-DiagFinding -Severity Info -Area $id -Title 'New Outlook for Windows is disabled for this mailbox' }
            }

            # Permissions
            Invoke-DiagStep -Name 'Delegates and permissions' -Area $id -ScriptBlock {
                $fa = @(Get-MailboxPermission -Identity $upn -ErrorAction Stop | Where-Object { -not $_.IsInherited -and [string]$_.User -notmatch 'NT AUTHORITY\\SELF|^S-1-5' } | ForEach-Object { [pscustomobject]@{ Trustee = [string]$_.User; Rights = (@($_.AccessRights) -join ','); Deny = $_.Deny } })
                $sa = @(Get-RecipientPermission -Identity $upn -ErrorAction Stop | Where-Object { [string]$_.Trustee -notmatch 'NT AUTHORITY\\SELF' } | ForEach-Object { [pscustomobject]@{ Trustee = [string]$_.Trustee; Rights = (@($_.AccessRights) -join ','); Deny = ($_.AccessControlType -eq 'Deny') } })
                $sob = @($mbx.GrantSendOnBehalfTo | ForEach-Object { [pscustomobject]@{ Trustee = [string]$_; Rights = 'SendOnBehalf'; Deny = $false } })
                $calPath = if ($script:calendarPath) { $script:calendarPath } else { 'Calendar' }
                $cal = @()
                try { $cal = @(Get-MailboxFolderPermission -Identity "$($upn):\$calPath" -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Trustee = [string]$_.User; Rights = "Calendar: $(@($_.AccessRights) -join ',')"; Deny = $false } }) } catch { Write-DiagInfo "Calendar permissions: $($_.Exception.Message)" -Level Dim }
                Add-DiagData -Section "$id - Permissions" -Data (@($fa) + @($sa) + @($sob) + @($cal))
                if ($fa.Count -gt 0) { Add-DiagFinding -Severity Info -Area $id -Title "$($fa.Count) user(s) have Full Access" -Detail 'Full Access auto-maps the mailbox in Outlook (unless granted with -AutoMapping $false). Auto-mapping can take up to 60 min to appear.' }
            } | Out-Null

            # Mobile devices
            $mob = Invoke-DiagStep -Name 'Mobile devices' -Area $id -ScriptBlock { Get-MobileDeviceStatistics -Mailbox $upn -ErrorAction Stop }
            if ($mob) {
                $mrows = @($mob | ForEach-Object { [pscustomobject]@{ Device = $_.DeviceFriendlyName; Model = $_.DeviceModel; OS = $_.DeviceOS; Client = $_.ClientType; UserAgent = $_.DeviceUserAgent; AccessState = $_.DeviceAccessState; AccessReason = $_.DeviceAccessStateReason; LastSuccessSync = $_.LastSuccessSync; FirstSync = $_.FirstSyncTime; Status = $_.Status } })
                Add-DiagData -Section "$id - Mobile devices" -Data $mrows
                foreach ($m in @($mrows | Where-Object { $_.AccessState -in 'Quarantined', 'Blocked' })) { Add-DiagFinding -Severity Warning -Area $id -Title "Mobile device $($m.Model) is $($m.AccessState) ($($m.AccessReason))" -Recommendation 'Device access rules/ABQ or Intune CA blocks it. An admin must allow it or the user must use Outlook mobile.' }
            }

            # Auto reply & junk
            Invoke-DiagStep -Name 'Automatic replies and junk settings' -Area $id -ScriptBlock {
                $ar = Get-MailboxAutoReplyConfiguration -Identity $upn -ErrorAction Stop
                Add-DiagData -Section "$id - Automatic replies" -Data ([ordered]@{ State = $ar.AutoReplyState; Start = $ar.StartTime; End = $ar.EndTime; ExternalAudience = $ar.ExternalAudience; InternalMessageLength = ([string]$ar.InternalMessage).Length; ExternalMessageLength = ([string]$ar.ExternalMessage).Length })
                if ($ar.AutoReplyState -ne 'Disabled') { Add-DiagFinding -Severity Info -Area $id -Title "Automatic replies are $($ar.AutoReplyState)" }
                $j = Get-MailboxJunkEmailConfiguration -Identity $upn -ErrorAction Stop
                Add-DiagData -Section "$id - Junk email settings" -Data ([ordered]@{ Enabled = $j.Enabled; ContactsTrusted = $j.ContactsTrusted; TrustedListsOnly = $j.TrustedListsOnly; TrustedSendersCount = @($j.TrustedSendersAndDomains).Count; BlockedSendersCount = @($j.BlockedSendersAndDomains).Count; TrustedSenders = @($j.TrustedSendersAndDomains | Select-Object -First 100); BlockedSenders = @($j.BlockedSendersAndDomains | Select-Object -First 100) })
                if ($j.TrustedListsOnly) { Add-DiagFinding -Severity Warning -Area $id -Title 'Junk filter is set to "Safe lists only" - everything else goes to Junk' }
            } | Out-Null

            # Migration
            $mv = Invoke-DiagStep -Name 'Move / migration request' -Area $id -ScriptBlock { try { Get-MoveRequest -Identity $upn -ErrorAction Stop } catch { if ($_.Exception.Message -match "couldn't be found|not found") { $null } else { throw } } }
            if ($mv) {
                $ms = Get-MoveRequestStatistics -Identity $upn -ErrorAction SilentlyContinue
                Add-DiagData -Section "$id - Move request" -Data ($ms | Select-DiagObject -Property Status, StatusDetail, PercentComplete, BatchName, TotalMailboxSize, ItemsTransferred, BadItemsEncountered, LargeItemsEncountered, QueuedTimestamp, LastUpdateTimestamp, FailureType, Message)
                if ($mv.Status -match 'Failed') { Add-DiagFinding -Severity Critical -Area $id -Title "Mailbox move FAILED ($($ms.FailureType))" -Detail ([string]$ms.Message) }
                elseif ($mv.Status -notmatch 'Completed') { Add-DiagFinding -Severity Info -Area $id -Title "Mailbox move in progress: $($mv.Status) $($ms.PercentComplete)%" }
            }
        }
        $summary.Add([pscustomobject]$row)
    }
    if ($bulk) { Add-DiagData -Section 'Summary (all mailboxes)' -Data $summary.ToArray() }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
