<#
.SYNOPSIS
    Tenant mail flow and protection configuration: restricted (blocked) senders, connectors, transport rules, DKIM, remote domains/forwarding, anti-spam/phish/malware policies, allow/block lists, SMTP AUTH and modern auth settings.

.DESCRIPTION
    Run for tenant-wide mail issues: "nobody can send externally", "user blocked from sending",
    "mail from partner goes to junk", "external forwarding not working", "app can't send via SMTP",
    "mail loops / routes via on-prem", and for a quick security posture review of EOP settings.

.EXAMPLE
    .\Get-MailFlowConfiguration.ps1

.NOTES
    Connection : Exchange Online
    Roles      : Global Reader, Security Reader or View-Only Organization Management
    Read-only  : Exchange session restricted to Get- cmdlets.
#>
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

Start-DiagRun -Name 'Get-MailFlowConfiguration' -Title 'Exchange Online - Mail Flow & Protection Configuration' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
$commands = 'Get-RemoteDomain', 'Get-InboundConnector', 'Get-OutboundConnector', 'Get-TransportRule', 'Get-DkimSigningConfig', 'Get-HostedContentFilterPolicy',
'Get-HostedContentFilterRule', 'Get-HostedOutboundSpamFilterPolicy', 'Get-HostedOutboundSpamFilterRule', 'Get-HostedConnectionFilterPolicy', 'Get-MalwareFilterPolicy',
'Get-AntiPhishPolicy', 'Get-TenantAllowBlockListItems', 'Get-BlockedSenderAddress', 'Get-TransportConfig', 'Get-AuthenticationPolicy', 'Get-JournalRule', 'Get-ArcConfig',
'Get-SafeLinksPolicy', 'Get-SafeAttachmentPolicy', 'Get-EOPProtectionPolicyRule', 'Get-ATPProtectionPolicyRule'
try {
    Connect-DiagExchange -CommandName $commands -UserPrincipalName $UserPrincipalName
    $accepted = @(Get-AcceptedDomain)
    $internal = @($accepted | ForEach-Object { [string]$_.DomainName })
    Add-DiagData -Section 'Accepted domains' -Data @($accepted | Select-DiagObject -Property DomainName, DomainType, Default, AuthenticationType, MatchSubDomains)
    foreach ($d in @($accepted | Where-Object { $_.DomainType -eq 'InternalRelay' })) { Add-DiagFinding -Severity Info -Area 'Domains' -Title "$($d.DomainName) is InternalRelay" -Detail 'Mail for unknown recipients is relayed out via connector instead of NDR. Required for some hybrid/coexistence setups; a cause of mail loops if misconfigured.' }

    # Restricted senders - #1 cause of "user suddenly cannot send"
    Invoke-DiagStep -Name 'Restricted (blocked) senders' -Area 'Outbound' -ScriptBlock {
        $b = @(Get-BlockedSenderAddress -ErrorAction Stop)
        Add-DiagData -Section 'Restricted senders' -Data @($b | Select-DiagObject -Property SenderAddress, Reason, ReasonType, CreatedDatetime, ChangedDatetime)
        foreach ($s in $b) { Add-DiagFinding -Severity Critical -Area 'Outbound' -Title "$($s.SenderAddress) is BLOCKED from sending ($($s.ReasonType))" -Recommendation 'Exceeded outbound limits - usually a compromised account. Secure the account first, then release in Defender portal > Restricted entities.' }
        if ($b.Count -eq 0) { Add-DiagFinding -Severity OK -Area 'Outbound' -Title 'No users are restricted from sending' -Quiet }
    } | Out-Null

    Invoke-DiagStep -Name 'Organization transport settings' -Area 'Transport' -ScriptBlock {
        $t = Get-TransportConfig -ErrorAction Stop
        Add-DiagData -Section 'Transport config' -Data ($t | Select-DiagObject -Property SmtpClientAuthenticationDisabled, AllowLegacyTLSClients, MaxSendSize, MaxReceiveSize, MaxRecipientEnvelopeLimit, ExternalPostmasterAddress, JournalingReportNdrTo, ReplyAllStormProtectionEnabled, ReplyAllStormDetectionMinimumRecipients, AddressBookPolicyRoutingEnabled, InternalSMTPServers, ConvertDisclaimerWrapperToEml)
        $o = Get-OrganizationConfig -ErrorAction Stop
        Add-DiagData -Section 'Organization config' -Data ($o | Select-DiagObject -Property Name, OAuth2ClientProfileEnabled, DefaultAuthenticationPolicy, AuditDisabled, EwsEnabled, EwsApplicationAccessPolicy, MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, FocusedInboxOn, ConnectorsEnabled, BookingsEnabled, OutlookMobileGCCRestrictionsEnabled, IsDehydrated, PublicFoldersEnabled, AutoExpandingArchiveEnabled, InPlaceHolds, ElcProcessingDisabled)
        if ($o.OAuth2ClientProfileEnabled -eq $false) { Add-DiagFinding -Severity Critical -Area 'Auth' -Title 'Modern authentication (OAuth2ClientProfileEnabled) is OFF for Exchange Online' -Recommendation 'Outlook will prompt repeatedly / fail. Enable modern auth (change required).' }
        if ($o.AuditDisabled) { Add-DiagFinding -Severity Warning -Area 'Audit' -Title 'Mailbox auditing is disabled at the organization level' }
        if ($o.ElcProcessingDisabled) { Add-DiagFinding -Severity Warning -Area 'Retention' -Title 'Managed Folder Assistant is disabled for the organization' }
        if ($o.EwsEnabled -eq $false) { Add-DiagFinding -Severity Warning -Area 'Transport' -Title 'EWS disabled organization-wide' -Detail 'Breaks Teams calendar, Mac Outlook, many add-ins/migrations.' }
        if (-not $t.SmtpClientAuthenticationDisabled) { Add-DiagFinding -Severity Info -Area 'Transport' -Title 'SMTP AUTH client submission is enabled tenant-wide' -Recommendation 'Disable tenant-wide and allow per mailbox only where devices/apps need it.' }
        else { Add-DiagFinding -Severity Info -Area 'Transport' -Title 'SMTP AUTH is disabled tenant-wide' -Detail 'Printers/apps sending via smtp.office365.com:587 fail with 5.7.57/5.7.139 unless enabled on that mailbox (Get-MailboxDiagnostics shows the per-mailbox setting).' }
        if ($t.JournalingReportNdrTo -match '^<>$|^$') {
            $j = @(Get-JournalRule -ErrorAction SilentlyContinue)
            if ($j.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Journal' -Title 'Journal rules exist but no JournalingReportNdrTo mailbox is set' }
        }
        $ap = @(Get-AuthenticationPolicy -ErrorAction SilentlyContinue)
        if ($ap) { Add-DiagData -Section 'Authentication policies' -Data @($ap | Select-DiagObject -Property Name, AllowBasicAuthSmtp, AllowBasicAuthImap, AllowBasicAuthPop, AllowBasicAuthActiveSync, AllowBasicAuthWebServices, AllowBasicAuthPowershell, AllowBasicAuthMapi, AllowBasicAuthAutodiscover) }
    } | Out-Null

    Invoke-DiagStep -Name 'Connectors' -Area 'Connectors' -ScriptBlock {
        $in = @(Get-InboundConnector -ErrorAction Stop)
        $out = @(Get-OutboundConnector -ErrorAction Stop)
        Add-DiagData -Section 'Inbound connectors' -Data @($in | Select-DiagObject -Property Name, Enabled, ConnectorType, ConnectorSource, SenderDomains, SenderIPAddresses, RestrictDomainsToIPAddresses, RestrictDomainsToCertificate, RequireTls, TlsSenderCertificateName, CloudServicesMailEnabled, EFSkipLastIP, EFSkipIPs, EFUsers, TrustedOrganizations, WhenChanged)
        Add-DiagData -Section 'Outbound connectors' -Data @($out | Select-DiagObject -Property Name, Enabled, ConnectorType, ConnectorSource, RecipientDomains, SmartHosts, UseMXRecord, TlsSettings, TlsDomain, IsTransportRuleScoped, RouteAllMessagesViaOnPremises, CloudServicesMailEnabled, AllAcceptedDomains, SenderRewritingEnabled, LastValidationTimestamp, ValidationRecipients, IsValidated, WhenChanged)
        foreach ($c in @($out | Where-Object { $_.Enabled -and @($_.RecipientDomains) -contains '*' -and -not $_.IsTransportRuleScoped })) {
            Add-DiagFinding -Severity Info -Area 'Connectors' -Title "Outbound connector '$($c.Name)' routes ALL external mail via $(@($c.SmartHosts) -join ', ')" -Detail 'If that smart host/gateway is down or rejects, all outbound mail queues (Pending in trace).'
        }
        foreach ($c in @($out | Where-Object { $_.Enabled -and $_.IsValidated -eq $false })) { Add-DiagFinding -Severity Warning -Area 'Connectors' -Title "Outbound connector '$($c.Name)' failed or never passed validation" }
        foreach ($c in @($in | Where-Object { $_.Enabled -and $_.ConnectorType -eq 'Partner' -and -not $_.EFSkipLastIP -and -not $_.EFSkipIPs })) {
            Add-DiagFinding -Severity Info -Area 'Connectors' -Title "Inbound connector '$($c.Name)' has no Enhanced Filtering" -Detail 'If MX points to a third-party gateway, SPF/DMARC/IP checks see the gateway IP - causing spoof/junk verdicts.' -Recommendation 'Configure Enhanced Filtering for Connectors (skip listing) on the gateway connector.'
        }
        foreach ($c in @($in + $out | Where-Object { -not $_.Enabled })) { Add-DiagFinding -Severity Info -Area 'Connectors' -Title "Connector '$($c.Name)' is disabled" -Quiet }
    } | Out-Null

    Invoke-DiagStep -Name 'Transport (mail flow) rules' -Area 'Rules' -ScriptBlock {
        $rules = @(Get-TransportRule -ErrorAction Stop)
        $rows = foreach ($r in $rules) {
            $actions = @()
            foreach ($a in 'RedirectMessageTo', 'BlindCopyTo', 'AddToRecipients', 'CopyTo', 'ModerateMessageByUser', 'RouteMessageOutboundConnector', 'DeleteMessage', 'RejectMessageReasonText', 'RejectMessageEnhancedStatusCode', 'SetSCL', 'Quarantine', 'ApplyHtmlDisclaimerText', 'PrependSubject', 'SetHeaderName', 'GenerateIncidentReport', 'StopRuleProcessing', 'ApplyRightsProtectionTemplate', 'ApplyOME') {
                if ($r.PSObject.Properties[$a] -and $r.$a -and [string]$r.$a -notin 'False', '0') { $actions += "$a=$(@($r.$a) -join ',')" }
            }
            [pscustomobject]@{ Priority = $r.Priority; Name = $r.Name; State = $r.State; Mode = $r.Mode; Actions = ($actions -join ' | '); Description = ([string]$r.Description -replace '\s+', ' '); Comments = $r.Comments; WhenChanged = $r.WhenChanged; ExpiryDate = $r.ExpiryDate }
        }
        $rows = @($rows | Sort-Object Priority)
        Add-DiagData -Section 'Transport rules' -Data $rows
        foreach ($r in @($rows | Where-Object { $_.State -eq 'Enabled' -and $_.Mode -eq 'Enforce' })) {
            if ($r.Actions -match 'SetSCL=-1') { Add-DiagFinding -Severity Warning -Area 'Rules' -Title "Rule '$($r.Name)' bypasses spam filtering (SCL -1)" -Recommendation 'Bypass rules based on sender domain are easily spoofed. Prefer Tenant Allow/Block list or connector-based conditions.' }
            if ($r.Actions -match 'DeleteMessage=True') { Add-DiagFinding -Severity Warning -Area 'Rules' -Title "Rule '$($r.Name)' silently deletes messages" -Detail $r.Description }
            $ext = @(Get-DiagEmailAddress -Value $r.Actions | Where-Object { Test-DiagExternalAddress -Address $_ -InternalDomains $internal })
            if ($ext.Count -gt 0 -and $r.Actions -match 'RedirectMessageTo|BlindCopyTo|AddToRecipients|CopyTo') { Add-DiagFinding -Severity Warning -Area 'Rules' -Title "Rule '$($r.Name)' copies/redirects mail to external address(es) $($ext -join ', ')" }
            if ($r.Actions -match 'RejectMessage') { Add-DiagFinding -Severity Info -Area 'Rules' -Title "Rule '$($r.Name)' rejects messages" -Detail $r.Description }
        }
        foreach ($r in @($rows | Where-Object { (ConvertTo-DiagDate $_.WhenChanged) -gt (Get-Date).ToUniversalTime().AddDays(-7) })) { Add-DiagFinding -Severity Info -Area 'Rules' -Title "Rule '$($r.Name)' changed in the last 7 days ($($r.WhenChanged))" }
    } | Out-Null

    Invoke-DiagStep -Name 'DKIM signing' -Area 'DKIM' -ScriptBlock {
        $dk = @(Get-DkimSigningConfig -ErrorAction Stop)
        Add-DiagData -Section 'DKIM signing' -Data @($dk | Select-DiagObject -Property Domain, Enabled, Status, Selector1CNAME, Selector2CNAME, KeyCreationTime, RotateOnDate, SelectorBeforeRotateOnDate)
        foreach ($d in @($accepted | Where-Object { [string]$_.DomainName -notmatch 'onmicrosoft\.com$' })) {
            $c = $dk | Where-Object { [string]$_.Domain -eq [string]$d.DomainName } | Select-Object -First 1
            if (-not $c -or -not $c.Enabled) { Add-DiagFinding -Severity Warning -Area 'DKIM' -Title "DKIM signing not enabled for $($d.DomainName)" -Recommendation 'Without DKIM, DMARC relies on SPF alone - forwarded mail fails DMARC. Enable in Defender portal > Email authentication.' }
        }
    } | Out-Null

    Invoke-DiagStep -Name 'Remote domains and forwarding policy' -Area 'Forwarding' -ScriptBlock {
        $rd = @(Get-RemoteDomain -ErrorAction Stop)
        Add-DiagData -Section 'Remote domains' -Data @($rd | Select-DiagObject -Property Name, DomainName, AutoForwardEnabled, AutoReplyEnabled, AllowedOOFType, DeliveryReportEnabled, NDREnabled, TNEFEnabled, ContentType, CharacterSet)
        $op = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
        $opr = @(Get-HostedOutboundSpamFilterRule -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Outbound spam policies' -Data @($op | Select-DiagObject -Property Name, IsDefault, AutoForwardingMode, RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay, ActionWhenThresholdReached, BccSuspiciousOutboundMail, NotifyOutboundSpam)
        Add-DiagData -Section 'Outbound spam rules' -Data @($opr | Select-DiagObject -Property Name, Priority, State, HostedOutboundSpamFilterPolicy, From, FromMemberOf, SenderDomainIs)
        $def = $op | Where-Object IsDefault | Select-Object -First 1
        if ($def -and $def.AutoForwardingMode -in 'Automatic', 'Off') { Add-DiagFinding -Severity Info -Area 'Forwarding' -Title "External auto-forwarding is blocked by default (AutoForwardingMode = $($def.AutoForwardingMode))" -Detail 'Users with forwarding/redirect rules to external addresses get NDR 5.7.520. Allowed only for users in a custom policy with AutoForwardingMode On.' }
        if ($def -and $def.AutoForwardingMode -eq 'On') { Add-DiagFinding -Severity Warning -Area 'Forwarding' -Title 'External auto-forwarding is allowed for everyone (default policy = On)' -Recommendation 'Attackers use forwarding to exfiltrate mail. Allow it only for specific users via a custom policy.' }
        $rdDef = $rd | Where-Object { $_.DomainName -eq '*' } | Select-Object -First 1
        if ($rdDef -and -not $rdDef.AutoForwardEnabled) { Add-DiagFinding -Severity Info -Area 'Forwarding' -Title 'Default remote domain blocks auto-forward (AutoForwardEnabled = False)' -Detail 'Forwarded messages are dropped silently (no NDR) - explains "forwarding does nothing".' }
    } | Out-Null

    Invoke-DiagStep -Name 'Anti-spam (inbound) policies' -Area 'Anti-spam' -ScriptBlock {
        $cf = @(Get-HostedContentFilterPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Inbound anti-spam policies' -Data @($cf | Select-DiagObject -Property Name, IsDefault, BulkThreshold, SpamAction, HighConfidenceSpamAction, PhishSpamAction, HighConfidencePhishAction, BulkSpamAction, QuarantineRetentionPeriod, SpamQuarantineTag, MarkAsSpamBulkMail, AllowedSenders, AllowedSenderDomains, BlockedSenders, BlockedSenderDomains, InlineSafetyTipsEnabled, IncreaseScoreWithImageLinks)
        foreach ($p in $cf) {
            $own = @(@($p.AllowedSenderDomains) | ForEach-Object { [string]$_ } | Where-Object { $internal -contains $_ })
            if ($own.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Anti-spam' -Title "Policy '$($p.Name)' allow-lists your own domain(s): $($own -join ', ')" -Recommendation 'Spoofed mail from your own domain skips spam filtering. Remove it.' }
            $cnt = @($p.AllowedSenderDomains).Count + @($p.AllowedSenders).Count
            if ($cnt -gt 50) { Add-DiagFinding -Severity Info -Area 'Anti-spam' -Title "Policy '$($p.Name)' has $cnt allowed senders/domains" -Recommendation 'Large allow lists weaken protection; use Tenant Allow/Block list with expiry instead.' }
            if ($p.HighConfidencePhishAction -ne 'Quarantine') { Add-DiagFinding -Severity Warning -Area 'Anti-spam' -Title "Policy '$($p.Name)' does not quarantine high-confidence phish ($($p.HighConfidencePhishAction))" }
        }
        $cn = @(Get-HostedConnectionFilterPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Connection filter' -Data @($cn | Select-DiagObject -Property Name, IPAllowList, IPBlockList, EnableSafeList)
        foreach ($c in $cn) { if (@($c.IPAllowList).Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Anti-spam' -Title "Connection filter allows $(@($c.IPAllowList).Count) IP range(s) - mail from them skips spam filtering" } }
        $ap = @(Get-AntiPhishPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Anti-phishing policies' -Data @($ap | Select-DiagObject -Property Name, IsDefault, Enabled, EnableSpoofIntelligence, EnableMailboxIntelligence, EnableMailboxIntelligenceProtection, EnableTargetedUserProtection, EnableTargetedDomainsProtection, EnableOrganizationDomainsProtection, PhishThresholdLevel, AuthenticationFailAction, HonorDmarcPolicy, EnableFirstContactSafetyTips, EnableUnauthenticatedSender, EnableViaTag)
        $mp = @(Get-MalwareFilterPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Anti-malware policies' -Data @($mp | Select-DiagObject -Property Name, IsDefault, EnableFileFilter, FileTypeAction, ZapEnabled, QuarantineTag, EnableInternalSenderAdminNotifications)
    } | Out-Null

    Invoke-DiagStep -Name 'Preset security policies & Defender (if licensed)' -Area 'Defender' -ScriptBlock {
        $eop = @(Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue)
        $atp = @(Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Preset security policies' -Data (@($eop) + @($atp) | Select-DiagObject -Property Name, State, Priority, SentTo, SentToMemberOf, RecipientDomainIs)
        $sl = @(Get-SafeLinksPolicy -ErrorAction SilentlyContinue)
        $sa = @(Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue)
        if ($sl) { Add-DiagData -Section 'Safe Links policies' -Data @($sl | Select-DiagObject -Property Name, EnableSafeLinksForEmail, EnableSafeLinksForTeams, EnableSafeLinksForOffice, TrackClicks, AllowClickThrough, ScanUrls, EnableForInternalSenders, DeliverMessageAfterScan, DoNotRewriteUrls) }
        if ($sa) { Add-DiagData -Section 'Safe Attachments policies' -Data @($sa | Select-DiagObject -Property Name, Enable, Action, QuarantineTag, Redirect) }
        if (@($sa | Where-Object { $_.Action -eq 'DynamicDelivery' -or $_.Action -eq 'Block' }).Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Defender' -Title 'Safe Attachments is active - attachments can be delayed a few minutes while scanned' -Quiet }
    } | Out-Null

    Invoke-DiagStep -Name 'Tenant Allow/Block List' -Area 'Allow/Block' -ScriptBlock {
        $items = foreach ($lt in 'Sender', 'Url', 'FileHash') {
            foreach ($i in @(Get-TenantAllowBlockListItems -ListType $lt -ErrorAction SilentlyContinue)) { [pscustomobject]@{ ListType = $lt; Value = $i.Value; Action = $i.Action; ExpirationDate = $i.ExpirationDate; LastUsedDate = $i.LastUsedDate; Notes = $i.Notes; SubmissionID = $i.SubmissionID } }
        }
        $items = @($items)
        Add-DiagData -Section 'Tenant Allow/Block List' -Data $items
        if (@($items | Where-Object Action -eq 'Block').Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Allow/Block' -Title "$(@($items | Where-Object Action -eq 'Block').Count) blocked entries in Tenant Allow/Block list" -Detail 'Check here when a specific partner''s mail is rejected/quarantined.' }
    } | Out-Null

    Invoke-DiagStep -Name 'ARC trusted sealers' -Area 'Auth' -ScriptBlock {
        $arc = Get-ArcConfig -ErrorAction Stop
        Add-DiagData -Section 'ARC configuration' -Data ($arc | Select-DiagObject -Property ArcTrustedSealers)
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
