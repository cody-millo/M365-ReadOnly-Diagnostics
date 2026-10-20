<#
.SYNOPSIS
    Teams Phone tenant diagnostics: Direct Routing gateways/routes/usages/policies with broken-reference checks, dial plans, call queues, auto attendants and resource accounts - plus an offline "which route will this number take?" test.

.DESCRIPTION
    Typical tickets: "outbound PSTN calls fail", "call queue doesn't ring agents", "auto attendant unreachable",
    "number translates wrongly". With -TestNumber (E.164, e.g. +14255550100) the script evaluates every voice
    routing policy's usages and routes in order (client-side regex) and shows which gateway would be used.

.PARAMETER TestNumber
    Optional E.164 number to evaluate routing for.

.EXAMPLE
    .\Get-TeamsPhoneDiagnostics.ps1 -TestNumber +442071234567

.NOTES
    Connection : Microsoft Teams PowerShell
    Roles      : Global Reader or Teams Administrator / Teams Telephony Administrator (read)
    Read-only  : Only Get-Cs* cmdlets are called; route testing is evaluated locally.
#>
[CmdletBinding()]
param(
    [string]$TestNumber,
    [int]$MaxResourceAccounts = 200,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $PSBoundParameters.ContainsKey('TestNumber')) { $TestNumber = Read-DiagValue -Prompt 'Number to test outbound routing for (E.164, e.g. +14255550100)' -Optional -Pattern '^\+?\d{3,15}$' -PatternHint 'Digits only, optional leading +' }

Start-DiagRun -Name 'Get-TeamsPhoneDiagnostics' -Title 'Microsoft Teams - Phone System Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ TestNumber = $TestNumber })
$cqAppId = '11cd3e2e-fccb-42ad-ad00-878b93575e07'
$aaAppId = 'ce933385-9390-45d1-9512-c8d228074e07'
try {
    Connect-DiagTeams -TenantId $TenantId | Out-Null

    # --- Direct Routing
    $gws = @(Invoke-DiagStep -Name 'PSTN gateways (SBCs)' -Area 'Direct Routing' -ScriptBlock { Get-CsOnlinePSTNGateway -ErrorAction Stop })
    $routes = @(Invoke-DiagStep -Name 'Voice routes' -Area 'Direct Routing' -ScriptBlock { Get-CsOnlineVoiceRoute -ErrorAction Stop })
    $usages = Invoke-DiagStep -Name 'PSTN usages' -Area 'Direct Routing' -ScriptBlock { Get-CsOnlinePstnUsages -ErrorAction Stop }
    $vrps = @(Invoke-DiagStep -Name 'Voice routing policies' -Area 'Direct Routing' -ScriptBlock { Get-CsOnlineVoiceRoutingPolicy -ErrorAction Stop })

    Add-DiagData -Section 'PSTN gateways' -Data @($gws | Select-DiagObject -Property Identity, Fqdn, SipSignalingPort, Enabled, ForwardCallHistory, ForwardPai, SendSipOptions, MaxConcurrentSessions, MediaBypass, BypassMode, FailoverTimeSeconds, FailoverResponseCodes, ProxySbc, GatewaySiteId, PidfLoSupported, MediaRelayRoutingLocationOverride)
    Add-DiagData -Section 'Voice routes' -Data @($routes | Select-DiagObject -Property Identity, Priority, NumberPattern, OnlinePstnGatewayList, OnlinePstnUsages, Description)
    Add-DiagData -Section 'PSTN usages' -Data ([ordered]@{ Usages = @($usages.Usage) })
    Add-DiagData -Section 'Voice routing policies' -Data @($vrps | Select-DiagObject -Property Identity, OnlinePstnUsages, Description)

    $gwIds = @($gws | ForEach-Object { [string]$_.Identity })
    foreach ($g in @($gws | Where-Object { -not $_.Enabled })) { Add-DiagFinding -Severity Warning -Area 'Direct Routing' -Title "SBC $($g.Identity) is disabled" }
    foreach ($r in $routes) {
        foreach ($gw in @($r.OnlinePstnGatewayList)) {
            if ($gwIds -notcontains [string]$gw) { Add-DiagFinding -Severity Critical -Area 'Direct Routing' -Title "Voice route '$($r.Identity)' points to unknown gateway '$gw'" }
            elseif (-not ($gws | Where-Object { [string]$_.Identity -eq [string]$gw }).Enabled) { Add-DiagFinding -Severity Warning -Area 'Direct Routing' -Title "Voice route '$($r.Identity)' uses disabled gateway '$gw'" }
        }
        if (@($r.OnlinePstnGatewayList).Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Direct Routing' -Title "Voice route '$($r.Identity)' has no gateways" }
        if (@($r.OnlinePstnUsages).Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Direct Routing' -Title "Voice route '$($r.Identity)' has no PSTN usage (never used)" }
        try { [void][regex]::new([string]$r.NumberPattern) } catch { Add-DiagFinding -Severity Critical -Area 'Direct Routing' -Title "Voice route '$($r.Identity)' has an invalid NumberPattern" -Detail ([string]$r.NumberPattern) }
    }
    $usedUsages = @($routes | ForEach-Object { @($_.OnlinePstnUsages) } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    foreach ($p in $vrps) {
        foreach ($u in @($p.OnlinePstnUsages)) { if ($usedUsages -notcontains [string]$u) { Add-DiagFinding -Severity Warning -Area 'Direct Routing' -Title "Policy '$($p.Identity)' references usage '$u' that no voice route uses" -Detail 'Calls matching only this usage fail with "no route".' } }
        if (@($p.OnlinePstnUsages).Count -eq 0 -and $gws.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Direct Routing' -Title "Voice routing policy '$($p.Identity)' has no PSTN usages" -Detail 'Direct Routing users assigned this policy cannot call PSTN.' }
    }
    if ($gws.Count -eq 0) { Add-DiagFinding -Severity Info -Area 'Direct Routing' -Title 'No Direct Routing SBCs configured (Calling Plans / Operator Connect only)' -Quiet }

    # --- Route test (offline evaluation)
    if ($TestNumber) {
        $num = if ($TestNumber.StartsWith('+')) { $TestNumber } else { "+$TestNumber" }
        $test = foreach ($p in $vrps) {
            $hit = $null
            foreach ($u in @($p.OnlinePstnUsages)) {
                $cand = @($routes | Where-Object { @($_.OnlinePstnUsages) -contains $u } | Sort-Object Priority)
                foreach ($r in $cand) {
                    $ok = $false
                    try { $ok = $num -match [string]$r.NumberPattern } catch { $ok = $false }
                    if ($ok) { $hit = [pscustomobject]@{ Policy = $p.Identity; Usage = $u; Route = $r.Identity; Priority = $r.Priority; Pattern = $r.NumberPattern; Gateways = (@($r.OnlinePstnGatewayList) -join ', ') }; break }
                }
                if ($hit) { break }
            }
            if ($hit) { $hit } else { [pscustomobject]@{ Policy = $p.Identity; Usage = ''; Route = '(no matching route - call fails)'; Priority = ''; Pattern = ''; Gateways = '' } }
        }
        Add-DiagData -Section "Route test for $num" -Data @($test) -Description 'Number must already be normalized (dial plans apply first). Usages are tried in policy order, routes by priority.'
        foreach ($t in @($test | Where-Object { $_.Route -like '(no matching*' })) { Add-DiagFinding -Severity Warning -Area 'Route test' -Title "Policy '$($t.Policy)' has no route for $num" }
    }

    # --- Dial plans
    Invoke-DiagStep -Name 'Tenant dial plans' -Area 'Dial plans' -ScriptBlock {
        $dp = @(Get-CsTenantDialPlan -ErrorAction Stop)
        $rows = foreach ($d in $dp) { foreach ($n in @($d.NormalizationRules)) { [pscustomobject]@{ DialPlan = $d.Identity; Rule = $n.Name; Pattern = $n.Pattern; Translation = $n.Translation; IsInternalExtension = $n.IsInternalExtension; Priority = $n.Priority } } }
        Add-DiagData -Section 'Dial plan normalization rules' -Data @($rows)
        foreach ($r in @($rows)) { try { [void][regex]::new([string]$r.Pattern) } catch { Add-DiagFinding -Severity Critical -Area 'Dial plans' -Title "Invalid normalization pattern in $($r.DialPlan)/$($r.Rule)" } }
    } | Out-Null

    Invoke-DiagStep -Name 'Calling line ID & emergency policies' -Area 'Policies' -ScriptBlock {
        Add-DiagData -Section 'Caller ID policies' -Data @(Get-CsCallingLineIdentity -ErrorAction Stop | Select-DiagObject -Property Identity, CallingIDSubstitute, ServiceNumber, ResourceAccount, EnableUserOverride, BlockIncomingPstnCallerID, CompanyName)
        Add-DiagData -Section 'Calling policies' -Data @(Get-CsTeamsCallingPolicy -ErrorAction Stop | Select-DiagObject -Property Identity, AllowPrivateCalling, AllowVoicemail, AllowCallGroups, AllowDelegation, AllowCallForwardingToUser, AllowCallForwardingToPhone, PreventTollBypass, BusyOnBusyEnabledType, AllowWebPSTNCalling, AllowTranscriptionForCalling, AllowCloudRecordingForCalls, AutoAnswerEnabledType, SpamFilteringEnabledType)
        Add-DiagData -Section 'Emergency calling policies' -Data @(Get-CsTeamsEmergencyCallingPolicy -ErrorAction SilentlyContinue | Select-DiagObject -Property Identity, NotificationGroup, NotificationMode, ExternalLocationLookupMode, EnhancedEmergencyServiceDisclaimer)
        $g = Get-CsTeamsCallingPolicy -Identity Global -ErrorAction SilentlyContinue
        if ($g -and $g.AllowPrivateCalling -eq $false) { Add-DiagFinding -Severity Warning -Area 'Policies' -Title 'Global calling policy disables private calling' -Detail 'Users with this policy cannot make 1:1 calls (incl. PSTN).' }
        if ($g -and $g.BusyOnBusyEnabledType -eq 'Enabled') { Add-DiagFinding -Severity Info -Area 'Policies' -Title 'Busy-on-busy is enabled globally' -Detail 'Second calls get busy signal - explains missed calls while on a call.' }
    } | Out-Null

    # --- Resource accounts, CQ, AA
    $ras = @(Invoke-DiagStep -Name 'Resource accounts' -Area 'Resource accounts' -ScriptBlock { Get-CsOnlineApplicationInstance -ErrorAction Stop | Select-Object -First $MaxResourceAccounts })
    $raRows = foreach ($ra in $ras) {
        $type = if ([string]$ra.ApplicationId -eq $cqAppId) { 'Call queue' } elseif ([string]$ra.ApplicationId -eq $aaAppId) { 'Auto attendant' } else { [string]$ra.ApplicationId }
        $lic = ''
        try { $ou = Get-CsOnlineUser -Identity $ra.ObjectId -ErrorAction Stop; $lic = (@($ou.FeatureTypes) -join ', ') } catch { $lic = '?' }
        [pscustomobject]@{ ResourceAccount = $ra.UserPrincipalName; DisplayName = $ra.DisplayName; Type = $type; PhoneNumber = $ra.PhoneNumber; FeatureTypes = $lic; ObjectId = $ra.ObjectId }
    }
    $raRows = @($raRows)
    Add-DiagData -Section 'Resource accounts' -Data $raRows
    foreach ($r in @($raRows | Where-Object { $_.PhoneNumber -and $_.FeatureTypes -notmatch 'PhoneSystem|VirtualUser' })) { Add-DiagFinding -Severity Warning -Area 'Resource accounts' -Title "Resource account $($r.ResourceAccount) has a phone number but no Teams Phone Resource Account license" -Recommendation 'Incoming PSTN calls to it fail. Assign the free "Microsoft Teams Phone Resource Account" license.' }

    Invoke-DiagStep -Name 'Call queues' -Area 'Call queues' -ScriptBlock {
        $cqs = @(Get-CsCallQueue -WarningAction SilentlyContinue -ErrorAction Stop)
        $rows = foreach ($q in $cqs) {
            [pscustomobject]@{
                Name = $q.Name; RoutingMethod = $q.RoutingMethod; Agents = @($q.Agents).Count; DistributionLists = @($q.DistributionLists).Count; ChannelId = $q.ChannelId; ConferenceMode = $q.ConferenceMode
                PresenceBasedRouting = $q.PresenceBasedRouting; AllowOptOut = $q.AllowOptOut; AgentAlertTime = $q.AgentAlertTime; OverflowThreshold = $q.OverflowThreshold; OverflowAction = $q.OverflowAction
                TimeoutThreshold = $q.TimeoutThreshold; TimeoutAction = $q.TimeoutAction; ResourceAccounts = @($q.ApplicationInstances).Count; LanguageId = $q.LanguageId; Identity = $q.Identity
            }
        }
        $rows = @($rows)
        Add-DiagData -Section 'Call queues' -Data $rows
        foreach ($q in $rows) {
            if ($q.Agents -eq 0 -and $q.DistributionLists -eq 0 -and -not $q.ChannelId) { Add-DiagFinding -Severity Critical -Area 'Call queues' -Title "Call queue '$($q.Name)' has no agents" }
            if ($q.ResourceAccounts -eq 0) { Add-DiagFinding -Severity Info -Area 'Call queues' -Title "Call queue '$($q.Name)' has no resource account (only reachable via an auto attendant / transfer)" }
            if ($q.OverflowThreshold -eq 0) { Add-DiagFinding -Severity Warning -Area 'Call queues' -Title "Call queue '$($q.Name)' overflow threshold is 0 - every call overflows immediately ($($q.OverflowAction))" }
            if ($q.AgentAlertTime -lt 15) { Add-DiagFinding -Severity Info -Area 'Call queues' -Title "Call queue '$($q.Name)' rings agents only $($q.AgentAlertTime)s" }
            if (-not $q.ConferenceMode) { Add-DiagFinding -Severity Info -Area 'Call queues' -Title "Call queue '$($q.Name)' has conference mode off (slower call connect)" -Quiet }
        }
    } | Out-Null

    Invoke-DiagStep -Name 'Auto attendants' -Area 'Auto attendants' -ScriptBlock {
        $aas = @(Get-CsAutoAttendant -ErrorAction Stop)
        $rows = foreach ($a in $aas) {
            [pscustomobject]@{
                Name = $a.Name; LanguageId = $a.LanguageId; TimeZoneId = $a.TimeZoneId; VoiceResponseEnabled = $a.VoiceResponseEnabled; ResourceAccounts = @($a.ApplicationInstances).Count
                Operator = if ($a.Operator) { "$($a.Operator.Type) $($a.Operator.Id)" } else { '' }; CallFlows = @($a.CallFlows).Count; HolidayOrScheduleAssociations = @($a.CallHandlingAssociations).Count
                DefaultMenuOptions = (@($a.DefaultCallFlow.Menu.MenuOptions | ForEach-Object { "$($_.DtmfResponse)->$($_.Action)" }) -join '; '); Identity = $a.Identity
            }
        }
        $rows = @($rows)
        Add-DiagData -Section 'Auto attendants' -Data $rows
        foreach ($a in @($rows | Where-Object { $_.ResourceAccounts -eq 0 })) { Add-DiagFinding -Severity Info -Area 'Auto attendants' -Title "Auto attendant '$($a.Name)' has no resource account (not directly reachable)" }
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
