<#
.SYNOPSIS
    Teams user diagnostics: licensing/feature types, upgrade (coexistence) mode, effective policies, phone number & Enterprise Voice, call forwarding/voicemail, audio conferencing and team memberships.

.DESCRIPTION
    Typical tickets: "user can't sign in to Teams / has no Teams", "can't make PSTN calls", "calls not ringing",
    "no dial-pad", "can't record meetings / chat with externals" (policy), "user homed on-prem Skype".

.PARAMETER Identity
    User UPN. Prompted if omitted.

.EXAMPLE
    .\Get-TeamsUserDiagnostics.ps1 -Identity jane@contoso.com

.NOTES
    Connection : Microsoft Teams PowerShell
    Roles      : Global Reader or Teams Communications Support Engineer / Teams Administrator (read)
    Read-only  : Only Get-Cs* / Get-Team* cmdlets are called.
#>
[CmdletBinding()]
param(
    [string]$Identity,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Identity) { $Identity = Read-DiagValue -Prompt 'Teams user (UPN)' -Pattern '@' -PatternHint 'Enter a UPN like user@domain.com' }

Start-DiagRun -Name 'Get-TeamsUserDiagnostics' -Title 'Microsoft Teams - User Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Identity = $Identity })
try {
    Connect-DiagTeams -TenantId $TenantId | Out-Null

    $u = Invoke-DiagStep -Name 'Teams user object' -Area 'User' -ScriptBlock { Get-CsOnlineUser -Identity $Identity -ErrorAction Stop }
    if (-not $u) { throw "User '$Identity' not found in Teams." }
    Register-DiagSensitiveValue -Value ([string]$u.DisplayName) -Category name
    Add-DiagData -Section 'User' -Data ($u | Select-DiagObject -Property DisplayName, UserPrincipalName, SipAddress, AccountEnabled, Enabled, IsSipEnabled, UsageLocation, InterpretedUserType, FeatureTypes, TeamsUpgradeEffectiveMode, TeamsUpgradePolicy,
        EnterpriseVoiceEnabled, HostedVoiceMail, LineUri, OnPremLineURI, OnlineVoiceRoutingPolicy, TenantDialPlan, CallingLineIdentity, TeamsCallingPolicy, TeamsEmergencyCallingPolicy, TeamsEmergencyCallRoutingPolicy,
        TeamsMeetingPolicy, TeamsMessagingPolicy, TeamsAppSetupPolicy, TeamsAppPermissionPolicy, ExternalAccessPolicy, TeamsMeetingBroadcastPolicy, TeamsChannelsPolicy, TeamsUpdateManagementPolicy, TeamsFeedbackPolicy,
        HostingProvider, RegistrarPool, OnPremHostingProvider, OnPremSIPEnabled, DirSyncEnabled, WhenChanged, LastSyncTimeStamp, AssignedPlan)

    $features = @($u.FeatureTypes)
    if ($u.AccountEnabled -eq $false) { Add-DiagFinding -Severity Critical -Area 'User' -Title 'Account is disabled' }
    if ($features.Count -gt 0 -and $features -notcontains 'Teams') { Add-DiagFinding -Severity Critical -Area 'Licensing' -Title 'No Teams service plan (FeatureTypes lacks "Teams")' -Detail ("FeatureTypes: " + ($features -join ', ')) -Recommendation 'Assign a license including Microsoft Teams (Teams is sold separately for new EEA/global E-SKUs). Changes can take up to 24 h to reach Teams.' }
    if ([string]$u.InterpretedUserType -match 'OnPrem|Hybrid') { Add-DiagFinding -Severity Warning -Area 'User' -Title "User type is $($u.InterpretedUserType)" -Detail 'The user is (or looks) homed on Skype for Business Server. Teams calling/meetings/chat interop may be limited.' -Recommendation 'Move the user to Teams Only (Move-CsUser) - a change on the on-premises side.' }
    if ($u.TeamsUpgradeEffectiveMode -and $u.TeamsUpgradeEffectiveMode -ne 'TeamsOnly') { Add-DiagFinding -Severity Warning -Area 'User' -Title "Upgrade mode is $($u.TeamsUpgradeEffectiveMode) (not TeamsOnly)" -Detail 'Skype for Business Online is retired; non-TeamsOnly modes cause routing of chats/calls to the wrong client.' }
    if (-not $u.UsageLocation) { Add-DiagFinding -Severity Warning -Area 'Licensing' -Title 'No usage location' -Detail 'Phone numbers and calling plans cannot be assigned.' }

    # Voice
    $hasPhoneSystem = ($features -contains 'PhoneSystem') -or ($features -match 'PhoneSystem')
    if ($u.EnterpriseVoiceEnabled -and -not $hasPhoneSystem) { Add-DiagFinding -Severity Warning -Area 'Voice' -Title 'Enterprise Voice enabled but no Teams Phone (PhoneSystem) feature' -Recommendation 'Assign Teams Phone Standard (or E5).' }
    $numbers = Invoke-DiagStep -Name 'Phone number assignment' -Area 'Voice' -ScriptBlock { @(Get-CsPhoneNumberAssignment -AssignedPstnTargetId $Identity -ErrorAction Stop) }
    if ($null -ne $numbers) {
        Add-DiagData -Section 'Phone numbers' -Data @($numbers | Select-DiagObject -Property TelephoneNumber, NumberType, ActivationState, Capability, AcquiredCapabilities, AssignmentCategory, PstnPartnerName, IsoCountryCode, City, LocationId, PortInOrderStatus)
        if (@($numbers).Count -gt 0) {
            if (-not $u.EnterpriseVoiceEnabled) { Add-DiagFinding -Severity Warning -Area 'Voice' -Title 'User has a phone number but Enterprise Voice is disabled' -Recommendation 'Calls cannot be made/received until EnterpriseVoiceEnabled is True.' }
            foreach ($n in @($numbers | Where-Object { $_.ActivationState -and $_.ActivationState -ne 'Activated' })) { Add-DiagFinding -Severity Warning -Area 'Voice' -Title "Number $($n.TelephoneNumber) activation state: $($n.ActivationState)" }
            $dr = @($numbers | Where-Object { $_.NumberType -eq 'DirectRouting' })
            if ($dr.Count -gt 0 -and -not $u.OnlineVoiceRoutingPolicy) { Add-DiagFinding -Severity Warning -Area 'Voice' -Title 'Direct Routing number but no Online Voice Routing Policy assigned' -Detail 'User falls back to the Global policy - outbound PSTN fails if Global has no usages/routes.' -Recommendation 'Run Get-TeamsPhoneDiagnostics.ps1 -TestNumber <dialled number> to see which route applies.' }
            $cp = @($numbers | Where-Object { $_.NumberType -eq 'CallingPlan' })
            if ($cp.Count -gt 0 -and -not ($features -match 'CallingPlan')) { Add-DiagFinding -Severity Warning -Area 'Voice' -Title 'Calling Plan number but no Calling Plan license detected' }
        }
        elseif ($u.EnterpriseVoiceEnabled) { Add-DiagFinding -Severity Info -Area 'Voice' -Title 'Enterprise Voice enabled but no phone number assigned' -Detail 'User can call internally/through call queues but has no DID for PSTN.' }
    }

    Invoke-DiagStep -Name 'Call forwarding / simultaneous ring' -Area 'Calling' -ScriptBlock {
        $cs = Get-CsUserCallingSettings -Identity $Identity -ErrorAction Stop
        Add-DiagData -Section 'Calling settings' -Data ($cs | Select-DiagObject -Property IsForwardingEnabled, ForwardingType, ForwardingTargetType, ForwardingTarget, IsUnansweredEnabled, UnansweredTargetType, UnansweredTarget, UnansweredDelay, CallGroupOrder, CallGroupTargets, GroupMembershipDetails, GroupNotificationOverride)
        if ($cs.IsForwardingEnabled -and $cs.ForwardingType -eq 'Immediate') { Add-DiagFinding -Severity Info -Area 'Calling' -Title "Calls are forwarded immediately to $($cs.ForwardingTargetType) $($cs.ForwardingTarget)" -Detail 'Explains "my Teams never rings".' }
        elseif ($cs.IsForwardingEnabled) { Add-DiagFinding -Severity Info -Area 'Calling' -Title "Simultaneous ring to $($cs.ForwardingTargetType) $($cs.ForwardingTarget)" }
        if ($cs.IsUnansweredEnabled) { Add-DiagFinding -Severity Info -Area 'Calling' -Title "Unanswered calls go to $($cs.UnansweredTargetType) after $($cs.UnansweredDelay)" -Quiet }
    } | Out-Null

    Invoke-DiagStep -Name 'Voicemail settings' -Area 'Calling' -ScriptBlock {
        $vm = Get-CsOnlineVoicemailUserSettings -Identity $Identity -ErrorAction Stop
        Add-DiagData -Section 'Voicemail' -Data ($vm | Select-DiagObject -Property VoicemailEnabled, PromptLanguage, CallAnswerRules, DefaultGreetingPromptOverwrite, OofGreetingEnabled, ShareData, TransferTarget)
        if ($vm.VoicemailEnabled -eq $false) { Add-DiagFinding -Severity Info -Area 'Calling' -Title 'Voicemail is disabled for the user' }
    } | Out-Null

    Invoke-DiagStep -Name 'Effective policy assignments' -Area 'Policies' -ScriptBlock {
        $pa = @(Get-CsUserPolicyAssignment -Identity $Identity -ErrorAction Stop)
        Add-DiagData -Section 'Policy assignments' -Data @($pa | ForEach-Object { [pscustomobject]@{ PolicyType = $_.PolicyType; PolicyName = $_.PolicyName; Source = (@($_.PolicySource | ForEach-Object { "$($_.AssignmentType) $($_.Reference)" }) -join '; ') } }) -Description 'Direct assignments win over group assignments; group assignments are ranked. Global (Org-wide default) applies when nothing is listed.'
    } | Out-Null

    Invoke-DiagStep -Name 'Audio conferencing' -Area 'Meetings' -ScriptBlock {
        $ac = Get-CsOnlineDialInConferencingUser -Identity $Identity -ErrorAction Stop
        if ($ac) { Add-DiagData -Section 'Audio conferencing' -Data ($ac | Select-DiagObject -Property ServiceNumber, TollNumber, TollFreeServiceNumber, AllowTollFreeDialIn, AllowPstnOnlyMeetings, BridgeName, Provider) }
        else { Add-DiagFinding -Severity Info -Area 'Meetings' -Title 'User is not enabled for audio conferencing (no dial-in numbers in invites)' -Quiet }
    } | Out-Null

    Invoke-DiagStep -Name 'Team memberships' -Area 'Teams' -ScriptBlock {
        $teams = @(Get-Team -User $Identity -ErrorAction Stop)
        Add-DiagData -Section 'Team memberships' -Data @($teams | Select-DiagObject -Property DisplayName, GroupId, Visibility, Archived, MailNickName)
        Add-DiagFinding -Severity Info -Area 'Teams' -Title "Member of $($teams.Count) team(s)" -Quiet
        if ($teams.Count -gt 900) { Add-DiagFinding -Severity Warning -Area 'Teams' -Title "User is in $($teams.Count) teams (limit 1,000)" }
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
