<#
.SYNOPSIS
    Teams tenant configuration: external access/federation, guest access, meeting/messaging/app/channel policies, upgrade mode and meeting settings - with the settings behind common "can't" tickets flagged.

.DESCRIPTION
    Typical tickets: "can't chat with another company", "guests can't join", "anonymous users can't join meetings",
    "recording/transcription missing", "users stuck in lobby", "app missing / can't upload custom app",
    "can't create private/shared channels".

.EXAMPLE
    .\Get-TeamsTenantConfiguration.ps1

.NOTES
    Connection : Microsoft Teams PowerShell
    Roles      : Global Reader or Teams Administrator (read)
    Read-only  : Only Get-Cs* cmdlets are called.
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

Start-DiagRun -Name 'Get-TeamsTenantConfiguration' -Title 'Microsoft Teams - Tenant Configuration' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
try {
    $tenant = Connect-DiagTeams -TenantId $TenantId
    Add-DiagData -Section 'Tenant' -Data ($tenant | Select-DiagObject -Property DisplayName, TenantId, CountryAbbreviation, PreferredLanguage, ServiceInstance, TeamsUpgradeEffectiveMode, VerifiedDomains, SipDomain, WhenCreated)

    Invoke-DiagStep -Name 'External access (federation)' -Area 'External access' -ScriptBlock {
        $f = Get-CsTenantFederationConfiguration -ErrorAction Stop
        Add-DiagData -Section 'Federation' -Data ($f | Select-DiagObject -Property AllowFederatedUsers, AllowedDomains, BlockedDomains, AllowTeamsConsumer, AllowTeamsConsumerInbound, AllowPublicUsers, TreatDiscoveredPartnersAsUnverified, SharedSipAddressSpace, RestrictTeamsConsumerToExternalUserProfiles, ExternalAccessWithTrialTenants, BlockAllSubdomains)
        if (-not $f.AllowFederatedUsers) { Add-DiagFinding -Severity Warning -Area 'External access' -Title 'External access with other organizations is OFF' -Detail 'Users cannot chat/call with any other Teams tenant.' }
        else {
            $allowed = [string]$f.AllowedDomains
            if ($allowed -match 'AllowedDomain|Domain=' -and $allowed -notmatch 'AllowAllKnownDomains') { Add-DiagFinding -Severity Info -Area 'External access' -Title 'External access is limited to an allow list of domains' -Detail $allowed -Recommendation 'Partners not in the list cannot chat. Both tenants must allow each other.' }
            if (@($f.BlockedDomains).Count -gt 0) { Add-DiagFinding -Severity Info -Area 'External access' -Title "$(@($f.BlockedDomains).Count) domain(s) blocked for external access" }
        }
        if ($f.ExternalAccessWithTrialTenants -eq 'Blocked') { Add-DiagFinding -Severity Info -Area 'External access' -Title 'Chat with trial-only tenants is blocked' -Quiet }
        $ea = @(Get-CsExternalAccessPolicy -ErrorAction SilentlyContinue)
        if ($ea) { Add-DiagData -Section 'External access policies' -Data @($ea | Select-DiagObject -Property Identity, EnableFederationAccess, EnableTeamsConsumerAccess, EnableTeamsConsumerInbound, EnablePublicCloudAccess, EnableAcsFederationAccess, EnableOutsideAccess) }
        $g = $ea | Where-Object { $_.Identity -eq 'Global' } | Select-Object -First 1
        if ($g -and $g.EnableFederationAccess -eq $false) { Add-DiagFinding -Severity Warning -Area 'External access' -Title 'Global external access policy disables federation for users' -Detail 'Tenant allows federation but users assigned the Global policy cannot use it.' }
    } | Out-Null

    Invoke-DiagStep -Name 'Guest access' -Area 'Guest access' -ScriptBlock {
        $c = Get-CsTeamsClientConfiguration -ErrorAction Stop
        Add-DiagData -Section 'Client configuration' -Data ($c | Select-DiagObject -Property AllowGuestUser, AllowEmailIntoChannel, AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte, AllowOrganizationTab, AllowSkypeBusinessInterop, ContentPin, AllowResourceAccountSendMessage, ResourceAccountContentAccess, AllowScopedPeopleSearchandAccess, RestrictedSenderList)
        if ($c.AllowGuestUser -eq $false) { Add-DiagFinding -Severity Warning -Area 'Guest access' -Title 'Guest access in Teams is OFF' -Detail 'Guests can be added to M365 groups but cannot use Teams.' }
        $gm = Get-CsTeamsGuestMeetingConfiguration -ErrorAction SilentlyContinue
        $gmsg = Get-CsTeamsGuestMessagingConfiguration -ErrorAction SilentlyContinue
        $gc = Get-CsTeamsGuestCallingConfiguration -ErrorAction SilentlyContinue
        Add-DiagData -Section 'Guest permissions' -Data ([ordered]@{
                Meeting   = ($gm | Select-DiagObject -Property AllowIPVideo, ScreenSharingMode, AllowMeetNow, LiveCaptionsEnabledType, AllowTranscription)
                Messaging = ($gmsg | Select-DiagObject -Property AllowUserEditMessage, AllowUserDeleteMessage, AllowUserDeleteChat, AllowUserChat, AllowGiphy, AllowMemes, AllowStickers, AllowImmersiveReader)
                Calling   = ($gc | Select-DiagObject -Property AllowPrivateCalling)
            })
    } | Out-Null

    Invoke-DiagStep -Name 'Meeting configuration and policies' -Area 'Meetings' -ScriptBlock {
        $mc = Get-CsTeamsMeetingConfiguration -ErrorAction Stop
        Add-DiagData -Section 'Meeting configuration' -Data ($mc | Select-DiagObject -Property DisableAnonymousJoin, DisableAppInteractionForAnonymousUsers, EnableQoS, ClientAudioPort, ClientAudioPortRange, ClientVideoPort, ClientVideoPortRange, ClientMediaPortRangeEnabled, LogoURL, LegalURL, HelpURL, CustomFooterText)
        if ($mc.DisableAnonymousJoin) { Add-DiagFinding -Severity Warning -Area 'Meetings' -Title 'Anonymous users cannot join meetings (tenant-wide)' -Detail 'External people without a Teams account (or from blocked orgs) cannot join.' }
        $mp = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop)
        $rows = @($mp | Select-DiagObject -Property Identity, AllowAnonymousUsersToJoinMeeting, AutoAdmittedUsers, AllowPSTNUsersToBypassLobby, AllowCloudRecording, AllowRecordingStorageOutsideRegion, NewMeetingRecordingExpirationDays, AllowTranscription, LiveCaptionsEnabledType, AllowMeetNow, AllowPrivateMeetNow, AllowChannelMeetingScheduling, AllowPrivateMeetingScheduling, AllowOutlookAddIn, AllowIPAudio, AllowIPVideo, ScreenSharingMode, AllowExternalParticipantGiveRequestControl, AllowPowerPointSharing, AllowWhiteboard, AllowSharedNotes, MeetingChatEnabledType, AllowExternalNonTrustedMeetingChat, AllowParticipantGiveRequestControl, DesignatedPresenterRoleMode, AllowWatermarkForScreenSharing, AllowWatermarkForCameraVideo, RoomAttributeUserOverride, AutoRecording, AllowCopilot, CopilotWithoutTranscript, MediaBitRateKb, AllowNetworkConfigurationSettingsLookup)
        Add-DiagData -Section 'Meeting policies' -Data $rows
        $g = $mp | Where-Object Identity -eq 'Global' | Select-Object -First 1
        if ($g) {
            if (-not $g.AllowCloudRecording) { Add-DiagFinding -Severity Info -Area 'Meetings' -Title 'Global meeting policy: cloud recording disabled' }
            if (-not $g.AllowTranscription) { Add-DiagFinding -Severity Info -Area 'Meetings' -Title 'Global meeting policy: transcription disabled' -Detail 'Also affects Copilot in meetings and intelligent recap.' }
            if (-not $g.AllowOutlookAddIn) { Add-DiagFinding -Severity Warning -Area 'Meetings' -Title 'Global meeting policy disables the Teams Outlook add-in' -Detail 'Explains a missing "Teams Meeting" button in Outlook.' }
            if (-not $g.AllowAnonymousUsersToJoinMeeting) { Add-DiagFinding -Severity Info -Area 'Meetings' -Title 'Global meeting policy blocks anonymous join' }
            if ($g.AutoAdmittedUsers -in 'OrganizerOnly', 'InvitedUsers') { Add-DiagFinding -Severity Info -Area 'Meetings' -Title "Global lobby setting: '$($g.AutoAdmittedUsers)' are admitted automatically" -Detail 'Everyone else waits in the lobby.' }
            if ($g.AllowIPVideo -eq $false) { Add-DiagFinding -Severity Warning -Area 'Meetings' -Title 'Global meeting policy disables video' }
        }
    } | Out-Null

    Invoke-DiagStep -Name 'Messaging policies' -Area 'Messaging' -ScriptBlock {
        $mp = @(Get-CsTeamsMessagingPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Messaging policies' -Data @($mp | Select-DiagObject -Property Identity, AllowUserChat, AllowUserEditMessage, AllowUserDeleteMessage, AllowUserDeleteChat, AllowOwnerDeleteMessage, AllowGiphy, GiphyRatingType, AllowMemes, AllowStickers, AllowUrlPreviews, ReadReceiptsEnabledType, AllowImmersiveReader, AllowPriorityMessages, AllowSmartReply, AllowRemoveUser, AllowVideoMessages, ChannelsInChatListEnabledType, AudioMessageEnabledType, AllowCommunicationComplianceEndUserReporting, InOrganizationChatControl, UsersCanDeleteBotMessages)
        $g = $mp | Where-Object Identity -eq 'Global' | Select-Object -First 1
        if ($g -and $g.AllowUserChat -eq $false) { Add-DiagFinding -Severity Warning -Area 'Messaging' -Title 'Global messaging policy disables 1:1/group chat' }
    } | Out-Null

    Invoke-DiagStep -Name 'App setup / permission policies' -Area 'Apps' -ScriptBlock {
        $as = @(Get-CsTeamsAppSetupPolicy -ErrorAction Stop)
        Add-DiagData -Section 'App setup policies' -Data @($as | ForEach-Object { [pscustomobject]@{ Identity = $_.Identity; AllowSideLoading = $_.AllowSideLoading; AllowUserPinning = $_.AllowUserPinning; PinnedAppBarApps = (@($_.PinnedAppBarApps | ForEach-Object { $_.Id }) -join ', '); AppPresetList = (@($_.AppPresetList | ForEach-Object { $_.Id }) -join ', ') } })
        $g = $as | Where-Object Identity -eq 'Global' | Select-Object -First 1
        if ($g -and -not $g.AllowSideLoading) { Add-DiagFinding -Severity Info -Area 'Apps' -Title 'Custom app upload (sideloading) is disabled in the Global app setup policy' -Detail 'Explains "Upload a custom app" missing for developers.' }
        $ap = @(Get-CsTeamsAppPermissionPolicy -ErrorAction SilentlyContinue)
        if ($ap) { Add-DiagData -Section 'App permission policies (legacy)' -Data @($ap | Select-DiagObject -Property Identity, DefaultCatalogAppsType, GlobalCatalogAppsType, PrivateCatalogAppsType) -Description 'Tenants on app-centric management control availability per app in the Teams admin center instead.' }
    } | Out-Null

    Invoke-DiagStep -Name 'Channels and upgrade policies' -Area 'Policies' -ScriptBlock {
        $cp = @(Get-CsTeamsChannelsPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Channels policies' -Data @($cp | Select-DiagObject -Property Identity, AllowOrgWideTeamCreation, AllowPrivateChannelCreation, AllowSharedChannelCreation, AllowChannelSharingToExternalUser, AllowUserToParticipateInExternalSharedChannel, EnablePrivateTeamDiscovery)
        $g = $cp | Where-Object Identity -eq 'Global' | Select-Object -First 1
        if ($g -and $g.AllowPrivateChannelCreation -eq $false) { Add-DiagFinding -Severity Info -Area 'Policies' -Title 'Private channel creation disabled in the Global channels policy' }
        if ($g -and $g.AllowSharedChannelCreation -eq $false) { Add-DiagFinding -Severity Info -Area 'Policies' -Title 'Shared channel creation disabled in the Global channels policy' }
        $up = @(Get-CsTeamsUpgradePolicy -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Upgrade policies' -Data @($up | Select-DiagObject -Property Identity, Mode, NotifySfbUsers)
        $gu = $up | Where-Object Identity -eq 'Global' | Select-Object -First 1
        if ($gu -and $gu.Mode -ne 'TeamsOnly') { Add-DiagFinding -Severity Warning -Area 'Policies' -Title "Tenant-wide upgrade mode is $($gu.Mode) (not TeamsOnly)" }
        $upd = @(Get-CsTeamsUpdateManagementPolicy -ErrorAction SilentlyContinue)
        if ($upd) { Add-DiagData -Section 'Update management policies' -Data @($upd | Select-DiagObject -Property Identity, AllowManagedUpdates, AllowPreview, AllowPublicPreview, UpdateDayOfWeek, UpdateTime, DisabledInProductMessages) }
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
