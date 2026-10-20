<#
.SYNOPSIS
    Team diagnostics: owners/members/guests, archived state, channels (standard/private/shared), member/guest/messaging settings - or a tenant scan for ownerless, single-owner and archived teams.

.DESCRIPTION
    Typical tickets: "nobody can manage this team", "can't add guests", "can't create channels",
    "team is read-only", "can't delete/edit messages".

.PARAMETER Team
    Team display name or GroupId. Prompted if omitted (or choose a tenant scan).

.PARAMETER ScanTenant
    Scan all teams (up to -MaxTeams) for owner problems instead of one team.

.EXAMPLE
    .\Get-TeamsTeamDiagnostics.ps1 -Team "Finance"
    .\Get-TeamsTeamDiagnostics.ps1 -ScanTenant -MaxTeams 2000

.NOTES
    Connection : Microsoft Teams PowerShell
    Roles      : Global Reader or Teams Administrator (read)
    Read-only  : Only Get-Team* cmdlets are called.
#>
[CmdletBinding()]
param(
    [string]$Team,
    [switch]$ScanTenant,
    [int]$MaxTeams = 1000,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Team -and -not $ScanTenant) {
    $Team = Read-DiagValue -Prompt 'Team name or GroupId (or type * to scan all teams for owner problems)'
    if ($Team -eq '*') { $ScanTenant = $true; $Team = $null }
}

Start-DiagRun -Name 'Get-TeamsTeamDiagnostics' -Title "Microsoft Teams - $(if ($ScanTenant) { 'Tenant Team Scan' } else { 'Team Diagnostics' })" -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Team = $Team; ScanTenant = [bool]$ScanTenant; MaxTeams = $MaxTeams })
try {
    Connect-DiagTeams -TenantId $TenantId | Out-Null

    if ($ScanTenant) {
        $all = Invoke-DiagStep -Name 'Listing teams' -Area 'Scan' -ScriptBlock { @(Get-Team -ErrorAction Stop | Select-Object -First $MaxTeams) }
        $rows = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($t in @($all)) {
            $i++
            if ($i % 25 -eq 0) { Write-DiagInfo "$i / $(@($all).Count)" -Level Dim }
            $owners = @(); $count = $null
            try {
                $users = @(Get-TeamUser -GroupId $t.GroupId -ErrorAction Stop)
                $owners = @($users | Where-Object Role -eq 'owner')
                $count = $users.Count
                $guests = @($users | Where-Object Role -eq 'guest').Count
            }
            catch { $guests = $null }
            $rows.Add([pscustomobject]@{ Team = $t.DisplayName; GroupId = $t.GroupId; Visibility = $t.Visibility; Archived = $t.Archived; Owners = $owners.Count; Members = $count; Guests = $guests })
        }
        $arr = $rows.ToArray()
        Add-DiagData -Section 'Teams' -Data $arr
        $noOwner = @($arr | Where-Object { $_.Owners -eq 0 -and $null -ne $_.Members })
        $oneOwner = @($arr | Where-Object { $_.Owners -eq 1 })
        if ($noOwner.Count) { Add-DiagFinding -Severity Warning -Area 'Scan' -Title "$($noOwner.Count) ownerless team(s)" -Detail (($noOwner | Select-Object -First 20 | ForEach-Object Team) -join ', ') -Recommendation 'Assign owners (or enable the Microsoft 365 group ownership governance policy).' }
        if ($oneOwner.Count) { Add-DiagFinding -Severity Info -Area 'Scan' -Title "$($oneOwner.Count) team(s) with a single owner" -Recommendation 'Recommend at least 2 owners per team.' }
        Add-DiagFinding -Severity Info -Area 'Scan' -Title "$(@($arr | Where-Object Archived).Count) archived team(s), $(@($arr | Where-Object { $_.Guests -gt 0 }).Count) team(s) with guests" -Quiet
        if (@($all).Count -ge $MaxTeams) { Add-DiagFinding -Severity Warning -Area 'Scan' -Title "Scan capped at $MaxTeams teams" }
    }
    else {
        $t = Invoke-DiagStep -Name "Finding team '$Team'" -Area 'Team' -ScriptBlock {
            if ($Team -match '^[0-9a-fA-F-]{36}$') { Get-Team -GroupId $Team -ErrorAction Stop }
            else {
                $m = @(Get-Team -DisplayName $Team -ErrorAction Stop)
                if ($m.Count -eq 0) { throw "No team named '$Team'." }
                if ($m.Count -gt 1) {
                    $pick = Read-DiagChoice -Prompt 'Several teams match - pick one' -Options @($m | ForEach-Object { [pscustomobject]@{ Label = "$($_.DisplayName) [$($_.GroupId)] $($_.Visibility)"; Value = $_ } })
                    $pick
                }
                else { $m[0] }
            }
        }
        if (-not $t) { throw "Team '$Team' not found." }
        $gid = $t.GroupId
        Add-DiagData -Section 'Team settings' -Data ($t | Select-DiagObject -Property DisplayName, GroupId, Description, Visibility, Archived, MailNickName, Classification, ShowInTeamsSearchAndSuggestions,
            AllowGuestCreateUpdateChannels, AllowGuestDeleteChannels, AllowCreateUpdateChannels, AllowCreatePrivateChannels, AllowDeleteChannels, AllowAddRemoveApps, AllowCreateUpdateRemoveTabs, AllowCreateUpdateRemoveConnectors,
            AllowUserEditMessages, AllowUserDeleteMessages, AllowOwnerDeleteMessages, AllowTeamMentions, AllowChannelMentions, AllowGiphy, GiphyContentRating, AllowStickersAndMemes, AllowCustomMemes)
        if ($t.Archived) { Add-DiagFinding -Severity Info -Area 'Team' -Title 'Team is ARCHIVED (read-only)' -Detail 'Members cannot post, edit or upload until an owner/admin restores it.' }
        if ($t.AllowUserEditMessages -eq $false -or $t.AllowUserDeleteMessages -eq $false) { Add-DiagFinding -Severity Info -Area 'Team' -Title 'Members cannot edit/delete their messages in this team' }
        if ($t.AllowCreateUpdateChannels -eq $false) { Add-DiagFinding -Severity Info -Area 'Team' -Title 'Members cannot create/update channels (owners only)' }

        $users = Invoke-DiagStep -Name 'Owners, members, guests' -Area 'Membership' -ScriptBlock { @(Get-TeamUser -GroupId $gid -ErrorAction Stop) }
        if ($null -ne $users) {
            $owners = @($users | Where-Object Role -eq 'owner'); $guests = @($users | Where-Object Role -eq 'guest')
            Add-DiagData -Section 'Membership summary' -Data ([ordered]@{ Owners = $owners.Count; Members = @($users | Where-Object Role -eq 'member').Count; Guests = $guests.Count; Total = @($users).Count })
            Add-DiagData -Section 'Members' -Data @($users | Select-DiagObject -Property User, Name, Role, UserId)
            if ($owners.Count -eq 0) { Add-DiagFinding -Severity Critical -Area 'Membership' -Title 'Team has NO owners' -Recommendation 'Nobody can manage membership or settings. A Teams admin must add an owner.' }
            elseif ($owners.Count -eq 1) { Add-DiagFinding -Severity Warning -Area 'Membership' -Title 'Team has a single owner' -Recommendation 'Add a second owner to avoid an orphaned team.' }
            if (@($users).Count -gt 24000) { Add-DiagFinding -Severity Warning -Area 'Membership' -Title "Team has $(@($users).Count) members (limit 25,000)" }
            if ($guests.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Membership' -Title "$($guests.Count) guest(s) in the team" -Quiet }
        }

        $channels = Invoke-DiagStep -Name 'Channels' -Area 'Channels' -ScriptBlock { @(Get-TeamChannel -GroupId $gid -ErrorAction Stop) }
        if ($null -ne $channels) {
            $chRows = foreach ($c in $channels) {
                $memberCount = $null
                if ($c.MembershipType -in 'Private', 'Shared') {
                    try { $memberCount = @(Get-TeamChannelUser -GroupId $gid -DisplayName $c.DisplayName -ErrorAction Stop).Count } catch { $memberCount = 'n/a' }
                }
                [pscustomobject]@{ Channel = $c.DisplayName; MembershipType = $c.MembershipType; Members = $memberCount; Description = $c.Description; Id = $c.Id }
            }
            Add-DiagData -Section 'Channels' -Data @($chRows)
            $priv = @($chRows | Where-Object MembershipType -eq 'Private').Count
            if (@($channels).Count -gt 950) { Add-DiagFinding -Severity Warning -Area 'Channels' -Title "Team has $(@($channels).Count) channels (limit 1,000 incl. deleted)" }
            if ($priv -gt 28) { Add-DiagFinding -Severity Info -Area 'Channels' -Title "Team has $priv private channels (limit 30)" }
        }
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
