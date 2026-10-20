<#
.SYNOPSIS
    Conditional Access report in plain language (IDs resolved to names), named locations, security defaults, recent policy changes, and optionally which policies target a specific user.

.DESCRIPTION
    Use when sign-ins are blocked/prompting unexpectedly. Every policy is flattened to one readable row
    (who / what apps / conditions / grant / session). Highlights: report-only vs enabled policies, policies
    changed in the last 14 days, missing legacy-auth block, all-users block policies without exclusions.
    With -UserPrincipalName, evaluates user/group/role scoping statically to list the policies that
    include or exclude that user (apps and conditions still apply at sign-in time).

.PARAMETER UserPrincipalName
    Optional user to evaluate scoping for.

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -UserPrincipalName jane@contoso.com

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader, Security Reader or Conditional Access Administrator (read)
    Scopes     : Policy.Read.All, Directory.Read.All, Application.Read.All
    Read-only  : HTTP GET requests only (no What-If API calls, those are POST).
#>
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $PSBoundParameters.ContainsKey('UserPrincipalName')) { $UserPrincipalName = Read-DiagValue -Prompt 'Evaluate policy targeting for a user (UPN)' -Optional }

Start-DiagRun -Name 'Get-ConditionalAccessReport' -Title 'Entra ID - Conditional Access Report' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ UserPrincipalName = $UserPrincipalName })
try {
    Connect-DiagGraph -Scopes 'Policy.Read.All', 'Directory.Read.All', 'Application.Read.All' -TenantId $TenantId

    $nameCache = @{}
    $lookups = 0
    $special = @{ All = 'All'; None = 'None'; GuestsOrExternalUsers = 'All guests/external users'; Office365 = 'Office 365 (app group)'; MicrosoftAdminPortals = 'Microsoft Admin Portals'; AllTrusted = 'All trusted locations' }
    $roleTemplates = @{}
    Invoke-DiagStep -Name 'Directory role templates' -Area 'Lookup' -ScriptBlock {
        foreach ($r in @(Invoke-DiagGraph -Uri 'v1.0/directoryRoleTemplates?$select=id,displayName' -All)) { $roleTemplates[[string]$r.id] = $r.displayName }
    } | Out-Null
    $locations = @{}

    function Resolve-Ids {
        param($Ids, [ValidateSet('object', 'role', 'app', 'location')][string]$Kind)
        $names = foreach ($id in @($Ids)) {
            if (-not $id) { continue }
            $id = [string]$id
            if ($special.ContainsKey($id)) { $special[$id]; continue }
            if ($Kind -eq 'role') { if ($roleTemplates.ContainsKey($id)) { $roleTemplates[$id] } else { $id }; continue }
            if ($Kind -eq 'location') { if ($locations.ContainsKey($id)) { $locations[$id] } else { $id }; continue }
            $key = "$Kind|$id"
            if (-not $nameCache.ContainsKey($key)) {
                $nm = $id
                if ($script:lookups -lt 400) {
                    $script:lookups++
                    try {
                        if ($Kind -eq 'app') {
                            $sp = @(Invoke-DiagGraph -Uri "v1.0/servicePrincipals?`$filter=appId eq '$id'&`$select=displayName")
                            if ($sp.Count -gt 0) { $nm = $sp[0].displayName }
                        }
                        else {
                            $o = Invoke-DiagGraph -Uri "v1.0/directoryObjects/$id"
                            $nm = if ($o.userPrincipalName) { $o.userPrincipalName } elseif ($o.displayName) { $o.displayName } else { $id }
                        }
                    }
                    catch { $nm = "$id (not found/deleted)" }
                }
                $nameCache[$key] = $nm
            }
            $nameCache[$key]
        }
        return (@($names) -join '; ')
    }

    $named = Invoke-DiagStep -Name 'Named locations' -Area 'Locations' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/identity/conditionalAccess/namedLocations' -All }
    if ($named) {
        foreach ($n in $named) { $locations[[string]$n.id] = $n.displayName }
        Add-DiagData -Section 'Named locations' -Data @($named | ForEach-Object {
                $isIp = $_.'@odata.type' -match 'ipNamedLocation'
                [pscustomobject]@{
                    Name = $_.displayName; Type = if ($isIp) { 'IP ranges' } else { 'Countries' }; Trusted = $_.isTrusted
                    Ranges = if ($isIp) { (@($_.ipRanges.cidrAddress) -join ', ') } else { (@($_.countriesAndRegions) -join ', ') }
                    IncludeUnknownCountries = $_.includeUnknownCountriesAndRegions; Modified = $_.modifiedDateTime
                }
            })
    }

    $sd = Invoke-DiagStep -Name 'Security defaults' -Area 'Policy' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy' }
    if ($sd) { Add-DiagData -Section 'Security defaults' -Data ($sd | Select-DiagObject -Property displayName, isEnabled, description) }

    $policies = Invoke-DiagStep -Name 'Conditional Access policies' -Area 'Policy' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/identity/conditionalAccess/policies' -All }
    if ($null -eq $policies) { throw 'Could not read Conditional Access policies.' }
    $policies = @($policies)

    if ($sd -and $sd.isEnabled -and $policies.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Policy' -Title 'Security defaults are ON and CA policies exist' -Detail 'Enabled CA policies cannot be used while security defaults are on.' }
    if ($sd -and -not $sd.isEnabled -and @($policies | Where-Object state -eq 'enabled').Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Policy' -Title 'No security defaults and no enabled CA policies' -Recommendation 'Users are not required to use MFA.' }

    Write-DiagInfo "Resolving names for $($policies.Count) policies" -Level Step
    $rows = foreach ($p in $policies) {
        $c = $p.conditions
        $g = $p.grantControls
        $sc = $p.sessionControls
        $grant = @()
        if ($g) {
            $grant += @($g.builtInControls)
            if ($g.authenticationStrength) { $grant += "AuthStrength: $($g.authenticationStrength.displayName)" }
            if ($g.termsOfUse) { $grant += 'TermsOfUse' }
            if ($g.customAuthenticationFactors) { $grant += @($g.customAuthenticationFactors) }
        }
        $session = @()
        if ($sc) {
            if ($sc.signInFrequency -and $sc.signInFrequency.isEnabled) { $session += "SignInFrequency: $($sc.signInFrequency.value) $($sc.signInFrequency.type) $($sc.signInFrequency.frequencyInterval)" }
            if ($sc.persistentBrowser -and $sc.persistentBrowser.isEnabled) { $session += "PersistentBrowser: $($sc.persistentBrowser.mode)" }
            if ($sc.applicationEnforcedRestrictions -and $sc.applicationEnforcedRestrictions.isEnabled) { $session += 'AppEnforcedRestrictions' }
            if ($sc.cloudAppSecurity -and $sc.cloudAppSecurity.isEnabled) { $session += "MDCA: $($sc.cloudAppSecurity.cloudAppSecurityType)" }
            if ($sc.disableResilienceDefaults) { $session += 'ResilienceDefaultsDisabled' }
        }
        [pscustomobject]@{
            Policy           = $p.displayName
            State            = $p.state
            IncludeUsers     = Resolve-Ids $c.users.includeUsers object
            IncludeGroups    = Resolve-Ids $c.users.includeGroups object
            IncludeRoles     = Resolve-Ids $c.users.includeRoles role
            IncludeGuests    = if ($c.users.includeGuestsOrExternalUsers) { [string]$c.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes } else { '' }
            ExcludeUsers     = Resolve-Ids $c.users.excludeUsers object
            ExcludeGroups    = Resolve-Ids $c.users.excludeGroups object
            ExcludeRoles     = Resolve-Ids $c.users.excludeRoles role
            IncludeApps      = Resolve-Ids $c.applications.includeApplications app
            ExcludeApps      = Resolve-Ids $c.applications.excludeApplications app
            UserActions      = (@($c.applications.includeUserActions) -join ', ')
            ClientAppTypes   = (@($c.clientAppTypes) -join ', ')
            Platforms        = if ($c.platforms) { "+" + (@($c.platforms.includePlatforms) -join ',') + " -" + (@($c.platforms.excludePlatforms) -join ',') } else { '' }
            Locations        = if ($c.locations) { "+" + (Resolve-Ids $c.locations.includeLocations location) + " -" + (Resolve-Ids $c.locations.excludeLocations location) } else { '' }
            SignInRisk       = (@($c.signInRiskLevels) -join ', ')
            UserRisk         = (@($c.userRiskLevels) -join ', ')
            DeviceFilter     = if ($c.devices -and $c.devices.deviceFilter) { "$($c.devices.deviceFilter.mode): $($c.devices.deviceFilter.rule)" } else { '' }
            Grant            = if ($g) { "$($g.operator): " + ($grant -join ', ') } else { '' }
            Session          = ($session -join '; ')
            Modified         = if ($p.modifiedDateTime) { $p.modifiedDateTime } else { $p.createdDateTime }
            Id               = $p.id
            _raw             = $p
        }
    }
    $rows = @($rows | Sort-Object State, Policy)
    Add-DiagData -Section 'Conditional Access policies' -Data @($rows | Select-Object -Property * -ExcludeProperty _raw) -Description 'One row per policy. + = include, - = exclude.'
    Add-DiagFinding -Severity Info -Area 'Policy' -Title "$($rows.Count) policies: $(@($rows | Where-Object State -eq 'enabled').Count) enabled, $(@($rows | Where-Object State -eq 'enabledForReportingButNotEnforced').Count) report-only, $(@($rows | Where-Object State -eq 'disabled').Count) disabled" -Quiet

    # --- Heuristics
    $enabled = @($rows | Where-Object State -eq 'enabled')
    foreach ($r in @($rows | Where-Object { (ConvertTo-DiagDate $_.Modified) -gt (Get-Date).ToUniversalTime().AddDays(-14) })) {
        Add-DiagFinding -Severity Info -Area 'Change' -Title "Policy '$($r.Policy)' changed on $($r.Modified) (state: $($r.State))" -Detail 'Recent policy changes are the most common cause of "it worked yesterday".' -Recommendation 'Check Entra ID audit logs (Search-AuditLogActivity.ps1 or portal) for who changed it.'
    }
    $legacyBlock = @($enabled | Where-Object { $_._raw.grantControls.builtInControls -contains 'block' -and (@($_._raw.conditions.clientAppTypes) -contains 'exchangeActiveSync' -or @($_._raw.conditions.clientAppTypes) -contains 'other') })
    if ($legacyBlock.Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Policy' -Title 'No enabled policy blocks legacy authentication clients' -Recommendation 'Create a CA policy: All users, client apps = Exchange ActiveSync + Other clients, Grant = Block.' }
    foreach ($r in @($enabled | Where-Object { $_._raw.grantControls.builtInControls -contains 'block' -and @($_._raw.conditions.users.includeUsers) -contains 'All' -and -not $_.ExcludeUsers -and -not $_.ExcludeGroups })) {
        Add-DiagFinding -Severity Warning -Area 'Policy' -Title "Block policy '$($r.Policy)' targets All users with no exclusions" -Recommendation 'Exclude emergency-access (break-glass) accounts to avoid tenant lock-out.'
    }
    $mfaAll = @($enabled | Where-Object { @($_._raw.conditions.users.includeUsers) -contains 'All' -and ($_._raw.grantControls.builtInControls -contains 'mfa' -or $_._raw.grantControls.authenticationStrength) })
    if ($mfaAll.Count -eq 0 -and -not ($sd -and $sd.isEnabled)) { Add-DiagFinding -Severity Warning -Area 'Policy' -Title 'No enabled policy requires MFA for All users' }
    foreach ($r in @($rows | Where-Object { $_.IncludeUsers -match 'not found' -or $_.IncludeGroups -match 'not found' -or $_.ExcludeGroups -match 'not found' -or $_.ExcludeUsers -match 'not found' })) {
        Add-DiagFinding -Severity Info -Area 'Policy' -Title "Policy '$($r.Policy)' references deleted users/groups" -Recommendation 'Clean up the stale object IDs.'
    }

    # --- Per-user targeting
    if ($UserPrincipalName) {
        Invoke-DiagStep -Name "Policies targeting $UserPrincipalName" -Area 'User scoping' -ScriptBlock {
            $u = Invoke-DiagGraph -Uri ("v1.0/users/" + [uri]::EscapeDataString($UserPrincipalName) + '?$select=id,userType,displayName')
            Register-DiagSensitiveValue -Value $u.displayName -Category name
            $mem = @(Invoke-DiagGraph -Uri "v1.0/users/$($u.id)/transitiveMemberOf?`$select=id,roleTemplateId" -All -MaxItems 5000)
            $groupIds = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object { [string]$_.id })
            $roleIds = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { [string]$_.roleTemplateId })
            $isGuest = $u.userType -eq 'Guest'
            $res = foreach ($r in $rows) {
                $usr = $r._raw.conditions.users
                $inc = (@($usr.includeUsers) -contains 'All') -or (@($usr.includeUsers) -contains $u.id) -or
                (@($usr.includeGroups | Where-Object { $groupIds -contains $_ }).Count -gt 0) -or
                (@($usr.includeRoles | Where-Object { $roleIds -contains $_ }).Count -gt 0) -or
                ($isGuest -and (@($usr.includeUsers) -contains 'GuestsOrExternalUsers' -or $usr.includeGuestsOrExternalUsers))
                $exc = (@($usr.excludeUsers) -contains $u.id) -or
                (@($usr.excludeGroups | Where-Object { $groupIds -contains $_ }).Count -gt 0) -or
                (@($usr.excludeRoles | Where-Object { $roleIds -contains $_ }).Count -gt 0) -or
                ($isGuest -and (@($usr.excludeUsers) -contains 'GuestsOrExternalUsers' -or $usr.excludeGuestsOrExternalUsers))
                $verdict = if ($exc) { 'Excluded' } elseif ($inc) { 'Applies (if app/conditions match)' } else { 'Not targeted' }
                [pscustomobject]@{ Policy = $r.Policy; State = $r.State; ForUser = $verdict; Apps = $r.IncludeApps; Grant = $r.Grant; Session = $r.Session; ClientAppTypes = $r.ClientAppTypes; Locations = $r.Locations; Platforms = $r.Platforms }
            }
            $res = @($res | Sort-Object @{ Expression = { if ($_.ForUser -like 'Applies*') { 0 } elseif ($_.ForUser -eq 'Excluded') { 1 } else { 2 } } }, Policy)
            Add-DiagData -Section "Policy targeting for user" -Data $res -Description 'Static evaluation of users/groups/roles only. Guest sub-types and dynamic conditions are approximated; use the sign-in log for the actual result.'
            $applies = @($res | Where-Object { $_.ForUser -like 'Applies*' -and $_.State -eq 'enabled' })
            Add-DiagFinding -Severity Info -Area 'User scoping' -Title "$($applies.Count) enabled policies can apply to the user" -Detail (($applies | ForEach-Object { "$($_.Policy) [$($_.Grant)]" }) -join ' | ')
        } | Out-Null
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
