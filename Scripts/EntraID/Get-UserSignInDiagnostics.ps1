<#
.SYNOPSIS
    "User can't sign in / keeps getting prompted": account state, recent sign-ins with decoded error codes, Conditional Access results, MFA methods, risk, licenses, groups/roles and devices.

.DESCRIPTION
    Collects everything needed to explain a sign-in problem for one user:
      - Account: enabled, sync state, provisioning errors, password age, session revocation, guest state
      - Sign-in activity (last interactive / non-interactive / successful)
      - Recent sign-in log entries with error codes decoded and failed Conditional Access policies named
      - Registered authentication methods (MFA), per-user MFA state, Identity Protection risk
      - License assignment errors, group memberships, admin roles, registered/owned devices

.PARAMETER UserPrincipalName
    The user to check. Prompted if omitted.

.PARAMETER Days
    Days of sign-in logs to read (default 7, max 30).

.PARAMETER MaxSignIns
    Max sign-in records to read (default 300).

.PARAMETER IncludeNonInteractive
    Also read non-interactive sign-ins (beta endpoint) - useful for "Outlook/Teams keeps prompting" cases.

.EXAMPLE
    .\Get-UserSignInDiagnostics.ps1 -UserPrincipalName jane@contoso.com -Days 3 -IncludeNonInteractive

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader (or Security Reader + Reports Reader). Sign-in logs require Entra ID P1; risk data requires P2.
    Scopes     : User.Read.All, AuditLog.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All, Policy.Read.All
    Read-only  : HTTP GET requests only.
#>
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [ValidateRange(1, 30)][int]$Days = 7,
    [ValidateRange(10, 5000)][int]$MaxSignIns = 300,
    [switch]$IncludeNonInteractive,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $UserPrincipalName) { $UserPrincipalName = Read-DiagValue -Prompt 'User principal name (e.g. jane@contoso.com)' -Pattern '@' -PatternHint 'Enter a UPN like user@domain.com' }
if (-not $PSBoundParameters.ContainsKey('IncludeNonInteractive')) { $IncludeNonInteractive = Read-DiagYesNo -Prompt 'Include non-interactive sign-ins (token refresh by Outlook/Teams etc.)?' -Default $false }

Start-DiagRun -Name 'Get-UserSignInDiagnostics' -Title 'Entra ID - User Sign-in Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ UserPrincipalName = $UserPrincipalName; Days = $Days; MaxSignIns = $MaxSignIns; IncludeNonInteractive = [bool]$IncludeNonInteractive })
$legacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP', 'MAPI Over HTTP', 'Offline Address Book', 'Outlook Anywhere (RPC over HTTP)', 'Exchange Web Services', 'AutoDiscover', 'Exchange Online PowerShell', 'Other clients', 'Reporting Web Services', 'Universal Outlook')
try {
    Connect-DiagGraph -Scopes 'User.Read.All', 'AuditLog.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All', 'Policy.Read.All' -TenantId $TenantId
    $upnEnc = [uri]::EscapeDataString($UserPrincipalName)
    $now = (Get-Date).ToUniversalTime()

    # --- Account
    $user = Invoke-DiagStep -Name 'User account' -Area 'Account' -ScriptBlock {
        $sel = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,creationType,externalUserState,externalUserStateChangeDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesDomainName,onPremisesProvisioningErrors,passwordPolicies,lastPasswordChangeDateTime,signInSessionsValidFromDateTime,usageLocation,assignedLicenses,licenseAssignmentStates,proxyAddresses,signInActivity'
        try { Invoke-DiagGraph -Uri "v1.0/users/$upnEnc`?`$select=$sel" }
        catch {
            if ($_.Exception.Message -match 'signInActivity|Premium|403|Forbidden') {
                Write-DiagInfo 'signInActivity not available (needs Entra ID P1 + AuditLog.Read.All); retrying without it' -Level Dim
                Invoke-DiagGraph -Uri ("v1.0/users/$upnEnc`?`$select=" + ($sel -replace ',signInActivity', ''))
            }
            else { throw }
        }
    }
    if (-not $user) { throw "User '$UserPrincipalName' was not found." }
    Register-DiagSensitiveValue -Value $user.displayName -Category name

    Add-DiagData -Section 'Account' -Data ($user | Select-DiagObject -Property displayName, userPrincipalName, mail, id, accountEnabled, userType, createdDateTime, creationType, externalUserState, onPremisesSyncEnabled, onPremisesLastSyncDateTime, onPremisesDomainName, passwordPolicies, lastPasswordChangeDateTime, signInSessionsValidFromDateTime, usageLocation, proxyAddresses)
    if ($user.signInActivity) { Add-DiagData -Section 'Sign-in activity' -Data $user.signInActivity }

    if ($user.accountEnabled -eq $false) {
        $src = if ($user.onPremisesSyncEnabled) { 'The account is synced - enable it in on-premises Active Directory.' } else { 'Enable the account in Entra ID if appropriate.' }
        Add-DiagFinding -Severity Critical -Area 'Account' -Title 'Account is DISABLED - sign-in is blocked' -Recommendation $src
    }
    if ($user.userType -eq 'Guest' -and $user.externalUserState -eq 'PendingAcceptance') {
        Add-DiagFinding -Severity Warning -Area 'Account' -Title 'Guest has not redeemed the invitation (PendingAcceptance)' -Recommendation 'Resend the invitation or have the guest use the redemption link.'
    }
    foreach ($e in @($user.onPremisesProvisioningErrors)) {
        if ($e) { Add-DiagFinding -Severity Critical -Area 'Sync' -Title "Directory sync provisioning error: $($e.category) on $($e.propertyCausingError)" -Detail "Value: $($e.value)  Occurred: $($e.occurredDateTime)" -Recommendation 'Fix the duplicate/invalid attribute in on-premises AD; see Get-DirectorySyncHealth.ps1.' }
    }
    $pwdChanged = ConvertTo-DiagDate $user.lastPasswordChangeDateTime
    if ($pwdChanged -and ($now - $pwdChanged).TotalHours -lt 48) {
        Add-DiagFinding -Severity Info -Area 'Account' -Title "Password changed recently ($pwdChanged UTC)" -Detail 'Apps/devices still using the old password produce 50126/50133 errors and repeated prompts.' -Recommendation 'Have the user re-sign-in on phones (mail apps), Outlook, mapped drives and Wi-Fi.'
    }
    $rev = ConvertTo-DiagDate $user.signInSessionsValidFromDateTime
    if ($rev -and $user.createdDateTime -and ($now - $rev).TotalDays -lt 7 -and ($rev - (ConvertTo-DiagDate $user.createdDateTime)).TotalMinutes -gt 5) {
        Add-DiagFinding -Severity Info -Area 'Account' -Title "Sessions were revoked on $rev UTC" -Detail 'All refresh tokens issued before this time are invalid - users are prompted to sign in again everywhere.'
    }
    if ($user.signInActivity) {
        $last = ConvertTo-DiagDate $user.signInActivity.lastSuccessfulSignInDateTime
        if (-not $last) { $last = ConvertTo-DiagDate $user.signInActivity.lastSignInDateTime }
        if ($last -and ($now - $last).TotalDays -gt 30) { Add-DiagFinding -Severity Info -Area 'Account' -Title "No successful sign-in for $([int]($now - $last).TotalDays) days" }
    }
    if (@($user.assignedLicenses).Count -gt 0 -and -not $user.usageLocation) {
        Add-DiagFinding -Severity Warning -Area 'Licensing' -Title 'Licensed user has no usage location' -Recommendation 'Some services (Teams Phone, Exchange) cannot be provisioned without usageLocation.'
    }

    # --- Licenses
    Invoke-DiagStep -Name 'Licenses' -Area 'Licensing' -ScriptBlock {
        $skuMap = @{}
        foreach ($s in @(Invoke-DiagGraph -Uri 'v1.0/subscribedSkus?$select=skuId,skuPartNumber' -All)) { $skuMap[[string]$s.skuId] = $s.skuPartNumber }
        $rows = foreach ($st in @($user.licenseAssignmentStates)) {
            [pscustomobject]@{
                Sku = $skuMap[[string]$st.skuId]; SkuId = $st.skuId; State = $st.state; Error = $st.error
                AssignedVia = if ($st.assignedByGroup) { "Group $($st.assignedByGroup)" } else { 'Direct' }
                DisabledPlans = @($st.disabledPlans).Count; LastUpdated = $st.lastUpdatedDateTime
            }
        }
        Add-DiagData -Section 'Licenses' -Data @($rows)
        foreach ($r in @($rows | Where-Object { $_.Error -and $_.Error -ne 'None' })) {
            Add-DiagFinding -Severity Critical -Area 'Licensing' -Title "License $($r.Sku) failed to apply: $($r.Error)" -Recommendation 'CountViolation = no licenses left; MutuallyExclusiveViolation = conflicting plans; DependencyViolation = missing prerequisite plan; ProhibitedInUsageLocationViolation = service not offered in usage location.'
        }
        if (@($rows).Count -eq 0) { Add-DiagFinding -Severity Info -Area 'Licensing' -Title 'User has no licenses assigned' }
    } | Out-Null

    # --- Sign-in logs
    $since = $now.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = New-Object System.Collections.Generic.List[object]
    Invoke-DiagStep -Name "Interactive sign-ins (last $Days days)" -Area 'Sign-ins' -ScriptBlock {
        $r = Invoke-DiagGraph -Uri "v1.0/auditLogs/signIns?`$filter=userId eq '$($user.id)' and createdDateTime ge $since&`$top=500" -All -MaxItems $MaxSignIns
        foreach ($x in @($r)) { $signIns.Add($x) }
        Write-DiagInfo "$(@($r).Count) interactive sign-in(s)" -Level Dim
    } | Out-Null
    if ($IncludeNonInteractive) {
        Invoke-DiagStep -Name 'Non-interactive sign-ins (beta endpoint)' -Area 'Sign-ins' -ScriptBlock {
            $r = Invoke-DiagGraph -Uri "beta/auditLogs/signIns?`$filter=userId eq '$($user.id)' and createdDateTime ge $since and signInEventTypes/any(t: t eq 'nonInteractiveUser')&`$top=500" -All -MaxItems $MaxSignIns
            foreach ($x in @($r)) { $signIns.Add($x) }
            Write-DiagInfo "$(@($r).Count) non-interactive sign-in(s)" -Level Dim
        } | Out-Null
    }

    $rows = foreach ($s in ($signIns | Sort-Object createdDateTime -Descending)) {
        $code = [string]$s.status.errorCode
        $info = Get-DiagSignInErrorInfo -Code $code
        $failedCa = @($s.appliedConditionalAccessPolicies | Where-Object { $_.result -eq 'failure' } | ForEach-Object { $_.displayName })
        [pscustomobject]@{
            TimeUtc = $s.createdDateTime; Interactive = $s.isInteractive; App = $s.appDisplayName; Resource = $s.resourceDisplayName
            ClientApp = $s.clientAppUsed; ErrorCode = $code; Result = if ($code -eq '0') { 'Success' } elseif ($info.IsInterrupt) { 'Interrupted' } else { 'Failure' }
            Reason = if ($code -ne '0') { $info.Description } else { '' }; FailureReason = $s.status.failureReason; AdditionalDetails = $s.status.additionalDetails
            ConditionalAccess = $s.conditionalAccessStatus; FailedCAPolicies = ($failedCa -join '; '); AuthRequirement = $s.authenticationRequirement
            IP = $s.ipAddress; Location = (@($s.location.city, $s.location.countryOrRegion) | Where-Object { $_ }) -join ', '
            OS = $s.deviceDetail.operatingSystem; Browser = $s.deviceDetail.browser; DeviceCompliant = $s.deviceDetail.isCompliant; DeviceManaged = $s.deviceDetail.isManaged
            JoinType = $s.deviceDetail.trustType; Risk = $s.riskLevelDuringSignIn; CorrelationId = $s.correlationId; RequestId = $s.id
        }
    }
    $rows = @($rows)
    Add-DiagData -Section 'Sign-in log' -Data $rows -Description 'Most recent first. Give CorrelationId + RequestId + TimeUtc to Microsoft support when opening a case.'

    if ($rows.Count -gt 0) {
        $fail = @($rows | Where-Object { $_.Result -eq 'Failure' })
        $summary = @($rows | Where-Object { $_.ErrorCode -ne '0' } | Group-Object ErrorCode | Sort-Object Count -Descending | ForEach-Object {
                $i = Get-DiagSignInErrorInfo -Code $_.Name
                [pscustomobject]@{ ErrorCode = $_.Name; Count = $_.Count; Meaning = $i.Description; Interrupt = $i.IsInterrupt; Hint = $i.Hint; Apps = (@($_.Group.App | Select-Object -Unique) -join ', '); LastSeen = ($_.Group | Select-Object -First 1).TimeUtc }
            })
        Add-DiagData -Section 'Sign-in errors summary' -Data $summary
        Add-DiagFinding -Severity Info -Area 'Sign-ins' -Title "$($rows.Count) sign-in(s): $(@($rows | Where-Object Result -eq 'Success').Count) success, $($fail.Count) failure, $(@($rows | Where-Object Result -eq 'Interrupted').Count) interrupted" -Quiet

        foreach ($g in @($summary | Where-Object { -not $_.Interrupt })) {
            $sev = if ($g.ErrorCode -in '50053', '50057', '53003', '50055', '50144', '53000', '50155') { 'Critical' } elseif ($g.Count -ge 3) { 'Warning' } else { 'Info' }
            Add-DiagFinding -Severity $sev -Area 'Sign-ins' -Title "Error $($g.ErrorCode) x$($g.Count): $($g.Meaning)" -Detail "Apps: $($g.Apps). Last seen $($g.LastSeen)" -Recommendation $g.Hint
        }
        $caFail = @($rows | Where-Object { $_.FailedCAPolicies } | Group-Object FailedCAPolicies)
        foreach ($c in $caFail) {
            Add-DiagFinding -Severity Warning -Area 'Conditional Access' -Title "Blocked/failed by Conditional Access policy: $($c.Name) (x$($c.Count))" -Recommendation 'Review the policy conditions/grant controls with Get-ConditionalAccessReport.ps1 -UserPrincipalName <user>.'
        }
        $legacy = @($rows | Where-Object { $legacyClients -contains $_.ClientApp })
        if ($legacy.Count -gt 0) {
            Add-DiagFinding -Severity Warning -Area 'Sign-ins' -Title "$($legacy.Count) sign-in(s) used legacy/basic-auth clients ($((@($legacy.ClientApp | Select-Object -Unique)) -join ', '))" -Recommendation 'Legacy protocols are blocked by Microsoft/most CA policies. Move the device/app to modern auth (Outlook, Outlook mobile, OAuth SMTP).'
        }
        $bad = @($rows | Where-Object { $_.ErrorCode -eq '50126' } | Group-Object IP | Where-Object { $_.Count -ge 5 })
        foreach ($b in $bad) { Add-DiagFinding -Severity Warning -Area 'Sign-ins' -Title "$($b.Count) bad-password attempts from one IP ($($b.Name))" -Recommendation 'Either a device with a stale saved password, or an attack. If the IP is unknown, reset the password and revoke sessions.' }
        $countries = @($rows | Where-Object { $_.Result -eq 'Success' -and $_.Location } | ForEach-Object { ($_.Location -split ', ')[-1] } | Select-Object -Unique)
        if ($countries.Count -gt 1) { Add-DiagFinding -Severity Info -Area 'Sign-ins' -Title "Successful sign-ins from $($countries.Count) countries: $($countries -join ', ')" -Recommendation 'Confirm travel/VPN; otherwise investigate possible compromise.' }
        foreach ($r in @($rows | Where-Object { $_.Risk -in 'high', 'medium' } | Select-Object -First 3)) { Add-DiagFinding -Severity Warning -Area 'Risk' -Title "Sign-in at $($r.TimeUtc) had $($r.Risk) risk" }
        if ($fail.Count -eq 0) { Add-DiagFinding -Severity OK -Area 'Sign-ins' -Title 'No hard sign-in failures in the period' }
    }
    else {
        Add-DiagFinding -Severity Info -Area 'Sign-ins' -Title 'No sign-in records returned for the period' -Recommendation 'If the user reports failures, they may be failing before reaching Entra ID (wrong tenant/UPN, network, federation server) - try -IncludeNonInteractive or check the device with Get-LocalEntraJoinStatus.ps1.'
    }

    # --- Authentication methods
    Invoke-DiagStep -Name 'Registered authentication methods' -Area 'MFA' -ScriptBlock {
        $methods = @(Invoke-DiagGraph -Uri "v1.0/users/$($user.id)/authentication/methods" -All)
        $rows = foreach ($m in $methods) {
            $type = ([string]$m.'@odata.type') -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            $detail = @($m.displayName, $m.phoneType, $m.model, $m.deviceTag, $m.phoneNumber, $m.emailAddress) | Where-Object { $_ }
            [pscustomobject]@{ Method = $type; Detail = ($detail -join ' | '); Created = $m.createdDateTime }
        }
        Add-DiagData -Section 'Authentication methods' -Data @($rows)
        $strong = @($rows | Where-Object { $_.Method -notin 'password', 'email' })
        if ($strong.Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'MFA' -Title 'No MFA method registered (password only)' -Recommendation 'User will be forced to register at next sign-in (or blocked if registration is restricted). Consider issuing a Temporary Access Pass.' }
        if ($rows | Where-Object { $_.Method -eq 'temporaryAccessPass' }) { Add-DiagFinding -Severity Info -Area 'MFA' -Title 'A Temporary Access Pass exists for this user' }
    } | Out-Null

    Invoke-DiagStep -Name 'Per-user MFA state (beta)' -Area 'MFA' -ScriptBlock {
        $req = Invoke-DiagGraph -Uri "beta/users/$($user.id)/authentication/requirements"
        Add-DiagData -Section 'Per-user MFA' -Data $req
        if ($req.perUserMfaState -in 'enforced', 'enabled') { Add-DiagFinding -Severity Info -Area 'MFA' -Title "Legacy per-user MFA is '$($req.perUserMfaState)'" -Recommendation 'Per-user MFA overrides Conditional Access remember/frequency settings and can cause extra prompts. Prefer CA-based MFA.' }
    } | Out-Null

    # --- Risk
    Invoke-DiagStep -Name 'Identity Protection risk' -Area 'Risk' -ScriptBlock {
        try {
            $risk = Invoke-DiagGraph -Uri "v1.0/identityProtection/riskyUsers/$($user.id)"
            Add-DiagData -Section 'User risk' -Data ($risk | Select-DiagObject -Property riskLevel, riskState, riskDetail, riskLastUpdatedDateTime, isProcessing)
            if ($risk.riskState -in 'atRisk', 'confirmedCompromised') {
                $sev = if ($risk.riskLevel -eq 'high' -or $risk.riskState -eq 'confirmedCompromised') { 'Critical' } else { 'Warning' }
                Add-DiagFinding -Severity $sev -Area 'Risk' -Title "User risk: $($risk.riskLevel) ($($risk.riskState))" -Recommendation 'A user-risk CA policy may block sign-in or force a password change. Investigate in Entra ID > Protection > Risky users.'
            }
        }
        catch { if ($_.Exception.Message -match '404|NotFound') { Add-DiagData -Section 'User risk' -Data 'No risk record for this user.' } else { throw } }
    } | Out-Null

    # --- Groups & roles
    Invoke-DiagStep -Name 'Group memberships and admin roles' -Area 'Membership' -ScriptBlock {
        $mem = @(Invoke-DiagGraph -Uri "v1.0/users/$($user.id)/transitiveMemberOf?`$select=id,displayName,groupTypes,securityEnabled,mailEnabled,onPremisesSyncEnabled" -All -MaxItems 2000)
        $roles = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
        $groups = @($mem | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | ForEach-Object {
                [pscustomobject]@{ Group = $_.displayName; Id = $_.id; Type = if ($_.groupTypes -contains 'Unified') { 'Microsoft 365' } elseif ($_.securityEnabled) { 'Security' } else { 'Distribution' }; Dynamic = ($_.groupTypes -contains 'DynamicMembership'); Synced = [bool]$_.onPremisesSyncEnabled }
            })
        Add-DiagData -Section 'Admin roles' -Data @($roles | ForEach-Object { [pscustomobject]@{ Role = $_.displayName; Id = $_.id } })
        Add-DiagData -Section 'Group memberships (transitive)' -Data $groups
        if ($roles.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Membership' -Title "User holds $($roles.Count) admin role(s): $((@($roles.displayName)) -join ', ')" -Detail 'Admin-targeted CA policies (e.g. phishing-resistant MFA) may apply.' }
    } | Out-Null

    # --- Devices
    Invoke-DiagStep -Name 'Registered / owned devices' -Area 'Devices' -ScriptBlock {
        $dev = @(Invoke-DiagGraph -Uri "v1.0/users/$($user.id)/registeredDevices?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime" -All)
        $dev += @(Invoke-DiagGraph -Uri "v1.0/users/$($user.id)/ownedDevices?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime" -All)
        $dev = @($dev | Sort-Object id -Unique)
        Add-DiagData -Section 'Devices' -Data ($dev | Select-DiagObject -Property displayName, deviceId, operatingSystem, operatingSystemVersion, trustType, isCompliant, isManaged, accountEnabled, approximateLastSignInDateTime)
        foreach ($d in @($dev | Where-Object { $_.accountEnabled -eq $false })) { Add-DiagFinding -Severity Warning -Area 'Devices' -Title "Device $($d.displayName) is disabled in Entra ID" -Recommendation 'Sign-ins from it fail device authentication (50155/50097).' }
        foreach ($d in @($dev | Where-Object { $_.isManaged -and $_.isCompliant -eq $false })) { Add-DiagFinding -Severity Warning -Area 'Devices' -Title "Device $($d.displayName) is managed but NOT compliant" -Recommendation 'CA policies requiring a compliant device will block it. Check with Get-DeviceDiagnostics.ps1.' }
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
