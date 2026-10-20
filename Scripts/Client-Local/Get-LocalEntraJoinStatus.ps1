<#
.SYNOPSIS
    THIS PC: Entra ID join / hybrid join state, Primary Refresh Token (SSO) health, Windows Hello, MDM (Intune) enrollment, Intune Management Extension and clock skew - parsed from dsregcmd /status. No sign-in needed.

.DESCRIPTION
    Run on the affected Windows device (as the affected user, non-elevated is fine) for:
    "SSO not working / constant prompts", "device not compliant / not enrolled", "hybrid join pending",
    "Windows Hello not offered", "Conditional Access says device not registered".

.EXAMPLE
    .\Get-LocalEntraJoinStatus.ps1

.NOTES
    Connection : None (local device)
    Roles      : None (run as the affected user)
    Read-only  : Runs "dsregcmd /status" (read-only), reads registry keys and service state. Nothing is changed.
#>
[CmdletBinding()]
param(
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

Start-DiagRun -Name 'Get-LocalEntraJoinStatus' -Title "Local Device - Entra Join & SSO Status" -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
try {
    $ds = Invoke-DiagStep -Name 'dsregcmd /status' -Area 'Join' -ScriptBlock {
        $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
        if (-not (Test-Path -LiteralPath $exe)) { throw 'dsregcmd.exe not found (Windows 10/11 required).' }
        $out = & $exe /status 2>&1
        $sections = [ordered]@{}
        $current = 'General'
        foreach ($line in $out) {
            $l = [string]$line
            if ($l -match '^\|\s*(.+?)\s*\|?\s*$' -and $l -notmatch ':') { $current = $Matches[1].Trim(); continue }
            if ($l -match '^\s*\+-+\+\s*$') { continue }
            if ($l -match '^\s*([A-Za-z0-9 \-\(\)]+?)\s*:\s*(.*)$') {
                if (-not $sections.Contains($current)) { $sections[$current] = [ordered]@{} }
                $sections[$current][$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        $sections
    }
    if (-not $ds) { throw 'Could not read dsregcmd output.' }
    foreach ($k in $ds.Keys) { Add-DiagData -Section "dsregcmd - $k" -Data $ds[$k] }
    $flat = @{}
    foreach ($k in $ds.Keys) { foreach ($kk in $ds[$k].Keys) { if (-not $flat.ContainsKey($kk)) { $flat[$kk] = $ds[$k][$kk] } } }
    $v = { param($n) [string]$flat[$n] }
    if (& $v 'TenantName') { Register-DiagSensitiveValue -Value (& $v 'TenantName') -Category org }

    $aad = (& $v 'AzureAdJoined') -eq 'YES'
    $dom = (& $v 'DomainJoined') -eq 'YES'
    $wpj = (& $v 'WorkplaceJoined') -eq 'YES'
    $state = if ($aad -and $dom) { 'Hybrid Entra joined' } elseif ($aad) { 'Entra joined' } elseif ($dom -and $wpj) { 'Domain joined + Entra registered' } elseif ($dom) { 'Domain joined only' } elseif ($wpj) { 'Entra registered (workplace joined)' } else { 'Not joined/registered' }
    Add-DiagData -Section 'Summary' -Data ([ordered]@{
            JoinState = $state; Tenant = & $v 'TenantName'; DeviceId = & $v 'DeviceId'; DeviceAuthStatus = & $v 'DeviceAuthStatus'; TpmProtected = & $v 'TpmProtected'
            AzureAdPrt = & $v 'AzureAdPrt'; AzureAdPrtUpdateTime = & $v 'AzureAdPrtUpdateTime'; AzureAdPrtExpiryTime = & $v 'AzureAdPrtExpiryTime'; EnterprisePrt = & $v 'EnterprisePrt'
            NgcSet = & $v 'NgcSet'; WamDefaultSet = & $v 'WamDefaultSet'; MdmUrl = & $v 'MdmUrl'; ExecutingAccountName = & $v 'Executing Account Name'
        })
    Add-DiagFinding -Severity Info -Area 'Join' -Title "Join state: $state" -Quiet

    if (-not $aad -and $dom) { Add-DiagFinding -Severity Warning -Area 'Join' -Title 'Domain joined but NOT hybrid Entra joined' -Detail "Diagnostic: $(& $v 'Client ErrorCode') $(& $v 'Server ErrorCode') $(& $v 'Server Message')" -Recommendation 'Check SCP / Entra Connect device sync, that the computer object is in a synced OU, and connectivity to enterpriseregistration.windows.net (Test-M365NetworkConnectivity.ps1).' }
    if (-not $aad -and -not $dom -and -not $wpj) { Add-DiagFinding -Severity Warning -Area 'Join' -Title 'Device is not joined or registered with Entra ID' -Detail 'CA policies requiring a registered/compliant device will block access.' }
    if ((& $v 'DeviceAuthStatus') -and (& $v 'DeviceAuthStatus') -ne 'SUCCESS') { Add-DiagFinding -Severity Critical -Area 'Join' -Title "Device authentication status: $(& $v 'DeviceAuthStatus')" -Recommendation 'The device object is disabled or deleted in Entra ID. Re-enable it, or leave and re-join/re-register the device (a change).' }
    if ($aad -or $wpj) {
        if ((& $v 'AzureAdPrt') -eq 'NO') { Add-DiagFinding -Severity Critical -Area 'SSO' -Title 'No Primary Refresh Token (AzureAdPrt = NO) - single sign-on is broken' -Detail "Attempt status: $(& $v 'Attempt Status')  Error: $(& $v 'Credential Type') $(& $v 'Server Error Code') $(& $v 'Server Error Description')" -Recommendation 'Common causes: password changed but not yet used to unlock, MFA/CA on the device sign-in, TPM issues, proxy blocking login.microsoftonline.com, time skew. Lock/unlock with the password and re-run.' }
        else {
            $upd = $null
            $us = (& $v 'AzureAdPrtUpdateTime') -replace '\s*UTC\s*$', ''
            $dt = [datetime]::MinValue
            if ($us -and [datetime]::TryParse($us, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) { $upd = $dt.ToUniversalTime() }
            if ($upd -and ((Get-Date).ToUniversalTime() - $upd).TotalHours -gt 24) { Add-DiagFinding -Severity Warning -Area 'SSO' -Title "PRT last refreshed $([int]((Get-Date).ToUniversalTime() - $upd).TotalHours) hours ago (normally every 4 h)" -Recommendation 'PRT renewal is failing - check network/proxy to Entra endpoints.' }
            else { Add-DiagFinding -Severity OK -Area 'SSO' -Title 'Primary Refresh Token present and fresh' -Quiet }
        }
    }
    if ((& $v 'TpmProtected') -eq 'NO' -and $aad) { Add-DiagFinding -Severity Info -Area 'Join' -Title 'Device keys are not TPM protected' }
    if ((& $v 'NgcSet') -eq 'NO' -and $aad) { Add-DiagFinding -Severity Info -Area 'Hello' -Title 'Windows Hello for Business is not set up for this user' -Detail "PreReqResult: $(& $v 'PreReqResult')" }
    if ($aad -and -not (& $v 'MdmUrl')) { Add-DiagFinding -Severity Warning -Area 'MDM' -Title 'No MDM URL - device is not auto-enrolled into Intune' -Recommendation 'Check Entra ID > Mobility (MDM and WIP) user scope and the user''s Intune license.' }

    # MDM enrollments (registry, read-only)
    Invoke-DiagStep -Name 'MDM enrollments (registry)' -Area 'MDM' -ScriptBlock {
        $rows = foreach ($k in @(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.ProviderID) { [pscustomobject]@{ ProviderID = $p.ProviderID; UPN = $p.UPN; EnrollmentState = $p.EnrollmentState; EnrollmentType = $p.EnrollmentType; DiscoveryServiceFullURL = $p.DiscoveryServiceFullURL } }
        }
        $rows = @($rows)
        Add-DiagData -Section 'MDM enrollments' -Data $rows
        if ($aad -and @($rows | Where-Object ProviderID -eq 'MS DM Server').Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'MDM' -Title 'No Intune (MS DM Server) enrollment found on this device' }
    } | Out-Null

    Invoke-DiagStep -Name 'Intune Management Extension' -Area 'MDM' -ScriptBlock {
        $svc = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
        $log = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log'
        $lw = if (Test-Path -LiteralPath $log) { (Get-Item -LiteralPath $log).LastWriteTime } else { $null }
        Add-DiagData -Section 'Intune Management Extension' -Data ([ordered]@{ Service = if ($svc) { [string]$svc.Status } else { 'Not installed' }; StartType = if ($svc) { [string]$svc.StartType } else { '' }; LogLastWrite = $lw; LogFolder = (Split-Path $log) })
        if ($svc -and $svc.Status -ne 'Running') { Add-DiagFinding -Severity Warning -Area 'MDM' -Title "Intune Management Extension service is $($svc.Status)" -Detail 'Win32 apps, scripts and remediations will not run.' }
        if ($lw -and ((Get-Date) - $lw).TotalDays -gt 2) { Add-DiagFinding -Severity Info -Area 'MDM' -Title "IME log not written for $([int]((Get-Date) - $lw).TotalDays) days" }
    } | Out-Null

    Invoke-DiagStep -Name 'Clock skew vs Microsoft' -Area 'Time' -ScriptBlock {
        $skew = Get-DiagTimeSkew
        Add-DiagData -Section 'Time' -Data ([ordered]@{ LocalTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'); TimeZone = [System.TimeZoneInfo]::Local.Id; SkewMinutesVsMicrosoft = $skew })
        if ($null -eq $skew) { Add-DiagFinding -Severity Info -Area 'Time' -Title 'Could not reach login.microsoftonline.com to compare time' -Recommendation 'Network/proxy problem? Run Test-M365NetworkConnectivity.ps1.' }
        elseif ([math]::Abs($skew) -ge 5) { Add-DiagFinding -Severity Critical -Area 'Time' -Title "Clock is off by $skew minutes" -Recommendation 'Tokens are rejected when the clock is >5 minutes off. Fix time sync (w32time / NTP).' }
    } | Out-Null

    Add-DiagFinding -Severity Info -Area 'Next steps' -Title 'For full Intune/MDM logs, collect "Settings > Accounts > Access work or school > Export your management log files" on the device' -Quiet
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
