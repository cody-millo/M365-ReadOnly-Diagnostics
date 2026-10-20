<#
.SYNOPSIS
    Device diagnostics (Intune + Entra ID): compliance state with the exact failing settings, last check-in, encryption, configuration profile errors/conflicts, Entra join type/enabled state, duplicates/stale objects, and Autopilot record. Look up by device name, user, or serial number.

.DESCRIPTION
    Typical tickets: "blocked by Conditional Access - device not compliant", "device not checking in",
    "profile not applying", "can't sign in from this PC", "Autopilot not picking up profile".

.PARAMETER DeviceName
    Device name to look up.

.PARAMETER UserPrincipalName
    List/diagnose all devices of this user.

.PARAMETER SerialNumber
    Look up by hardware serial number.

.EXAMPLE
    .\Get-DeviceDiagnostics.ps1 -DeviceName LAPTOP-1234
    .\Get-DeviceDiagnostics.ps1 -UserPrincipalName jane@contoso.com

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader or Intune Read Only Operator / Intune Administrator (read)
    Scopes     : DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, Device.Read.All, User.Read.All
    Read-only  : HTTP GET requests only. BitLocker keys and LAPS passwords are never requested.
#>
[CmdletBinding()]
param(
    [string]$DeviceName,
    [string]$UserPrincipalName,
    [string]$SerialNumber,
    [int]$MaxDevices = 10,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not ($DeviceName -or $UserPrincipalName -or $SerialNumber)) {
    $mode = Read-DiagChoice -Prompt 'Look up devices by' -Options @(
        [pscustomobject]@{ Label = 'Device name'; Value = 'name' },
        [pscustomobject]@{ Label = 'User (all of the user''s devices)'; Value = 'user' },
        [pscustomobject]@{ Label = 'Serial number'; Value = 'serial' })
    switch ($mode) {
        'name' { $DeviceName = Read-DiagValue -Prompt 'Device name' }
        'user' { $UserPrincipalName = Read-DiagValue -Prompt 'User UPN' -Pattern '@' }
        'serial' { $SerialNumber = Read-DiagValue -Prompt 'Serial number' }
    }
}

Start-DiagRun -Name 'Get-DeviceDiagnostics' -Title 'Intune & Entra ID - Device Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ DeviceName = $DeviceName; UserPrincipalName = $UserPrincipalName; SerialNumber = $SerialNumber })
$esc = { param($s) ([string]$s).Replace("'", "''") }
try {
    Connect-DiagGraph -Scopes 'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementServiceConfig.Read.All', 'Device.Read.All', 'User.Read.All' -TenantId $TenantId
    $now = (Get-Date).ToUniversalTime()
    if ($DeviceName) { Register-DiagSensitiveValue -Value $DeviceName -Category host }

    $sel = 'id,deviceName,userPrincipalName,userDisplayName,operatingSystem,osVersion,complianceState,managementAgent,managedDeviceOwnerType,enrolledDateTime,lastSyncDateTime,azureADDeviceId,azureADRegistered,deviceEnrollmentType,deviceRegistrationState,managementState,jailBroken,isEncrypted,model,manufacturer,serialNumber,freeStorageSpaceInBytes,totalStorageSpaceInBytes,exchangeAccessState,exchangeAccessStateReason,autopilotEnrolled,partnerReportedThreatState,complianceGracePeriodExpirationDateTime,isSupervised'
    $filter = if ($DeviceName) { "deviceName eq '$(& $esc $DeviceName)'" } elseif ($UserPrincipalName) { "userPrincipalName eq '$(& $esc $UserPrincipalName)'" } else { "serialNumber eq '$(& $esc $SerialNumber)'" }
    $md = @(Invoke-DiagStep -Name 'Intune managed devices' -Area 'Intune' -ScriptBlock { Invoke-DiagGraph -Uri "v1.0/deviceManagement/managedDevices?`$filter=$filter&`$select=$sel" -All -MaxItems 100 })

    # Entra device objects
    $entra = New-Object System.Collections.Generic.List[object]
    $eSel = 'id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,registrationDateTime,profileType,deviceOwnership,onPremisesSyncEnabled,onPremisesLastSyncDateTime,mdmAppId,enrollmentType'
    Invoke-DiagStep -Name 'Entra ID device objects' -Area 'Entra ID' -ScriptBlock {
        $found = @()
        if ($DeviceName) { $found = @(Invoke-DiagGraph -Uri "v1.0/devices?`$filter=displayName eq '$(& $esc $DeviceName)'&`$select=$eSel" -All) }
        elseif ($UserPrincipalName) {
            $u = [uri]::EscapeDataString($UserPrincipalName)
            $found = @(Invoke-DiagGraph -Uri "v1.0/users/$u/registeredDevices?`$select=$eSel" -All) + @(Invoke-DiagGraph -Uri "v1.0/users/$u/ownedDevices?`$select=$eSel" -All)
        }
        foreach ($m in $md) {
            if ($m.azureADDeviceId -and $m.azureADDeviceId -ne '00000000-0000-0000-0000-000000000000') { $found += @(Invoke-DiagGraph -Uri "v1.0/devices?`$filter=deviceId eq '$($m.azureADDeviceId)'&`$select=$eSel" -All) }
        }
        foreach ($f in @($found | Where-Object { $_ } | Sort-Object id -Unique)) { $entra.Add($f) }
    } | Out-Null

    Add-DiagData -Section 'Intune devices' -Data @($md | ForEach-Object {
            [pscustomobject]@{
                DeviceName = $_.deviceName; User = $_.userPrincipalName; OS = "$($_.operatingSystem) $($_.osVersion)"; Compliance = $_.complianceState; GraceUntil = $_.complianceGracePeriodExpirationDateTime
                LastSync = $_.lastSyncDateTime; Enrolled = $_.enrolledDateTime; Ownership = $_.managedDeviceOwnerType; Agent = $_.managementAgent; EnrollmentType = $_.deviceEnrollmentType; Encrypted = $_.isEncrypted
                Model = "$($_.manufacturer) $($_.model)"; Serial = $_.serialNumber; FreeGB = if ($_.freeStorageSpaceInBytes) { [math]::Round($_.freeStorageSpaceInBytes / 1GB, 1) } else { '' }
                ManagementState = $_.managementState; RegistrationState = $_.deviceRegistrationState; ExchangeAccess = $_.exchangeAccessState; Autopilot = $_.autopilotEnrolled; EntraDeviceId = $_.azureADDeviceId; IntuneId = $_.id
            }
        })
    Add-DiagData -Section 'Entra ID devices' -Data @($entra | ForEach-Object {
            $jt = switch ($_.trustType) { 'AzureAd' { 'Entra joined' } 'ServerAd' { 'Hybrid joined' } 'Workplace' { 'Entra registered' } default { $_.trustType } }
            [pscustomobject]@{ DisplayName = $_.displayName; DeviceId = $_.deviceId; Enabled = $_.accountEnabled; JoinType = $jt; OS = "$($_.operatingSystem) $($_.operatingSystemVersion)"; Compliant = $_.isCompliant; Managed = $_.isManaged; LastSignIn = $_.approximateLastSignInDateTime; Registered = $_.registrationDateTime; Synced = $_.onPremisesSyncEnabled; Ownership = $_.deviceOwnership; ObjectId = $_.id }
        })

    if ($md.Count -eq 0 -and $entra.Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Lookup' -Title 'No device found in Intune or Entra ID' -Recommendation 'Check the exact device name (hostname), or look up by user/serial.' }
    if ($md.Count -eq 0 -and $entra.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Intune' -Title 'Device exists in Entra ID but is NOT enrolled in Intune' -Recommendation 'CA "require compliant device" will block it. Check MDM auto-enrollment scope (Entra ID > Mobility) and run Get-LocalEntraJoinStatus.ps1 on the device.' }

    # Entra checks
    foreach ($e in $entra) {
        if ($e.accountEnabled -eq $false) { Add-DiagFinding -Severity Critical -Area 'Entra ID' -Title "Entra device '$($e.displayName)' is DISABLED" -Detail 'Device-based sign-in (PRT, CA device checks) fails with 50155/135011.' }
        if ($e.trustType -eq 'ServerAd' -and -not $e.registrationDateTime) { Add-DiagFinding -Severity Warning -Area 'Entra ID' -Title "Hybrid join PENDING for '$($e.displayName)' (synced but never registered)" -Recommendation 'The device must sign in on the corporate network / see the SCP and complete registration. Check dsregcmd /status on the device.' }
        $ls = ConvertTo-DiagDate $e.approximateLastSignInDateTime
        if ($ls -and ($now - $ls).TotalDays -gt 90) { Add-DiagFinding -Severity Info -Area 'Entra ID' -Title "Entra device '$($e.displayName)' has not signed in for $([int]($now - $ls).TotalDays) days (stale)" }
    }
    $dupes = @($entra | Group-Object displayName | Where-Object Count -gt 1)
    foreach ($d in $dupes) { Add-DiagFinding -Severity Warning -Area 'Entra ID' -Title "$($d.Count) Entra device objects named '$($d.Name)'" -Detail (($d.Group | ForEach-Object { "$($_.trustType) enabled=$($_.accountEnabled) lastSignIn=$($_.approximateLastSignInDateTime)" }) -join ' | ') -Recommendation 'Duplicate/stale objects (e.g. registered + hybrid joined) confuse CA evaluation. Clean up the stale one.' }

    # Per Intune device detail
    foreach ($m in @($md | Sort-Object lastSyncDateTime -Descending | Select-Object -First $MaxDevices)) {
        $n = $m.deviceName
        Write-DiagInfo $n -Level Header
        $ls = ConvertTo-DiagDate $m.lastSyncDateTime
        switch ([string]$m.complianceState) {
            'noncompliant' { Add-DiagFinding -Severity Critical -Area $n -Title "'$n' is NON-COMPLIANT" -Detail 'Conditional Access requiring a compliant device blocks it. See the failing settings below.' }
            'inGracePeriod' { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' is non-compliant in grace period (until $($m.complianceGracePeriodExpirationDateTime))" }
            'unknown' { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' compliance state is unknown" -Detail 'Device has not reported compliance (new enrollment, check-in failing, or no policy assigned + "mark devices without policy as non-compliant").' }
            'error' { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' compliance evaluation is in error" }
            'configManager' { Add-DiagFinding -Severity Info -Area $n -Title "'$n' compliance is evaluated by Configuration Manager (co-management)" }
        }
        if ($ls -and ($now - $ls).TotalDays -gt 7) { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' last checked in $([int]($now - $ls).TotalDays) days ago" -Recommendation 'Device is offline, the MDM certificate expired, or the IME/MDM client is broken. On the device: Settings > Accounts > Access work or school > Info > Sync.' }
        if ($m.isEncrypted -eq $false -and $m.operatingSystem -match 'Windows|macOS') { Add-DiagFinding -Severity Info -Area $n -Title "'$n' reports disk NOT encrypted" -Quiet }
        if ($m.jailBroken -eq 'True') { Add-DiagFinding -Severity Critical -Area $n -Title "'$n' is jailbroken/rooted" }
        if ($m.managementState -match 'retire|wipe|delete') { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' has a pending action: $($m.managementState)" }
        if ($m.totalStorageSpaceInBytes -gt 0 -and ($m.freeStorageSpaceInBytes / $m.totalStorageSpaceInBytes) -lt 0.1) { Add-DiagFinding -Severity Info -Area $n -Title "'$n' has less than 10% free disk space" -Detail 'Low disk space breaks updates and app installs.' }
        if ($m.partnerReportedThreatState -and $m.partnerReportedThreatState -notin 'unknown', 'secured', 'activated') { Add-DiagFinding -Severity Warning -Area $n -Title "'$n' threat state from MTD/Defender: $($m.partnerReportedThreatState)" }

        Invoke-DiagStep -Name 'Compliance policy states (failing settings)' -Area $n -ScriptBlock {
            $cps = @(Invoke-DiagGraph -Uri "v1.0/deviceManagement/managedDevices/$($m.id)/deviceCompliancePolicyStates" -All)
            $rows = foreach ($c in $cps) {
                $bad = @($c.settingStates | Where-Object { $_.state -notin 'compliant', 'notApplicable' })
                [pscustomobject]@{ Policy = $c.displayName; State = $c.state; Platform = $c.platformType; SettingCount = $c.settingCount; FailingSettings = (@($bad | ForEach-Object { "$($_.settingName)=$($_.state)$(if ($_.errorDescription) { " ($($_.errorDescription))" })" }) -join '; ') }
                foreach ($b in $bad) { if ($b.state -in 'nonCompliant', 'error') { Add-DiagFinding -Severity Warning -Area $n -Title "Compliance setting failing: $($b.settingName) [$($c.displayName)]" -Detail "State: $($b.state). Current value: $($b.currentValue). $($b.errorDescription)" } }
            }
            Add-DiagData -Section "$n - Compliance policies" -Data @($rows)
        } | Out-Null

        Invoke-DiagStep -Name 'Configuration profile states' -Area $n -ScriptBlock {
            $cfg = @(Invoke-DiagGraph -Uri "v1.0/deviceManagement/managedDevices/$($m.id)/deviceConfigurationStates" -All)
            $rows = @($cfg | ForEach-Object { [pscustomobject]@{ Profile = $_.displayName; State = $_.state; Platform = $_.platformType; SettingCount = $_.settingCount; Problems = (@($_.settingStates | Where-Object { $_.state -in 'error', 'conflict', 'nonCompliant' } | ForEach-Object { "$($_.settingName)=$($_.state)" }) -join '; ') } })
            Add-DiagData -Section "$n - Configuration profiles" -Data $rows
            foreach ($r in @($rows | Where-Object { $_.State -in 'error', 'conflict' })) { Add-DiagFinding -Severity Warning -Area $n -Title "Configuration profile '$($r.Profile)' is in $($r.State)" -Detail $r.Problems -Recommendation 'Conflict = two profiles set the same setting differently. Error = see Intune > Devices > (device) > Device configuration.' }
        } | Out-Null

        if ($m.serialNumber) {
            Invoke-DiagStep -Name 'Autopilot registration' -Area $n -ScriptBlock {
                $ap = @(Invoke-DiagGraph -Uri "v1.0/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$(& $esc $m.serialNumber)')" -All)
                if ($ap.Count -gt 0) { Add-DiagData -Section "$n - Autopilot" -Data @($ap | Select-DiagObject -Property serialNumber, model, manufacturer, groupTag, enrollmentState, lastContactedDateTime, purchaseOrderIdentifier, azureActiveDirectoryDeviceId, managedDeviceId) }
                elseif ($m.operatingSystem -eq 'Windows') { Add-DiagFinding -Severity Info -Area $n -Title "'$n' is not registered in Windows Autopilot" -Quiet }
            } | Out-Null
        }
    }
    if ($md.Count -gt $MaxDevices) { Add-DiagFinding -Severity Info -Area 'Lookup' -Title "$($md.Count) devices matched - detailed only the $MaxDevices most recently synced" }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
