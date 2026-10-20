<#
.SYNOPSIS
    THIS PC: Microsoft 365 Apps (version, update channel, shared activation), sign-in/WAM health, Outlook (profiles, OST sizes, Autodiscover overrides, new Outlook), Teams client & Teams Outlook add-in, and OneDrive sync client (accounts, Known Folder Move, policies). No sign-in needed.

.DESCRIPTION
    Run on the affected PC as the affected user for: "Office keeps asking for password", "activation/licensing
    errors", "Teams meeting button missing in Outlook", "Outlook profile/autodiscover problems", "OST huge/slow",
    "OneDrive not syncing Desktop/Documents".

.EXAMPLE
    .\Get-M365AppsClientDiagnostics.ps1

.NOTES
    Connection : None (local device)
    Roles      : None (run as the affected user)
    Read-only  : Reads registry values, file sizes and installed package versions only. No credential stores,
                 tokens or license files are read.
#>
[CmdletBinding()]
param(
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

function Get-RegValues {
    param([string]$Path, [string[]]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $p = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $p) { return $null }
    $o = [ordered]@{}
    $names = if ($Name) { $Name } else { @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object Name) }
    foreach ($n in $names) { if ($p.PSObject.Properties[$n]) { $o[$n] = $p.$n } }
    return [pscustomobject]$o
}

Start-DiagRun -Name 'Get-M365AppsClientDiagnostics' -Title 'Local Device - Microsoft 365 Apps, Outlook, Teams & OneDrive Client' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
$channels = @{
    '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
    '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
    '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
    '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
    'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Channel (Preview)'
    '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
}
try {
    # --- Office Click-to-Run
    Invoke-DiagStep -Name 'Microsoft 365 Apps installation' -Area 'Office' -ScriptBlock {
        $c2r = Get-RegValues -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -Name VersionToReport, Platform, ProductReleaseIds, CDNBaseUrl, UpdateChannel, UpdateChannelChanged, UpdatesEnabled, SharedComputerLicensing, ClientCulture, InstallationPath
        if (-not $c2r) { Add-DiagFinding -Severity Warning -Area 'Office' -Title 'Microsoft 365 Apps (Click-to-Run) not found' -Detail 'MSI/volume Office or not installed - modern auth and many features behave differently.'; return }
        $chUrl = if ($c2r.UpdateChannel) { [string]$c2r.UpdateChannel } else { [string]$c2r.CDNBaseUrl }
        $chId = if ($chUrl -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $Matches[1].ToLowerInvariant() } else { '' }
        $pol = Get-RegValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate'
        Add-DiagData -Section 'Microsoft 365 Apps' -Data ([ordered]@{
                Version = $c2r.VersionToReport; Platform = $c2r.Platform; Products = $c2r.ProductReleaseIds; Channel = if ($channels.ContainsKey($chId)) { $channels[$chId] } else { $chUrl }; ChannelId = $chId
                UpdatesEnabled = $c2r.UpdatesEnabled; SharedComputerLicensing = $c2r.SharedComputerLicensing; Culture = $c2r.ClientCulture; UpdatePolicy = $pol
            })
        if ($c2r.UpdatesEnabled -eq 'False') { Add-DiagFinding -Severity Warning -Area 'Office' -Title 'Office automatic updates are disabled' -Detail 'Outdated builds fall out of support and miss fixes.' }
        if ($c2r.SharedComputerLicensing -eq '1') { Add-DiagFinding -Severity Info -Area 'Office' -Title 'Shared computer activation is ON' -Detail 'Each user gets a per-device token; frequent "sign in to activate" prompts are normal on new profiles.' }
        if ($chId -eq '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114') { Add-DiagFinding -Severity Info -Area 'Office' -Title 'Semi-Annual Enterprise Channel - new features (e.g. new Outlook toggles, Copilot) arrive months later' -Quiet }
        $lic = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Licensing\LicensingNext'
        if ($lic) { Add-DiagData -Section 'Licensing mode (per app)' -Data $lic -Description 'Values: 2/3 = subscription (vNext), other = legacy/perpetual. No license files or tokens are read.' }
    } | Out-Null

    # --- Identity / WAM
    Invoke-DiagStep -Name 'Office sign-in / WAM configuration' -Area 'Sign-in' -ScriptBlock {
        $id = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity' -Name EnableADAL, DisableADALatopWAMOverride, DisableAADWAM, DisableMSAWAM, Version, SignInOptions
        Add-DiagData -Section 'Office identity settings' -Data $id
        if ($id -and $id.DisableAADWAM -eq 1) { Add-DiagFinding -Severity Warning -Area 'Sign-in' -Title 'DisableAADWAM = 1 (Office bypasses Windows account broker)' -Recommendation 'Legacy workaround that causes repeated prompts and breaks SSO/CA device checks. Remove it unless Microsoft support asked for it.' }
        if ($id -and $id.DisableADALatopWAMOverride -eq 1) { Add-DiagFinding -Severity Warning -Area 'Sign-in' -Title 'DisableADALatopWAMOverride = 1 is set' -Detail 'Unsupported legacy setting - remove.' }
        if ($id -and $id.EnableADAL -eq 0) { Add-DiagFinding -Severity Critical -Area 'Sign-in' -Title 'Modern authentication is disabled for Office (EnableADAL = 0)' }
        $accounts = @(Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities' -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                [pscustomobject]@{ EmailAddress = $p.EmailAddress; ProviderId = $p.ProviderId; IdP = $p.IdP; SignInName = $p.SignInName }
            } | Where-Object { $_.EmailAddress -or $_.SignInName })
        Add-DiagData -Section 'Office accounts (signed in)' -Data $accounts
        if ($accounts.Count -gt 3) { Add-DiagFinding -Severity Info -Area 'Sign-in' -Title "$($accounts.Count) accounts known to Office on this profile" -Detail 'Stale accounts can cause the wrong account to be used for activation/sign-in.' }
        $broker = @(Get-AppxPackage -Name 'Microsoft.AAD.BrokerPlugin' -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Web Account Manager broker' -Data ([ordered]@{ Installed = ($broker.Count -gt 0); Version = ($broker | Select-Object -First 1).Version; Status = ($broker | Select-Object -First 1).Status })
        if ($broker.Count -eq 0) { Add-DiagFinding -Severity Critical -Area 'Sign-in' -Title 'Microsoft.AAD.BrokerPlugin (WAM) is missing for this user' -Recommendation 'Sign-in for Office/Teams/OneDrive fails or loops. Re-register the package (a change) per Microsoft guidance.' }
    } | Out-Null

    # --- Outlook
    Invoke-DiagStep -Name 'Outlook profiles, data files and Autodiscover' -Area 'Outlook' -ScriptBlock {
        $profiles = @(Get-ChildItem -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
        $defProfile = (Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook' -Name DefaultProfile)
        $ad = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover'
        $adPol = Get-RegValues -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\AutoDiscover'
        $cache = Get-RegValues -Path 'HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode'
        $newOl = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences' -Name UseNewOutlook
        $olk = @(Get-AppxPackage -Name 'Microsoft.OutlookForWindows' -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Outlook' -Data ([ordered]@{ Profiles = $profiles; DefaultProfile = if ($defProfile) { $defProfile.DefaultProfile } else { '' }; AutodiscoverSettings = $ad; AutodiscoverPolicy = $adPol; CachedModePolicy = $cache; UseNewOutlookToggle = if ($newOl) { $newOl.UseNewOutlook } else { '' }; NewOutlookInstalled = ($olk.Count -gt 0); NewOutlookVersion = ($olk | Select-Object -First 1).Version })
        foreach ($src in @($ad, $adPol)) {
            if (-not $src) { continue }
            if ($src.PSObject.Properties['ExcludeExplicitO365Endpoint'] -and $src.ExcludeExplicitO365Endpoint -eq 1) { Add-DiagFinding -Severity Warning -Area 'Outlook' -Title 'Autodiscover: ExcludeExplicitO365Endpoint = 1' -Detail 'Outlook skips the direct Microsoft 365 Autodiscover lookup - slow/failed profile creation, wrong on-prem redirects.' -Recommendation 'Remove unless needed for a hybrid migration scenario.' }
            if ($src.PSObject.Properties['PreferLocalXML'] -and $src.PreferLocalXML -eq 1) { Add-DiagFinding -Severity Warning -Area 'Outlook' -Title 'Autodiscover: PreferLocalXML = 1 (uses a local XML file)' }
            if ($src.PSObject.Properties['ExcludeScpLookup'] -and $src.ExcludeScpLookup -eq 0 -and (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain) { Add-DiagFinding -Severity Info -Area 'Outlook' -Title 'Domain-joined PC uses SCP lookup - a stale on-prem Exchange SCP can redirect Outlook' -Quiet }
        }
        if ($profiles.Count -gt 3) { Add-DiagFinding -Severity Info -Area 'Outlook' -Title "$($profiles.Count) Outlook profiles exist" -Quiet }
        $osts = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook') -Filter '*.ost' -ErrorAction SilentlyContinue)
        $psts = @(Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook') -Filter '*.pst' -ErrorAction SilentlyContinue)
        Add-DiagData -Section 'Outlook data files' -Data @(@($osts) + @($psts) | ForEach-Object { [pscustomobject]@{ File = $_.Name; SizeGB = [math]::Round($_.Length / 1GB, 2); LastWrite = $_.LastWriteTime } })
        foreach ($o in @($osts | Where-Object { $_.Length -ge 45GB })) { Add-DiagFinding -Severity Warning -Area 'Outlook' -Title "OST $($o.Name) is $([math]::Round($o.Length / 1GB, 1)) GB (default max 50 GB)" -Recommendation 'Reduce the cached mode sync window or the mailbox size; Outlook stops syncing at the limit.' }
    } | Out-Null

    # --- Teams client & add-in
    Invoke-DiagStep -Name 'Teams client and Outlook meeting add-in' -Area 'Teams' -ScriptBlock {
        $newTeams = @(Get-AppxPackage -Name 'MSTeams' -ErrorAction SilentlyContinue)
        $classicExe = Join-Path $env:LOCALAPPDATA 'Microsoft\Teams\current\Teams.exe'
        $cacheDir = Join-Path $env:LOCALAPPDATA 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'
        $cacheMb = $null
        if (Test-Path -LiteralPath $cacheDir) { $cacheMb = [math]::Round(((Get-ChildItem -LiteralPath $cacheDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum) / 1MB, 0) }
        $addin = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect' -Name LoadBehavior, FriendlyName
        $addinM = Get-RegValues -Path 'HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect' -Name LoadBehavior
        $disabled = Get-RegValues -Path 'HKCU:\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList'
        Add-DiagData -Section 'Teams' -Data ([ordered]@{ NewTeamsInstalled = ($newTeams.Count -gt 0); NewTeamsVersion = ($newTeams | Select-Object -First 1).Version; ClassicTeamsPresent = (Test-Path -LiteralPath $classicExe); NewTeamsCacheMB = $cacheMb; MeetingAddinLoadBehaviorUser = if ($addin) { $addin.LoadBehavior } else { '' }; MeetingAddinLoadBehaviorMachine = if ($addinM) { $addinM.LoadBehavior } else { '' }; DoNotDisableAddinList = $disabled })
        if ($newTeams.Count -eq 0) { Add-DiagFinding -Severity Warning -Area 'Teams' -Title 'New Teams client is not installed for this user' }
        if (Test-Path -LiteralPath $classicExe) { Add-DiagFinding -Severity Info -Area 'Teams' -Title 'Classic Teams files are still present' -Detail 'Classic Teams is retired; leftovers can confuse the Outlook add-in and protocol handlers.' }
        $lb = if ($addin) { $addin.LoadBehavior } elseif ($addinM) { $addinM.LoadBehavior } else { $null }
        if ($null -eq $lb) { Add-DiagFinding -Severity Warning -Area 'Teams' -Title 'Teams Meeting add-in for Outlook is not registered' -Detail 'Explains a missing "Teams Meeting" button in classic Outlook.' -Recommendation 'Start new Teams once (it registers the add-in), then restart Outlook.' }
        elseif ($lb -ne 3) { Add-DiagFinding -Severity Warning -Area 'Teams' -Title "Teams Meeting add-in LoadBehavior = $lb (not loaded at startup)" -Recommendation 'Outlook disabled it (slow add-in). Re-enable in Outlook > File > Options > Add-ins and consider adding it to the DoNotDisableAddinList policy.' }
        if ($cacheMb -gt 3000) { Add-DiagFinding -Severity Info -Area 'Teams' -Title "New Teams cache is $cacheMb MB" -Detail 'A large/corrupt cache causes sign-in loops and stale data; clearing it is a common fix.' }
    } | Out-Null

    # --- OneDrive
    Invoke-DiagStep -Name 'OneDrive sync client' -Area 'OneDrive' -ScriptBlock {
        $od = Get-RegValues -Path 'HKCU:\Software\Microsoft\OneDrive' -Name Version, UpdateRing, EnableADAL
        $exe = @((Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'), (Join-Path $env:ProgramFiles 'Microsoft OneDrive\OneDrive.exe')) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        $ver = if ($exe) { (Get-Item -LiteralPath $exe).VersionInfo.FileVersion } elseif ($od) { $od.Version } else { $null }
        $running = [bool](Get-Process -Name OneDrive -ErrorAction SilentlyContinue)
        $acc = @(Get-ChildItem -Path 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Business*' } | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                [pscustomobject]@{ Account = $_.PSChildName; UserEmail = $p.UserEmail; UserFolder = $p.UserFolder; DisplayName = $p.DisplayName; ConfiguredTenantId = $p.ConfiguredTenantId; KfmFoldersProtectedNow = $p.KfmFoldersProtectedNow; LastSignInTime = $p.LastSignInTime }
            })
        $shell = Get-RegValues -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name Desktop, Personal, 'My Pictures'
        $kfm = [ordered]@{}
        $roots = @($acc | Where-Object UserFolder | ForEach-Object { [string]$_.UserFolder })
        foreach ($n in 'Desktop', 'Personal', 'My Pictures') {
            $val = if ($shell -and $shell.PSObject.Properties[$n]) { [Environment]::ExpandEnvironmentVariables([string]$shell.$n) } else { '' }
            $kfm[$n] = if ($roots | Where-Object { $val -like "$_*" }) { 'Redirected to OneDrive' } else { 'Local' }
        }
        $pol = Get-RegValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        Add-DiagData -Section 'OneDrive client' -Data ([ordered]@{ Version = $ver; Running = $running; UpdateRing = if ($od) { $od.UpdateRing } else { '' }; BusinessAccounts = $acc.Count })
        Add-DiagData -Section 'OneDrive accounts' -Data $acc
        Add-DiagData -Section 'Known Folder Move' -Data $kfm
        Add-DiagData -Section 'OneDrive policies (HKLM)' -Data $pol
        if (-not $ver) { Add-DiagFinding -Severity Warning -Area 'OneDrive' -Title 'OneDrive sync client not found' }
        elseif (-not $running) { Add-DiagFinding -Severity Warning -Area 'OneDrive' -Title 'OneDrive is installed but not running' -Detail 'Files are not syncing until it is started.' }
        if ($ver -and $acc.Count -eq 0) { Add-DiagFinding -Severity Info -Area 'OneDrive' -Title 'No work/school account is signed in to OneDrive' }
        if ($pol -and $pol.PSObject.Properties['KFMSilentOptIn'] -and @($kfm.Values | Where-Object { $_ -eq 'Local' }).Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'OneDrive' -Title 'Known Folder Move policy is set but some folders are still local' -Detail 'KFM can be blocked by unsupported files, folder size, or existing redirection (GPO).' }
        if ($pol -and $pol.PSObject.Properties['AllowTenantList']) { Add-DiagFinding -Severity Info -Area 'OneDrive' -Title 'OneDrive is restricted to specific tenants (AllowTenantList)' -Quiet }
    } | Out-Null
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
