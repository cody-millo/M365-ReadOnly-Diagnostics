#Requires -Version 5.1
<#
    M365Diag - shared helpers for the M365 READ-ONLY diagnostic scripts.

    Design rules (enforced by Tests\Test-ReadOnlyCompliance.ps1):
      * Nothing in this toolkit changes Microsoft 365. Graph calls are HTTP GET only, Exchange Online is
        connected with a Get-/Search- cmdlet allow-list, Teams/SharePoint scripts only call Get- cmdlets.
      * The only local writes are the report files in the Reports folder.
      * EDR friendly: no Invoke-Expression, no encoded commands, no inline C# compilation, no credential
        store access, no hidden processes, no downloads executed.
#>

$script:ModuleRoot = $PSScriptRoot
$script:RepoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:DiagRun = $null
$script:Sanitizer = $null
$script:ExoCommandsLoaded = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:SkipProps = @('PSComputerName', 'RunspaceId', 'PSShowComputerName', 'PSSourceJobInstanceId', 'ObjectState', 'IsValid',
    'ExchangeVersion', 'ObjectCategory', 'ObjectClass', 'OriginatingServer', 'OrganizationId', '@odata.context', '@odata.etag')

#region ---------------------------------------------------------------- Console helpers

function Write-DiagInfo {
    <# Writes a status line to the console (sanitized when sanitization is on). #>
    param(
        [Parameter(Position = 0)][string]$Message,
        [ValidateSet('Info', 'Step', 'Ok', 'Warn', 'Error', 'Header', 'Dim')][string]$Level = 'Info'
    )
    $text = $Message
    if ($script:Sanitizer -and $script:Sanitizer.Enabled) { $text = Protect-DiagText -Text $Message }
    switch ($Level) {
        'Header' { Write-Host ''; Write-Host $text -ForegroundColor Cyan }
        'Step' { Write-Host "  -> $text" -ForegroundColor DarkCyan }
        'Ok' { Write-Host "     $text" -ForegroundColor Green }
        'Warn' { Write-Host "     $text" -ForegroundColor Yellow }
        'Error' { Write-Host "     $text" -ForegroundColor Red }
        'Dim' { Write-Host "     $text" -ForegroundColor DarkGray }
        default { Write-Host "  $text" }
    }
}

#endregion

#region ---------------------------------------------------------------- Input helpers

function Read-DiagValue {
    <# Prompts for a value. Returns $Default on empty input, $null when -Optional and empty. #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default,
        [switch]$Optional,
        [string]$Pattern,
        [string]$PatternHint = 'Invalid format.'
    )
    while ($true) {
        $label = $Prompt
        if ($Default) { $label = "$Prompt [$Default]" }
        elseif ($Optional) { $label = "$Prompt (optional, Enter to skip)" }
        $value = Read-Host -Prompt "  $label"
        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($Default) { return $Default }
            if ($Optional) { return $null }
            Write-Host '     A value is required.' -ForegroundColor Yellow
            continue
        }
        $value = $value.Trim()
        if ($Pattern -and $value -notmatch $Pattern) { Write-Host "     $PatternHint" -ForegroundColor Yellow; continue }
        return $value
    }
}

function Read-DiagYesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $true)
    $hint = if ($Default) { 'Y/n' } else { 'y/N' }
    $value = Read-Host -Prompt "  $Prompt [$hint]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return ($value.Trim() -match '^(y|yes)$')
}

function Read-DiagChoice {
    <# Numbered menu. Returns the chosen item (or its Value property when items are objects with Label/Value). #>
    param([Parameter(Mandatory)][string]$Prompt, [Parameter(Mandatory)][object[]]$Options, [int]$DefaultIndex = 0)
    Write-Host "  $Prompt" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $o = $Options[$i]
        $label = if ($o.PSObject.Properties['Label']) { $o.Label } else { [string]$o }
        $mark = if ($i -eq $DefaultIndex) { '*' } else { ' ' }
        Write-Host ("   {0}[{1}] {2}" -f $mark, ($i + 1), $label)
    }
    while ($true) {
        $raw = Read-Host -Prompt "  Choose 1-$($Options.Count) [$($DefaultIndex + 1)]"
        if ([string]::IsNullOrWhiteSpace($raw)) { $idx = $DefaultIndex }
        elseif ($raw -match '^\d+$' -and [int]$raw -ge 1 -and [int]$raw -le $Options.Count) { $idx = [int]$raw - 1 }
        else { Write-Host '     Invalid choice.' -ForegroundColor Yellow; continue }
        $o = $Options[$idx]
        if ($o.PSObject.Properties['Value']) { return $o.Value }
        return $o
    }
}

function Test-DiagGuiAvailable {
    if (-not [Environment]::UserInteractive) { return $false }
    if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { return $false }
    # WinForms dialogs need a single-threaded apartment. Windows PowerShell 5.1 is STA by default.
    # We deliberately do not spin up extra STA runspaces/threads (keeps behaviour simple and EDR-friendly).
    return ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::STA)
}

function Select-DiagFile {
    <#
        Opens a standard Windows "Open file" dialog. Falls back to typing a path when no GUI is available
        (e.g. PowerShell 7 started without -STA, or a remote session).
    #>
    param(
        [string]$Title = 'Select a file',
        [string]$Filter = 'All files (*.*)|*.*',
        [string]$InitialDirectory = [Environment]::GetFolderPath('Desktop')
    )
    $path = $null
    if (Test-DiagGuiAvailable) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $owner = New-Object System.Windows.Forms.Form
            $owner.TopMost = $true
            $owner.ShowInTaskbar = $false
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title = $Title
            $dialog.Filter = $Filter
            $dialog.Multiselect = $false
            $dialog.CheckFileExists = $true
            if ($InitialDirectory -and (Test-Path -LiteralPath $InitialDirectory)) { $dialog.InitialDirectory = $InitialDirectory }
            Write-Host '     (a file picker window has opened - it may be behind this window)' -ForegroundColor DarkGray
            if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $path = $dialog.FileName }
            $dialog.Dispose(); $owner.Dispose()
        }
        catch {
            Write-Host "     File picker unavailable ($($_.Exception.Message)). Type the path instead." -ForegroundColor Yellow
        }
    }
    if (-not $path -and -not (Test-DiagGuiAvailable)) {
        $typed = Read-DiagValue -Prompt "$Title - full path" -Optional
        if ($typed) { $path = $typed.Trim('"') }
    }
    if ($path -and -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host "     File not found: $path" -ForegroundColor Yellow
        return $null
    }
    return $path
}

function Import-DiagIdentityFile {
    <# Reads identities from a CSV (auto-detects the column) or a TXT file (one per line, # = comment). #>
    param([Parameter(Mandatory)][string]$Path)
    $values = @()
    if ($Path -match '\.csv$') {
        $rows = @(Import-Csv -LiteralPath $Path)
        if ($rows.Count -eq 0) { return @() }
        $headers = @($rows[0].PSObject.Properties.Name)
        $col = $headers | Where-Object { $_ -match '^(UserPrincipalName|UPN|PrimarySmtpAddress|EmailAddress|E-?mail|Mail|Identity|User|Username|SignInName|DeviceName|Name)$' } | Select-Object -First 1
        if (-not $col) { $col = $headers[0] }
        Write-DiagInfo "Using CSV column '$col' ($($rows.Count) rows)" -Level Dim
        $values = $rows | ForEach-Object { [string]$_.$col }
    }
    else {
        $values = Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch '^\s*#' }
    }
    return @($values | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function Read-DiagIdentityList {
    <# Asks for one/several identities (comma separated) or F to pick a CSV/TXT file. #>
    param([string]$Prompt = 'User (UPN or email)')
    while ($true) {
        $raw = Read-Host -Prompt "  $Prompt - type one or more (comma separated), or F to pick a CSV/TXT file"
        if ([string]::IsNullOrWhiteSpace($raw)) { Write-Host '     A value is required.' -ForegroundColor Yellow; continue }
        if ($raw.Trim() -match '^(f|file)$') {
            $path = Select-DiagFile -Title 'Select a CSV or TXT file with identities' -Filter 'CSV or text (*.csv;*.txt)|*.csv;*.txt|All files (*.*)|*.*'
            if (-not $path) { continue }
            $list = @(Import-DiagIdentityFile -Path $path)
            if ($list.Count -eq 0) { Write-Host '     The file contained no identities.' -ForegroundColor Yellow; continue }
            return $list
        }
        return @($raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
}

#endregion

#region ---------------------------------------------------------------- Conversion helpers

function ConvertTo-DiagBytes {
    <# Converts Exchange size strings ("1.5 GB (1,610,612,736 bytes)") or numbers to [long]. Unlimited/empty -> $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [long] -or $Value -is [int] -or $Value -is [double] -or $Value -is [decimal]) { return [long]$Value }
    $s = [string]$Value
    if ($s -match '\(([\d,\.\s]+)\s*bytes\)') { return [long]($Matches[1] -replace '[^\d]', '') }
    if ($s -match '^\s*\d+\s*$') { return [long]$s }
    return $null
}

function Format-DiagBytes {
    param($Bytes)
    if ($null -eq $Bytes) { return '' }
    $b = [double]$Bytes
    if ($b -ge 1TB) { return '{0:N2} TB' -f ($b / 1TB) }
    if ($b -ge 1GB) { return '{0:N2} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) }
    return "$b B"
}

function ConvertTo-DiagDate {
    <# Returns a UTC [datetime] from a DateTime/DateTimeOffset/ISO string, or $null. #>
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
        return $dto.UtcDateTime
    }
    return $null
}

function Select-DiagObject {
    <# Like Select-Object but silently drops properties that don't exist on the input objects. #>
    param([Parameter(ValueFromPipeline)]$InputObject, [string[]]$Property)
    process {
        if ($null -eq $InputObject) { return }
        $o = [ordered]@{}
        foreach ($p in $Property) {
            $prop = $InputObject.PSObject.Properties[$p]
            if ($prop) { $o[$prop.Name] = $prop.Value }
        }
        [pscustomobject]$o
    }
}

function Get-DiagEmailAddress {
    <# Extracts email addresses from strings like '"John" [SMTP:john@contoso.com]'. #>
    param($Value)
    $out = @()
    foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        foreach ($m in [regex]::Matches([string]$v, "[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")) { $out += $m.Value }
    }
    return @($out | Select-Object -Unique)
}

function Test-DiagExternalAddress {
    <# True when the address's domain is not one of the internal (accepted) domains. #>
    param([string]$Address, [string[]]$InternalDomains)
    if ($Address -notmatch '@(.+)$') { return $false }
    $domain = $Matches[1].ToLowerInvariant()
    foreach ($d in $InternalDomains) {
        $dl = $d.ToLowerInvariant()
        if ($domain -eq $dl -or $domain.EndsWith(".$dl")) { return $false }
    }
    return $true
}

#endregion

#region ---------------------------------------------------------------- Sanitizer

$script:PublicDomains = @('microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com', 'outlook.com', 'hotmail.com', 'live.com',
    'msn.com', 'gmail.com', 'googlemail.com', 'yahoo.com', 'icloud.com', 'me.com', 'aol.com', 'windows.net', 'azure.com', 'sharepoint.com',
    'onmicrosoft.com', 'example.com', 'example', 'protection.outlook.com', 'lync.com', 'skype.com', 'teams.microsoft.com', 'cloud.microsoft')
$script:TermStopList = @('admin', 'administrator', 'test', 'user', 'users', 'room', 'info', 'support', 'service', 'sales', 'global', 'default',
    'none', 'true', 'false', 'enabled', 'disabled', 'unknown', 'guest', 'member', 'owner', 'mail', 'team', 'teams', 'system', 'everyone')
$script:PersonKeyRegex = '^(User|userPrincipalName|PrimarySmtpAddress|WindowsEmailAddress|mail|SipAddress|userDisplayName|UserEmail|onPremisesSamAccountName|signInName)$'
$script:PersonNameRegex = '^(displayName|userDisplayName|givenName|surname|firstName|lastName|name|alias|mailNickname|samAccountName|onPremisesSamAccountName|identity|distinguishedName|onPremisesDistinguishedName|legacyExchangeDN|initials|manager|title|jobTitle|department|office|officeLocation|city|streetAddress|postalCode|employeeId|physicalDeliveryOfficeName|companyName|userName|simpleDisplayName|phoneticDisplayName)$'
$script:DeviceKeyRegex = '^(operatingSystem|deviceId|azureADDeviceId|DeviceOS|DeviceModel|serialNumber|trustType)$'
$script:DeviceNameRegex = '^(displayName|deviceName|DeviceFriendlyName|name|managedDeviceName|hostName|ComputerName|serialNumber|imei|meid|wiFiMacAddress|ethernetMacAddress|phoneNumber)$'
$script:RedactPropRegex = '^(subject|body|bodyPreview|preview|MessageText|InternalMessage|ExternalMessage|onPremisesImmutableId|immutableId|SID|onPremisesSecurityIdentifier|securityIdentifier|password.*|.*secret.*|.*token.*)$'
$script:PhonePropRegex = '^(phoneNumber|mobilePhone|businessPhones|LineUri|OnPremLineURI|TelephoneNumber|MobilePhone|Phone|HomePhone|Fax|faxNumber|TelephoneNumberAssigned|ServiceNumber|TollNumber|ForwardingTarget|UnansweredTarget|TargetPhoneNumber)$'
$script:HostPropRegex = '^(DeviceName|ComputerName|MachineName|HostName|ProxyServer|AutoConfigURL|ProxyOverride|ClientMachineName)$'
$script:GuidKeepRegex = '^(skuId|servicePlanId|templateId|roleTemplateId|resourceAppId|appId|correlationId|requestId|clientRequestId|MessageTraceId|ApplicationId|policyTemplateId|CDNBaseUrl|ChannelId)$'
$script:VersionPropRegex = '(?i)(version|build|release|osVersion|ClientVersion)'
$script:EmailRegex = [regex]"[A-Za-z0-9._%+'\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"
$script:GuidRegex = [regex]'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
$script:IPv4Regex = [regex]'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)'
$script:IPv6Regex = [regex]'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])'
$script:PhoneRegex = [regex]'(?i)(?:tel:)?\+\d{8,15}\b'
$script:SidRegex = [regex]'\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b'
$script:SpoHostRegex = [regex]'(?i)\b([a-z0-9][a-z0-9\-]*?)(-my|-admin)?\.sharepoint\.com'
$script:TenantHostRegex = [regex]'(?i)\b([a-z0-9][a-z0-9\-]*)\.(onmicrosoft\.com|mail\.onmicrosoft\.com|mail\.protection\.outlook\.com)'
$script:PersonalPathRegex = [regex]'(?i)/personal/([a-z0-9_\-\.]+)'

function New-DiagSanitizer {
    param([bool]$Enabled = $true)
    [pscustomobject]@{
        Enabled   = $Enabled
        Map       = @{}
        Reverse   = [ordered]@{}
        Counters  = @{}
        Terms     = @{}
        TermRegex = $null
        Dirty     = $true
    }
}

function Get-DiagSanitizer {
    if (-not $script:Sanitizer) { $script:Sanitizer = New-DiagSanitizer -Enabled $true }
    return $script:Sanitizer
}

function Get-DiagToken {
    param([Parameter(Mandatory)][string]$Category, [Parameter(Mandatory)][string]$Value, [switch]$AsTerm)
    $san = Get-DiagSanitizer
    $key = "$Category|$($Value.ToLowerInvariant())"
    if ($san.Map.ContainsKey($key)) { return $san.Map[$key] }
    if (-not $san.Counters.ContainsKey($Category)) { $san.Counters[$Category] = 0 }
    $san.Counters[$Category]++
    $n = $san.Counters[$Category]
    $token = switch ($Category) {
        'user' { 'user{0:d3}' -f $n }
        'domain' { 'domain{0:d2}.example' -f $n }
        'tenant' { 'tenant{0:d2}' -f $n }
        'name' { 'Name{0:d3}' -f $n }
        'host' { 'host{0:d3}' -f $n }
        'org' { 'Org{0:d2}' -f $n }
        'guid' { '00000000-0000-0000-0000-{0:d12}' -f $n }
        'ip-private' { 'private-ip-{0:d3}' -f $n }
        'ip-public' { 'public-ip-{0:d3}' -f $n }
        'ipv6' { 'ipv6-{0:d3}' -f $n }
        'phone' { '+1555{0:d7}' -f $n }
        'sid' { 'S-1-5-21-REDACTED-{0}' -f $n }
        default { '{0}{1:d3}' -f $Category, $n }
    }
    $san.Map[$key] = $token
    $san.Reverse[$token] = $Value
    if ($AsTerm -and $Value.Length -ge 3 -and $script:TermStopList -notcontains $Value.ToLowerInvariant()) {
        $san.Terms[$Value.ToLowerInvariant()] = $token
        $san.Dirty = $true
    }
    return $token
}

function Register-DiagSensitiveValue {
    <#
        Tells the sanitizer about a value that must be masked wherever it appears in free text
        (tenant domains, org name, the target user's display name, the local computer name...).
    #>
    param([Parameter(ValueFromPipeline)][string[]]$Value, [ValidateSet('domain', 'name', 'host', 'org', 'tenant', 'user')][string]$Category = 'name')
    process {
        foreach ($v in $Value) {
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $v = $v.Trim()
            if ($Category -eq 'domain') { Register-DiagDomain -Domain $v | Out-Null }
            else { Get-DiagToken -Category $Category -Value $v -AsTerm | Out-Null }
        }
    }
}

function Register-DiagDomain {
    param([string]$Domain)
    $d = $Domain.ToLowerInvariant().TrimEnd('.')
    foreach ($p in $script:PublicDomains) { if ($d -eq $p) { return $Domain } }
    if ($d -match '^(.+)\.onmicrosoft\.com$') {
        $t = Get-DiagToken -Category 'tenant' -Value $Matches[1] -AsTerm
        return "$t.onmicrosoft.com"
    }
    foreach ($p in $script:PublicDomains) { if ($d.EndsWith(".$p")) { return $Domain } }
    return (Get-DiagToken -Category 'domain' -Value $d -AsTerm)
}

function Update-DiagTermRegex {
    $san = Get-DiagSanitizer
    if (-not $san.Dirty) { return }
    $terms = @($san.Terms.Keys | Sort-Object -Property Length -Descending)
    if ($terms.Count -eq 0) { $san.TermRegex = $null }
    else {
        $alt = ($terms | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $san.TermRegex = New-Object System.Text.RegularExpressions.Regex ("(?<![\w\-])(?:$alt)(?![\w\-])", ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
    }
    $san.Dirty = $false
}

function Protect-DiagText {
    <# Sanitizes a single string. -PropertyName enables property-aware rules (redaction, versions, GUID allow-list). #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [string]$PropertyName, [switch]$KeepGuids)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $san = Get-DiagSanitizer
    if (-not $san.Enabled) { return $Text }

    if ($PropertyName) {
        if ($PropertyName -match $script:RedactPropRegex) { return '[redacted]' }
        if ($PropertyName -match $script:PhonePropRegex -and $Text -match '\d{6,}') { return (Get-DiagToken -Category 'phone' -Value $Text) }
        if ($PropertyName -match $script:HostPropRegex) { return (Get-DiagToken -Category 'host' -Value $Text -AsTerm) }
    }
    $isVersion = $PropertyName -and ($PropertyName -match $script:VersionPropRegex)
    $keepGuid = $KeepGuids -or ($PropertyName -and $PropertyName -match $script:GuidKeepRegex)

    $t = $Text
    $t = $script:EmailRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $parts = $m.Value.Split('@')
            $dom = Register-DiagDomain -Domain $parts[1]
            $usr = Get-DiagToken -Category 'user' -Value $m.Value
            "$usr@$dom"
        })
    $t = $script:SpoHostRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $tok = Get-DiagToken -Category 'tenant' -Value $m.Groups[1].Value -AsTerm
            "$tok$($m.Groups[2].Value).sharepoint.com"
        })
    $t = $script:TenantHostRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            # Microsoft datacenter server names (e.g. BN0PR04MB8000, CH2PEPF0000ABCD) are not tenant-identifying.
            if ($m.Groups[1].Value -match '^[A-Za-z]{2,3}\d[A-Za-z]{2,4}\d{2}[A-Za-z]{2}\d{2,}$|PEPF') { return $m.Value }
            $tok = Get-DiagToken -Category 'tenant' -Value $m.Groups[1].Value -AsTerm
            "$tok.$($m.Groups[2].Value)"
        })
    $t = $script:PersonalPathRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            '/personal/' + (Get-DiagToken -Category 'user' -Value $m.Groups[1].Value) + '_personal'
        })
    $t = $script:SidRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-DiagToken -Category 'sid' -Value $m.Value })
    if (-not $keepGuid) {
        $t = $script:GuidRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-DiagToken -Category 'guid' -Value $m.Value })
    }
    if (-not $isVersion) {
        $t = $script:IPv4Regex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $ip = $m.Value
                $cat = if ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)') { 'ip-private' } else { 'ip-public' }
                Get-DiagToken -Category $cat -Value $ip
            })
        $t = $script:IPv6Regex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $v = $m.Value
                $addr = $null
                if (($v.Contains('::') -or ($v.Split(':').Count -ge 8)) -and $v.Length -ge 3 -and [System.Net.IPAddress]::TryParse($v, [ref]$addr)) {
                    Get-DiagToken -Category 'ipv6' -Value $v
                }
                else { $v }
            })
    }
    $t = $script:PhoneRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-DiagToken -Category 'phone' -Value $m.Value })

    Update-DiagTermRegex
    if ($san.TermRegex) {
        $terms = $san.Terms
        $t = $san.TermRegex.Replace($t, [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $k = $m.Value.ToLowerInvariant()
                if ($terms.ContainsKey($k)) { $terms[$k] } else { $m.Value }
            })
    }
    return $t
}

function Get-DiagObjectKind {
    param($Keys)
    $kind = 'generic'
    foreach ($k in $Keys) {
        if ($k -match $script:PersonKeyRegex) { return 'person' }
        if ($k -match $script:DeviceKeyRegex) { $kind = 'device' }
    }
    return $kind
}

function Invoke-DiagSanitizeNode {
    # Pass 'Collect' registers names/domains; pass 'Replace' returns a sanitized copy.
    param($Node, [string]$PropertyName, [ValidateSet('Collect', 'Replace')][string]$Mode)
    if ($null -eq $Node) { return $null }
    if ($Node -is [string]) {
        if ($Mode -eq 'Collect') {
            foreach ($m in $script:EmailRegex.Matches($Node)) { Register-DiagDomain -Domain ($m.Value.Split('@')[1]) | Out-Null }
            return
        }
        return (Protect-DiagText -Text $Node -PropertyName $PropertyName)
    }
    if ($Node -is [System.Collections.IDictionary]) {
        $kind = Get-DiagObjectKind -Keys $Node.Keys
        $out = [ordered]@{}
        foreach ($k in @($Node.Keys)) {
            $v = $Node[$k]
            $isNameField = ($v -is [string]) -and (
                ($kind -eq 'person' -and ($k -match $script:PersonNameRegex -or $k -ceq 'Id')) -or
                ($kind -eq 'device' -and $k -match $script:DeviceNameRegex))
            if ($isNameField -and -not $script:GuidRegex.IsMatch($v) -and -not $script:EmailRegex.IsMatch($v)) {
                $cat = if ($kind -eq 'device') { 'host' } else { 'name' }
                $tok = Get-DiagToken -Category $cat -Value $v -AsTerm
                if ($Mode -eq 'Replace') { $out[$k] = $tok }
                continue
            }
            $r = Invoke-DiagSanitizeNode -Node $v -PropertyName ([string]$k) -Mode $Mode
            if ($Mode -eq 'Replace') { $out[$k] = $r }
        }
        if ($Mode -eq 'Replace') { return $out }
        return
    }
    if ($Node -is [System.Collections.IList]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $Node) {
            $r = Invoke-DiagSanitizeNode -Node $i -PropertyName $PropertyName -Mode $Mode
            if ($Mode -eq 'Replace') { $list.Add($r) }
        }
        if ($Mode -eq 'Replace') { return , ($list.ToArray()) }
        return
    }
    if ($Mode -eq 'Replace') { return $Node }
}

function Get-DiagSanitizerMap {
    $san = Get-DiagSanitizer
    return $san.Reverse
}

#endregion

#region ---------------------------------------------------------------- Normalisation

function ConvertTo-DiagPlain {
    # Turns any object (Graph PSObjects, deserialized EXO objects, hashtables) into ordered dictionaries/arrays/primitives.
    param($InputObject, [int]$Depth = 0, [int]$MaxDepth = 6)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return [string]$InputObject }
    if ($InputObject -is [datetime]) {
        if ($InputObject -eq [datetime]::MinValue) { return $null }
        return $InputObject.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
    }
    if ($InputObject -is [datetimeoffset]) { return $InputObject.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss') + 'Z' }
    if ($InputObject -is [enum] -or $InputObject -is [guid] -or $InputObject -is [timespan] -or $InputObject -is [version] -or $InputObject -is [uri] -or $InputObject -is [char]) {
        return $InputObject.ToString()
    }
    if ($InputObject -is [System.ValueType]) { return $InputObject }
    if ($InputObject -is [scriptblock]) { return $InputObject.ToString() }
    if ($Depth -ge $MaxDepth) { return [string]$InputObject }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($InputObject.Keys)) {
            if ($script:SkipProps -contains [string]$k) { continue }
            $o[[string]$k] = ConvertTo-DiagPlain -InputObject $InputObject[$k] -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
        return $o
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($i in $InputObject) { $list.Add((ConvertTo-DiagPlain -InputObject $i -Depth ($Depth + 1) -MaxDepth $MaxDepth)) }
        return , ($list.ToArray())
    }

    $typeName = ''
    if ($InputObject.PSObject.TypeNames.Count -gt 0) { $typeName = $InputObject.PSObject.TypeNames[0] }
    # Nested Exchange value types (sizes, ADObjectIds, SmtpAddresses...) read best as their string form.
    if ($Depth -gt 0 -and $typeName -match 'ByteQuantifiedSize|Unlimited|ADObjectId|SmtpAddress|ProxyAddress|EnhancedTimeSpan|ExchangeObjectVersion|SmtpDomain|MultiValuedProperty|RecipientIdHandle') {
        return $InputObject.ToString()
    }
    $props = @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -match 'Property' -and $script:SkipProps -notcontains $_.Name })
    if ($props.Count -eq 0) { return $InputObject.ToString() }
    if ($Depth -gt 0 -and $typeName -like 'Deserialized.*') {
        $str = $InputObject.ToString()
        if ($str -and $str -ne $typeName -and $str -notmatch '^Deserialized\.') { return $str }
    }
    $o = [ordered]@{}
    foreach ($p in $props) {
        $val = $null
        try { $val = $p.Value } catch { $val = '<unreadable>' }
        $o[$p.Name] = ConvertTo-DiagPlain -InputObject $val -Depth ($Depth + 1) -MaxDepth $MaxDepth
    }
    return $o
}

#endregion

#region ---------------------------------------------------------------- Run / report lifecycle

function Get-DiagDefaultOutputRoot {
    if ($env:M365DIAG_OUTPUT) { return $env:M365DIAG_OUTPUT }
    return (Join-Path -Path $script:RepoRoot -ChildPath 'Reports')
}

function Start-DiagRun {
    <# Begins a diagnostic run: creates the in-memory report and prints the banner. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Title,
        [switch]$NoSanitize,
        [string]$OutputPath,
        [System.Collections.IDictionary]$Parameters
    )
    if (-not $Title) { $Title = $Name }
    $script:Sanitizer = New-DiagSanitizer -Enabled (-not $NoSanitize)
    Register-DiagSensitiveValue -Value $env:COMPUTERNAME -Category host
    Register-DiagSensitiveValue -Value $env:USERNAME -Category user
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) { Register-DiagSensitiveValue -Value $env:USERDOMAIN -Category org }

    $root = if ($OutputPath) { $OutputPath } else { Get-DiagDefaultOutputRoot }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $paramCopy = [ordered]@{}
    if ($Parameters) { foreach ($k in $Parameters.Keys) { $paramCopy[[string]$k] = [string]$Parameters[$k] } }

    $script:DiagRun = [pscustomobject]@{
        Name       = $Name
        Title      = $Title
        RunId      = "$stamp`_$Name"
        Started    = (Get-Date).ToUniversalTime()
        OutputRoot = $root
        Sanitize   = (-not $NoSanitize)
        Parameters = $paramCopy
        Sections   = New-Object System.Collections.Generic.List[object]
        Findings   = New-Object System.Collections.Generic.List[object]
    }

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host '  READ-ONLY diagnostic - nothing in Microsoft 365 or on this PC is changed.' -ForegroundColor DarkGray
    $sanText = if ($script:DiagRun.Sanitize) { 'ON  (names, emails, IPs, IDs are pseudonymized in all output)' } else { 'OFF (raw values - do not share outside your organization)' }
    $sanColor = if ($script:DiagRun.Sanitize) { 'Green' } else { 'Yellow' }
    Write-Host "  Sanitization: $sanText" -ForegroundColor $sanColor
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Add-DiagData {
    <# Adds a data section to the report. -Data can be any object or collection. #>
    param(
        [Parameter(Mandatory)][string]$Section,
        [AllowNull()]$Data,
        [string]$Description
    )
    if (-not $script:DiagRun) { throw 'Start-DiagRun has not been called.' }
    $plain = ConvertTo-DiagPlain -InputObject $Data
    $script:DiagRun.Sections.Add([pscustomobject]@{ Name = $Section; Description = $Description; Data = $plain })
}

function Add-DiagFinding {
    <# Records a finding. Severity: Critical, Warning, Error (collection failed), Info, OK. #>
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'Warning', 'Error', 'Info', 'OK')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [string]$Recommendation,
        [string]$Area,
        [switch]$Quiet
    )
    if (-not $script:DiagRun) { throw 'Start-DiagRun has not been called.' }
    $script:DiagRun.Findings.Add([pscustomobject]@{
            Severity = $Severity; Area = $Area; Title = $Title; Detail = $Detail; Recommendation = $Recommendation
        })
    if (-not $Quiet) {
        $color = @{ Critical = 'Red'; Warning = 'Yellow'; Error = 'Magenta'; Info = 'Gray'; OK = 'Green' }[$Severity]
        $line = "[{0}] {1}" -f $Severity.ToUpperInvariant(), $Title
        if ($script:Sanitizer -and $script:Sanitizer.Enabled) { $line = Protect-DiagText -Text $line }
        Write-Host "     $line" -ForegroundColor $color
    }
}

function Get-DiagErrorHint {
    param([string]$Message)
    switch -Regex ($Message) {
        'RequestFromNonPremiumTenant|Premium|P1 license|P2 license' { return 'This data requires a Microsoft Entra ID P1/P2 (or other premium) license in the tenant.' }
        'Authorization_RequestDenied|Forbidden|403|Insufficient privileges|AccessDenied|not authorized|access is denied' { return 'Permission denied. Use an account with the needed reader role (e.g. Global Reader / Security Reader / Reports Reader) and make sure the Graph scopes were consented.' }
        'Request_ResourceNotFound|ResourceNotFound|404|couldn''t be found|could not be found|ManagementObjectNotFound|does not exist|not found' { return 'Object not found - check the spelling/identity, or the object may not exist in this service.' }
        'is not recognized as (the )?name of a cmdlet|CommandNotFoundException' { return 'Cmdlet not available - your admin role may not include it, the module is outdated, or the session is not connected.' }
        'throttl|429|TooManyRequests' { return 'Throttled by the service - wait a few minutes and run again.' }
        'Could not load file or assembly|Microsoft.Identity.Client|MSAL' { return 'Module assembly conflict (common when Graph and Exchange/Teams modules load in the same session). Close the window and run this script in a fresh launcher window.' }
        'Authentication|AADSTS|token|sign-?in' { return 'Authentication problem - reconnect, and check Conditional Access/MFA for the admin account.' }
        default { return '' }
    }
}

function Invoke-DiagStep {
    <#
        Runs one collection step. Errors never stop the script: they are recorded as 'Error' findings with a hint.
        Returns whatever the script block outputs.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$ScriptBlock, [string]$Area)
    Write-DiagInfo $Name -Level Step
    try {
        $result = & $ScriptBlock
        return $result
    }
    catch {
        $msg = $_.Exception.Message
        $hint = Get-DiagErrorHint -Message $msg
        Add-DiagFinding -Severity Error -Area $Area -Title "Could not collect: $Name" -Detail $msg -Recommendation $hint
        return   # emit nothing, so @(Invoke-DiagStep ...) is an empty array on failure
    }
}

function ConvertTo-DiagHtmlValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Collections.IDictionary] -or ($Value -is [System.Collections.IList])) {
        if ($Value -is [System.Collections.IList] -and @($Value | Where-Object { $_ -is [System.Collections.IDictionary] -or $_ -is [System.Collections.IList] }).Count -eq 0) {
            $s = (@($Value) -join '; ')
        }
        else { $s = ConvertTo-Json -InputObject $Value -Depth 6 -Compress }
        if ($s.Length -gt 600) { $s = $s.Substring(0, 600) + ' ...' }
        return '<code>' + [System.Net.WebUtility]::HtmlEncode($s) + '</code>'
    }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-DiagFlatRow {
    param([System.Collections.IDictionary]$Row, [string[]]$Columns)
    $o = [ordered]@{}
    foreach ($c in $Columns) {
        $v = $Row[$c]
        if ($v -is [System.Collections.IDictionary]) { $v = ConvertTo-Json -InputObject $v -Depth 6 -Compress }
        elseif ($v -is [System.Collections.IList]) {
            if (@($v | Where-Object { $_ -is [System.Collections.IDictionary] }).Count -gt 0) { $v = ConvertTo-Json -InputObject $v -Depth 6 -Compress }
            else { $v = (@($v) -join '; ') }
        }
        $o[$c] = $v
    }
    [pscustomobject]$o
}

function Get-DiagColumns {
    param([object[]]$Rows)
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($r in ($Rows | Select-Object -First 200)) {
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { if (-not $cols.Contains([string]$k)) { $cols.Add([string]$k) } } }
    }
    return $cols.ToArray()
}

function Write-DiagFile {
    param([string]$Path, [string]$Content)
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($true)))
}

function Complete-DiagRun {
    <# Sanitizes (if enabled) and writes report.html, report.json, one CSV per tabular section, then opens the HTML. #>
    param([switch]$NoOpen)
    $run = $script:DiagRun
    if (-not $run) { return }
    $finished = (Get-Date).ToUniversalTime()

    $findings = @($run.Findings | ForEach-Object { ConvertTo-DiagPlain -InputObject $_ })
    if (@($run.Findings | Where-Object { $_.Severity -ne 'OK' -and $_.Severity -ne 'Info' }).Count -eq 0 -and $run.Findings.Count -eq 0) {
        $findings = @([ordered]@{ Severity = 'OK'; Area = ''; Title = 'No issues detected by the automated checks'; Detail = 'Review the data sections below for anything unusual.'; Recommendation = '' })
    }
    $report = [ordered]@{
        Meta     = [ordered]@{
            Tool          = 'M365 Read-Only Diagnostics'
            Script        = $run.Name
            Title         = $run.Title
            StartedUtc    = $run.Started.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
            FinishedUtc   = $finished.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
            RunBy         = "$env:USERNAME on $env:COMPUTERNAME"
            PowerShell    = $PSVersionTable.PSVersion.ToString() + ' ' + $PSVersionTable.PSEdition
            Sanitized     = $run.Sanitize
            Parameters    = $run.Parameters
            ReadOnly      = 'This report was produced by read-only commands. No configuration was changed.'
        }
        Findings = $findings
        Sections = [ordered]@{}
    }
    foreach ($s in $run.Sections) {
        $name = $s.Name; $i = 2
        while ($report.Sections.Contains($name)) { $name = "$($s.Name) ($i)"; $i++ }
        $report.Sections[$name] = [ordered]@{ Description = $s.Description; Data = $s.Data }
    }

    if ($run.Sanitize) {
        Write-DiagInfo 'Sanitizing output' -Level Step
        Invoke-DiagSanitizeNode -Node $report -Mode Collect
        $report = Invoke-DiagSanitizeNode -Node $report -Mode Replace
        $report.Meta.Sanitized = $true
    }

    $folder = Join-Path -Path $run.OutputRoot -ChildPath $run.RunId
    [void][System.IO.Directory]::CreateDirectory($folder)

    # JSON (full data)
    Write-DiagFile -Path (Join-Path $folder 'report.json') -Content (ConvertTo-Json -InputObject $report -Depth 12)

    # CSV per tabular section
    $n = 0
    foreach ($key in $report.Sections.Keys) {
        $n++
        $data = $report.Sections[$key].Data
        $safe = ($key -replace '[^\w\-]+', '_').Trim('_')
        $rows = $null
        if ($data -is [System.Collections.IList] -and @($data).Count -gt 0 -and @($data)[0] -is [System.Collections.IDictionary]) { $rows = @($data) }
        elseif ($data -is [System.Collections.IDictionary]) { $rows = @($data) }
        if ($rows) {
            $cols = Get-DiagColumns -Rows $rows
            $csv = $rows | ForEach-Object { ConvertTo-DiagFlatRow -Row $_ -Columns $cols } | ConvertTo-Csv -NoTypeInformation
            Write-DiagFile -Path (Join-Path $folder ('{0:d2}_{1}.csv' -f $n, $safe)) -Content ($csv -join [Environment]::NewLine)
        }
    }
    $fcsv = $report.Findings | ForEach-Object { ConvertTo-DiagFlatRow -Row $_ -Columns @('Severity', 'Area', 'Title', 'Detail', 'Recommendation') } | ConvertTo-Csv -NoTypeInformation
    Write-DiagFile -Path (Join-Path $folder '00_Findings.csv') -Content ($fcsv -join [Environment]::NewLine)

    # HTML
    $htmlPath = Join-Path $folder 'report.html'
    Write-DiagFile -Path $htmlPath -Content (ConvertTo-DiagHtmlReport -Report $report)

    # Sanitization map stays OUTSIDE the report folder so the folder can be zipped and shared safely.
    if ($run.Sanitize) {
        $mapDir = Join-Path -Path $run.OutputRoot -ChildPath '_private-maps'
        [void][System.IO.Directory]::CreateDirectory($mapDir)
        $mapPath = Join-Path $mapDir "$($run.RunId).map.json"
        Write-DiagFile -Path $mapPath -Content (ConvertTo-Json -InputObject (Get-DiagSanitizerMap) -Depth 3)
    }

    # Console summary
    $sev = @('Critical', 'Warning', 'Error', 'Info', 'OK')
    Write-Host ''
    Write-Host ('-' * 78) -ForegroundColor DarkCyan
    $counts = foreach ($s in $sev) { '{0}: {1}' -f $s, @($report.Findings | Where-Object { $_.Severity -eq $s }).Count }
    Write-Host ('  Findings  ' + ($counts -join '   ')) -ForegroundColor Cyan
    foreach ($f in @($report.Findings | Where-Object { $_.Severity -in 'Critical', 'Warning' } | Select-Object -First 12)) {
        $color = if ($f.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
        Write-Host ("   - [{0}] {1}" -f $f.Severity, $f.Title) -ForegroundColor $color
    }
    Write-Host "  Report folder: $folder" -ForegroundColor Green
    if ($run.Sanitize) { Write-Host "  Private de-anonymization map (do NOT share): $mapPath" -ForegroundColor DarkGray }
    Write-Host ('-' * 78) -ForegroundColor DarkCyan

    if (-not $NoOpen -and [Environment]::UserInteractive) {
        try { Invoke-Item -LiteralPath $htmlPath } catch { Write-Verbose "Could not open report: $_" }
    }
    $script:DiagRun = $null
    return $folder
}

function ConvertTo-DiagHtmlReport {
    param([System.Collections.IDictionary]$Report)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $meta = $Report.Meta
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(& $enc $meta.Title)</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#5d6675;--card:#fff;--line:#dde1e7;--crit:#b42318;--warn:#b54708;--err:#7a2e98;--info:#3a5a8c;--ok:#18794e;--code:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ee;--muted:#9aa3b2;--card:#1c2027;--line:#2c323c;--crit:#f97066;--warn:#fdb022;--err:#d6a6f2;--info:#8fb3ef;--ok:#47cd89;--code:#252b34}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
header{padding:20px 24px;border-bottom:1px solid var(--line);background:var(--card)}h1{margin:0 0 4px;font-size:20px}
.badges span{display:inline-block;margin:6px 6px 0 0;padding:2px 8px;border-radius:10px;font-size:12px;border:1px solid var(--line);color:var(--muted)}
main{padding:16px 24px;max-width:1500px}section{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:0 0 16px;padding:12px 16px;overflow-x:auto}
h2{font-size:16px;margin:4px 0 8px}p.desc{color:var(--muted);margin:0 0 8px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600}td code{background:var(--code);padding:1px 4px;border-radius:4px;font-size:12px;word-break:break-all}
.sev{font-weight:700;white-space:nowrap}.Critical{color:var(--crit)}.Warning{color:var(--warn)}.Error{color:var(--err)}.Info{color:var(--info)}.OK{color:var(--ok)}
nav a{margin-right:12px;color:var(--info);text-decoration:none;font-size:13px}.kv th{width:28%}.note{color:var(--muted);font-size:12px}
</style></head><body><header>
<h1>$(& $enc $meta.Title)</h1>
<div class="badges"><span>READ-ONLY</span><span>$(if($meta.Sanitized){'SANITIZED'}else{'NOT SANITIZED - internal use only'})</span><span>Script: $(& $enc $meta.Script)</span><span>Run (UTC): $(& $enc $meta.StartedUtc)</span><span>By: $(& $enc $meta.RunBy)</span><span>PowerShell $(& $enc $meta.PowerShell)</span></div>
</header><main>
"@)
    # Navigation
    [void]$sb.Append('<section><nav><a href="#findings">Findings</a>')
    $i = 0
    foreach ($k in $Report.Sections.Keys) { $i++; [void]$sb.Append("<a href=""#s$i"">$(& $enc $k)</a>") }
    [void]$sb.Append('</nav></section>')

    # Findings
    $order = @{ Critical = 0; Warning = 1; Error = 2; Info = 3; OK = 4 }
    [void]$sb.Append('<section id="findings"><h2>Findings</h2><table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>')
    foreach ($f in ($Report.Findings | Sort-Object { $order[$_.Severity] })) {
        [void]$sb.Append("<tr><td class=""sev $($f.Severity)"">$(& $enc $f.Severity)</td><td>$(& $enc $f.Area)</td><td>$(& $enc $f.Title)</td><td>$(& $enc $f.Detail)</td><td>$(& $enc $f.Recommendation)</td></tr>")
    }
    [void]$sb.Append('</table></section>')

    # Parameters
    if ($meta.Parameters -and $meta.Parameters.Count -gt 0) {
        [void]$sb.Append('<section><h2>Run parameters</h2><table class="kv">')
        foreach ($k in $meta.Parameters.Keys) { [void]$sb.Append("<tr><th>$(& $enc $k)</th><td>$(& $enc $meta.Parameters[$k])</td></tr>") }
        [void]$sb.Append('</table></section>')
    }

    # Data sections
    $i = 0
    $maxRows = 1000
    foreach ($k in $Report.Sections.Keys) {
        $i++
        $sec = $Report.Sections[$k]
        $data = $sec.Data
        [void]$sb.Append("<section id=""s$i""><h2>$(& $enc $k)</h2>")
        if ($sec.Description) { [void]$sb.Append("<p class=""desc"">$(& $enc $sec.Description)</p>") }
        if ($null -eq $data -or ($data -is [System.Collections.IList] -and @($data).Count -eq 0)) {
            [void]$sb.Append('<p class="note">No data returned.</p>')
        }
        elseif ($data -is [System.Collections.IDictionary]) {
            [void]$sb.Append('<table class="kv">')
            foreach ($kk in $data.Keys) { [void]$sb.Append("<tr><th>$(& $enc $kk)</th><td>$(ConvertTo-DiagHtmlValue $data[$kk])</td></tr>") }
            [void]$sb.Append('</table>')
        }
        elseif ($data -is [System.Collections.IList] -and @($data)[0] -is [System.Collections.IDictionary]) {
            $rows = @($data)
            $cols = Get-DiagColumns -Rows $rows
            [void]$sb.Append("<p class=""note"">$($rows.Count) row(s)</p><table><tr>")
            foreach ($c in $cols) { [void]$sb.Append("<th>$(& $enc $c)</th>") }
            [void]$sb.Append('</tr>')
            foreach ($r in ($rows | Select-Object -First $maxRows)) {
                [void]$sb.Append('<tr>')
                foreach ($c in $cols) { [void]$sb.Append("<td>$(ConvertTo-DiagHtmlValue $r[$c])</td>") }
                [void]$sb.Append('</tr>')
            }
            [void]$sb.Append('</table>')
            if ($rows.Count -gt $maxRows) { [void]$sb.Append("<p class=""note"">Showing first $maxRows rows - full data is in the CSV/JSON files.</p>") }
        }
        elseif ($data -is [System.Collections.IList]) {
            [void]$sb.Append('<ul>')
            foreach ($v in $data) { [void]$sb.Append("<li>$(ConvertTo-DiagHtmlValue $v)</li>") }
            [void]$sb.Append('</ul>')
        }
        else { [void]$sb.Append("<pre>$(& $enc $data)</pre>") }
        [void]$sb.Append('</section>')
    }
    [void]$sb.Append('<p class="note">Generated by M365 Read-Only Diagnostics. Full data: report.json and CSV files in this folder.</p></main></body></html>')
    return $sb.ToString()
}

#endregion

#region ---------------------------------------------------------------- Module / connection guards

function Assert-DiagModule {
    <# Ensures a module is installed and imported. Never installs anything (use Scripts\Setup\Install-DiagPrerequisites.ps1). #>
    param([Parameter(Mandatory)][string]$Name, [string]$MinimumVersion = '0.0', [switch]$AllowWindowsPowerShellFallback)
    if (Get-Module -Name $Name) { return }
    $available = Get-Module -ListAvailable -Name $Name | Sort-Object -Property Version -Descending | Select-Object -First 1
    if (-not $available) {
        throw "Required module '$Name' is not installed. Run the launcher option [P] (Prerequisites) or: Install-Module $Name -Scope CurrentUser"
    }
    if ($available.Version -lt [version]$MinimumVersion) {
        throw "Module '$Name' $($available.Version) is older than the required $MinimumVersion. Update it with: Update-Module $Name"
    }
    try { Import-Module -Name $Name -MinimumVersion $MinimumVersion -DisableNameChecking -ErrorAction Stop -WarningAction SilentlyContinue }
    catch {
        if ($AllowWindowsPowerShellFallback -and $PSVersionTable.PSEdition -eq 'Core') {
            Import-Module -Name $Name -UseWindowsPowerShell -DisableNameChecking -ErrorAction Stop -WarningAction SilentlyContinue
        }
        else { throw }
    }
}

function Test-DiagReadOnlyScope {
    param([string]$Scope)
    if ($Scope -in @('openid', 'profile', 'offline_access', 'email')) { return $true }
    return ($Scope -match '^[A-Za-z][A-Za-z\.]*\.Read(Basic)?(\.All)?$')
}

function Connect-DiagGraph {
    <#
        Connects to Microsoft Graph with READ-ONLY delegated scopes only (any *.ReadWrite* scope is refused).
        Reuses an existing session when it already has the scopes.
    #>
    param([Parameter(Mandatory)][string[]]$Scopes, [string]$TenantId)
    Assert-DiagModule -Name 'Microsoft.Graph.Authentication' -MinimumVersion '2.0.0'
    foreach ($s in $Scopes) { if (-not (Test-DiagReadOnlyScope $s)) { throw "Refusing to request non read-only Graph scope '$s'." } }

    $ctx = Get-MgContext
    $need = $Scopes
    if ($ctx) {
        $missing = @($Scopes | Where-Object { $ctx.Scopes -notcontains $_ })
        if ($missing.Count -eq 0) {
            Write-DiagInfo "Reusing Microsoft Graph session ($($ctx.Account))" -Level Ok
            Register-DiagGraphTenant
            return
        }
        $need = @($Scopes) + @($ctx.Scopes | Where-Object { Test-DiagReadOnlyScope $_ }) | Select-Object -Unique
    }
    Write-DiagInfo 'Connecting to Microsoft Graph (a sign-in window may appear)...' -Level Step
    Write-DiagInfo ("Read-only scopes: " + ($Scopes -join ', ')) -Level Dim
    $p = @{ Scopes = $need; NoWelcome = $true; ErrorAction = 'Stop'; ContextScope = 'Process' }
    if ($TenantId) { $p['TenantId'] = $TenantId }
    Connect-MgGraph @p | Out-Null
    $ctx = Get-MgContext
    if ($ctx) {
        $writeScopes = @($ctx.Scopes | Where-Object { $_ -match 'ReadWrite|\.Write|FullControl|Manage' })
        if ($writeScopes.Count -gt 0) {
            Write-DiagInfo 'Note: this account previously consented write scopes for this app. These scripts still only send HTTP GET requests.' -Level Dim
        }
    }
    Register-DiagGraphTenant
}

function Register-DiagGraphTenant {
    try {
        $org = Invoke-DiagGraph -Uri 'v1.0/organization?$select=id,displayName,verifiedDomains'
        foreach ($o in @($org)) {
            Register-DiagSensitiveValue -Value $o.displayName -Category org
            foreach ($d in @($o.verifiedDomains)) { Register-DiagSensitiveValue -Value $d.name -Category domain }
        }
    }
    catch { Write-Verbose "Tenant registration skipped: $_" }
}

function Invoke-DiagGraph {
    <#
        GET-only wrapper for Microsoft Graph. -All follows @odata.nextLink up to -MaxItems.
        There is intentionally no -Method parameter.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$All,
        [switch]$Eventual,
        [int]$MaxItems = 5000
    )
    $headers = @{}
    if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
    $Uri = $Uri.TrimStart('/')
    $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $headers -OutputType PSObject -ErrorAction Stop
    if ($null -eq $resp) { return $null }
    if (-not $resp.PSObject.Properties['value']) { return $resp }
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($resp.value)) { $items.Add($v) }
    $next = $resp.'@odata.nextLink'
    while ($All -and $next -and $items.Count -lt $MaxItems) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers -OutputType PSObject -ErrorAction Stop
        foreach ($v in @($resp.value)) { $items.Add($v) }
        $next = $resp.'@odata.nextLink'
    }
    if ($All -and $next) { Write-DiagInfo "Result capped at $MaxItems items." -Level Warn }
    return , ($items.ToArray())
}

function Connect-DiagExchange {
    <#
        Connects to Exchange Online importing ONLY the listed Get-/Search- cmdlets (Connect-ExchangeOnline -CommandName),
        so no write cmdlet exists in the session at all.
    #>
    param([Parameter(Mandatory)][string[]]$CommandName, [string]$UserPrincipalName)
    Assert-DiagModule -Name 'ExchangeOnlineManagement' -MinimumVersion '3.2.0'
    $wanted = @($CommandName + @('Get-AcceptedDomain', 'Get-OrganizationConfig')) | Select-Object -Unique
    foreach ($c in $wanted) { if ($c -notmatch '^(Get|Search)-') { throw "Refusing to load non read-only Exchange cmdlet '$c'." } }

    $conn = $null
    try { $conn = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -notmatch 'compliance|protection\.outlook' } | Select-Object -First 1 } catch { $conn = $null }
    $missing = @($wanted | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
    if ($conn -and $missing.Count -eq 0) {
        Write-DiagInfo "Reusing Exchange Online session ($($conn.UserPrincipalName))" -Level Ok
    }
    else {
        foreach ($c in $wanted) { [void]$script:ExoCommandsLoaded.Add($c) }
        if ($conn) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
        Write-DiagInfo 'Connecting to Exchange Online (a sign-in window may appear)...' -Level Step
        Write-DiagInfo "Session restricted to $($script:ExoCommandsLoaded.Count) read-only cmdlets." -Level Dim
        $p = @{ CommandName = @($script:ExoCommandsLoaded); ShowBanner = $false; ErrorAction = 'Stop' }
        if ($UserPrincipalName) { $p['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @p | Out-Null
    }
    try { foreach ($d in @(Get-AcceptedDomain -ErrorAction Stop)) { Register-DiagSensitiveValue -Value ([string]$d.DomainName) -Category domain } } catch { Write-Verbose $_ }
}

function Connect-DiagTeams {
    param([string]$TenantId)
    Assert-DiagModule -Name 'MicrosoftTeams' -MinimumVersion '5.0.0'
    $tenant = $null
    try { $tenant = Get-CsTenant -ErrorAction Stop } catch { $tenant = $null }
    if ($tenant) { Write-DiagInfo 'Reusing Microsoft Teams session' -Level Ok }
    else {
        Write-DiagInfo 'Connecting to Microsoft Teams (a sign-in window may appear)...' -Level Step
        $p = @{ ErrorAction = 'Stop' }
        if ($TenantId) { $p['TenantId'] = $TenantId }
        Connect-MicrosoftTeams @p | Out-Null
        $tenant = Get-CsTenant -ErrorAction Stop
    }
    Register-DiagSensitiveValue -Value ([string]$tenant.DisplayName) -Category org
    foreach ($d in @($tenant.VerifiedDomains)) {
        $n = if ($d.PSObject.Properties['Name']) { $d.Name } else { [string]$d }
        Register-DiagSensitiveValue -Value $n -Category domain
    }
    return $tenant
}

function Connect-DiagSharePoint {
    <# Connects to the SharePoint Online admin endpoint. Returns @{ AdminUrl; TenantName }. #>
    param([string]$TenantName)
    Assert-DiagModule -Name 'Microsoft.Online.SharePoint.PowerShell' -MinimumVersion '16.0.0' -AllowWindowsPowerShellFallback
    $existing = $null
    try { $existing = Get-SPOTenant -ErrorAction Stop } catch { $existing = $null }
    if ($existing -and $script:SpoTenantName -and (-not $TenantName -or $TenantName -eq $script:SpoTenantName)) {
        Write-DiagInfo 'Reusing SharePoint Online session' -Level Ok
        return [pscustomobject]@{ AdminUrl = "https://$($script:SpoTenantName)-admin.sharepoint.com"; TenantName = $script:SpoTenantName }
    }
    if (-not $TenantName) {
        $TenantName = Read-DiagValue -Prompt 'SharePoint tenant name (the "contoso" in contoso.sharepoint.com) or any SharePoint URL'
    }
    if ($TenantName -match '(?i)https?://([a-z0-9\-]+?)(-admin|-my)?\.sharepoint\.') { $TenantName = $Matches[1] }
    $TenantName = $TenantName.Trim().ToLowerInvariant()
    $adminUrl = "https://$TenantName-admin.sharepoint.com"
    Write-DiagInfo "Connecting to SharePoint Online admin ($adminUrl)..." -Level Step
    Connect-SPOService -Url $adminUrl -ErrorAction Stop
    $script:SpoTenantName = $TenantName
    Register-DiagSensitiveValue -Value $TenantName -Category tenant
    return [pscustomobject]@{ AdminUrl = $adminUrl; TenantName = $TenantName }
}

function Get-DiagTimeSkew {
    <# Compares local clock with the HTTP Date header from login.microsoftonline.com (HEAD request). Returns minutes (local - server). #>
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        $req = [System.Net.WebRequest]::Create('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration')
        $req.Method = 'HEAD'
        $req.Timeout = 10000
        $resp = $req.GetResponse()
        $dateHeader = $resp.Headers['Date']
        $resp.Close()
        if (-not $dateHeader) { return $null }
        $server = [datetime]::Parse($dateHeader, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
        return [math]::Round(((Get-Date).ToUniversalTime() - $server).TotalMinutes, 1)
    }
    catch { return $null }
}

#endregion

#region ---------------------------------------------------------------- Knowledge tables

$script:SignInErrors = @{
    '0'       = @('Success', $false, '')
    '16000'   = @('Account picker / multiple accounts (interrupt)', $true, 'Normal interrupt - user chose an account.')
    '16001'   = @('Account selection required (interrupt)', $true, '')
    '16003'   = @('User account not found in the tenant the app expects', $false, 'Check the user is signing in to the right tenant / account type.')
    '50011'   = @('Reply URL mismatch for the application', $false, 'App registration redirect URI issue (app owner).')
    '50020'   = @('User from identity provider does not exist in tenant', $false, 'Guest not invited/redeemed, or wrong account used.')
    '50034'   = @('User account does not exist in the directory', $false, 'Typo in username, or the account was deleted.')
    '50053'   = @('Account locked (Smart Lockout) or sign-in from malicious IP blocked', $false, 'Wait for lockout to expire; look for stale credentials on devices or a password spray.')
    '50055'   = @('Password expired', $false, 'User must change password.')
    '50056'   = @('Invalid or null password - no password stored', $false, 'Check password hash sync / federation.')
    '50057'   = @('User account is disabled', $false, 'Enable the account if appropriate (on-prem AD if synced).')
    '50058'   = @('Session information not sufficient for SSO (silent sign-in failed)', $true, 'Usually benign: app tried silent sign-in.')
    '50064'   = @('Credential validation failed', $false, '')
    '50072'   = @('User must register for MFA (interrupt)', $true, 'User needs to complete MFA registration.')
    '50074'   = @('Strong authentication (MFA) required (interrupt)', $true, '')
    '50076'   = @('MFA required by policy/location (interrupt)', $true, '')
    '50079'   = @('User must enroll for second factor (interrupt)', $true, '')
    '50089'   = @('Flow token expired - authentication took too long', $false, 'User should retry promptly.')
    '50097'   = @('Device authentication required', $true, 'Device needs to be registered/joined; check PRT (dsregcmd /status).')
    '50105'   = @('User not assigned to the application', $false, 'Assign the user/group to the enterprise app or disable assignment requirement.')
    '50125'   = @('Sign-in interrupted by password reset/registration', $true, '')
    '50126'   = @('Invalid username or password', $false, 'Wrong password or stale credentials cached on a device/app. Many from one IP = possible spray.')
    '50128'   = @('Invalid domain name - no tenant found', $false, 'Domain not verified in any tenant.')
    '50129'   = @('Device is not workplace joined', $false, 'Workplace join / registration required.')
    '50131'   = @('Conditional Access: device/app state not satisfied', $false, 'Check device compliance & CA requirements.')
    '50132'   = @('Session revoked (password change / admin revoke)', $false, 'User must sign in again.')
    '50133'   = @('Session invalid due to password expiration or recent password change', $false, 'User must sign in again with new password.')
    '50140'   = @('"Keep me signed in" interrupt', $true, '')
    '50143'   = @('Session mismatch - wrong tenant/user in session', $false, '')
    '50144'   = @('Active Directory password expired', $false, 'User must change their on-premises password.')
    '50155'   = @('Device authentication failed', $false, 'Device object may be disabled/deleted in Entra ID. Re-register the device.')
    '50158'   = @('External security challenge not satisfied (3rd-party MFA / custom control)', $false, '')
    '50173'   = @('Grant expired due to password change/reset', $false, 'Sign in again.')
    '50199'   = @('Security confirmation prompt (interrupt)', $true, '')
    '51004'   = @('User account not in directory', $false, '')
    '53000'   = @('Conditional Access: device not compliant/managed', $false, 'Enroll/fix compliance in Intune or use a compliant device.')
    '53001'   = @('Conditional Access: device not domain/hybrid joined', $false, '')
    '53002'   = @('Conditional Access: application used is not an approved app', $false, 'Use an approved client app (e.g. Outlook mobile).')
    '53003'   = @('Blocked by Conditional Access', $false, 'Review the failed policy in the sign-in details (see appliedConditionalAccessPolicies).')
    '53004'   = @('User must complete MFA registration but is blocked from doing so', $false, 'Registration blocked by CA/risk; admin assistance required.')
    '53011'   = @('User blocked due to risk on home tenant', $false, '')
    '65001'   = @('Application consent required', $false, 'Admin or user consent needed for the app.')
    '70043'   = @('Refresh token expired due to sign-in frequency (CA)', $true, 'User must re-authenticate; expected with sign-in frequency policies.')
    '70044'   = @('Session expired / refresh token lifetime', $true, '')
    '700016'  = @('Application not found in tenant', $false, 'App not consented/registered in this tenant.')
    '7000218' = @('Request missing client assertion/secret', $false, 'App configuration issue (public client flows).')
    '80014'   = @('Pass-through authentication agent timeout', $false, 'Check PTA agents on-premises.')
    '81010'   = @('Seamless SSO failed - Kerberos ticket invalid/expired', $true, 'Seamless SSO computer account key may need rolling.')
    '81016'   = @('Seamless SSO: invalid Kerberos ticket', $true, '')
    '90072'   = @('Account does not exist in tenant - must be added as external user', $false, 'Invite the guest user first.')
    '90095'   = @('Admin consent required (interrupt)', $true, '')
    '500121'  = @('MFA failed - user did not complete strong authentication', $false, 'User denied/timed out the MFA prompt; possible MFA fatigue attack if unexpected.')
    '500011'  = @('Resource principal not found in tenant', $false, '')
    '530032'  = @('Blocked by security policy (security defaults/user risk)', $false, '')
    '530034'  = @('Conditional Access: blocked - token protection / device bound requirement', $false, '')
}

function Get-DiagSignInErrorInfo {
    <# Returns Description/IsInterrupt/Hint for a Microsoft Entra sign-in error code. #>
    param([Parameter(Mandatory)]$Code)
    $c = [string]$Code
    if ($script:SignInErrors.ContainsKey($c)) {
        $e = $script:SignInErrors[$c]
        return [pscustomobject]@{ Code = $c; Description = $e[0]; IsInterrupt = $e[1]; Hint = $e[2] }
    }
    return [pscustomobject]@{ Code = $c; Description = "See https://login.microsoftonline.com/error?code=$c"; IsInterrupt = $false; Hint = '' }
}

$script:NdrCodes = [ordered]@{
    '5\.1\.1\b'          = 'Recipient address does not exist (typo, deleted mailbox, or stale autocomplete/X500 entry).'
    '5\.1\.10'           = 'Recipient not found by SMTP address lookup (Directory Based Edge Blocking) - recipient does not exist in EXO.'
    '5\.1\.8'            = 'Sender is blocked from sending (Restricted entities / outbound spam). Check Get-BlockedSenderAddress & Defender portal.'
    '5\.1\.90'           = 'Sender reached daily recipient rate limit.'
    '5\.2\.2'            = 'Recipient mailbox is full.'
    '5\.2\.3'            = 'Message too large for sender/recipient/org limits.'
    '5\.4\.1'            = 'Relay access denied - recipient domain not accepted by the receiving org, or DBEB rejected it.'
    '5\.4\.(6|14)'       = 'Routing loop detected (often forwarding or hybrid connector misconfiguration).'
    '5\.4\.316'          = 'Connection refused/timeout to the destination server.'
    '5\.7\.1\b'          = 'Delivery not authorized - sender not allowed (restricted group/mailbox, transport rule, or recipient org policy).'
    '5\.7\.12'           = 'Sender not authenticated - group/recipient only accepts mail from authenticated (internal) senders.'
    '5\.7\.13[34]'       = 'Sender not authenticated or not allowed for this group/mailbox.'
    '5\.7\.23'           = 'Rejected by recipient due to SPF failure.'
    '5\.7\.57'           = 'Client not authenticated to send (SMTP AUTH client submission) - check SmtpClientAuthentication and credentials.'
    '5\.7\.509'          = 'Rejected by DMARC policy of the sender domain.'
    '5\.7\.520'          = 'External auto-forwarding blocked by the outbound spam policy.'
    '5\.7\.5\d\d'        = 'Access denied by policy (see detail).'
    '5\.7\.6[0-4]\d'     = 'Sending IP address banned/blocked (IP reputation).'
    '5\.7\.7[0-4]\d'     = 'Tenant exceeded sending limits or is blocked for suspicious activity - contact Microsoft support.'
    '5\.7\.750'          = 'Unregistered domain / tenant blocked from sending.'
    '4\.4\.7'            = 'Message expired in queue - destination unreachable for too long (DNS/connector/firewall).'
    '4\.7\.500'          = 'Server busy / throttled - temporary.'
    '550 5\.7\.708'      = 'Access denied - traffic not accepted from this IP (new/low reputation tenant sending).'
}

function Get-DiagNdrInfo {
    <# Explains common NDR/enhanced status codes found in text. #>
    param([string]$Text)
    if (-not $Text) { return $null }
    foreach ($k in $script:NdrCodes.Keys) { if ($Text -match $k) { return $script:NdrCodes[$k] } }
    return $null
}

#endregion

Export-ModuleMember -Function @(
    'Start-DiagRun', 'Complete-DiagRun', 'Add-DiagData', 'Add-DiagFinding', 'Invoke-DiagStep', 'Write-DiagInfo',
    'Register-DiagSensitiveValue', 'Protect-DiagText', 'Get-DiagSanitizerMap', 'New-DiagSanitizer',
    'Connect-DiagGraph', 'Invoke-DiagGraph', 'Connect-DiagExchange', 'Connect-DiagTeams', 'Connect-DiagSharePoint',
    'Assert-DiagModule', 'Get-DiagDefaultOutputRoot',
    'Select-DiagFile', 'Read-DiagValue', 'Read-DiagChoice', 'Read-DiagYesNo', 'Read-DiagIdentityList', 'Import-DiagIdentityFile',
    'ConvertTo-DiagBytes', 'ConvertTo-DiagDate', 'Format-DiagBytes', 'Select-DiagObject', 'Get-DiagEmailAddress', 'Test-DiagExternalAddress',
    'Get-DiagSignInErrorInfo', 'Get-DiagNdrInfo', 'Get-DiagErrorHint', 'Get-DiagTimeSkew'
)
