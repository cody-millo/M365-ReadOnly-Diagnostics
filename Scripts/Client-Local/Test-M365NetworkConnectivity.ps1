<#
.SYNOPSIS
    THIS PC: Microsoft 365 network checks - DNS resolution, TCP 443 reachability and latency, TLS inspection detection (certificate issuer), proxy configuration (WinHTTP/WinINET/PAC per URL), Teams media UDP 3478 (STUN) and clock skew. No sign-in needed.

.DESCRIPTION
    Run on the affected device/network for "everything is slow", "Teams call quality bad", "Outlook disconnected",
    "sign-in page won't load", "works at home but not in the office". Tests a fixed list of Microsoft 365 endpoints
    one at a time (no scanning) and reports which ones fail or are intercepted by a proxy/firewall.

.PARAMETER TenantName
    Optional SharePoint tenant name (the "contoso" in contoso.sharepoint.com) to include SharePoint/OneDrive hosts.

.PARAMETER SkipUdp
    Skip the Teams media UDP/STUN test.

.EXAMPLE
    .\Test-M365NetworkConnectivity.ps1 -TenantName contoso

.NOTES
    Connection : None (network tests only)
    Roles      : None
    Read-only  : DNS lookups, TCP/TLS handshakes (no data sent), one STUN binding request per relay, proxy settings read.
#>
[CmdletBinding()]
param(
    [string]$TenantName,
    [switch]$SkipUdp,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $PSBoundParameters.ContainsKey('TenantName')) { $TenantName = Read-DiagValue -Prompt 'SharePoint tenant name to include (the "contoso" in contoso.sharepoint.com)' -Optional }
if ($TenantName -match '(?i)https?://([a-z0-9\-]+?)(-my|-admin)?\.sharepoint\.') { $TenantName = $Matches[1] }

Start-DiagRun -Name 'Test-M365NetworkConnectivity' -Title 'Local Device - Microsoft 365 Network Connectivity' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ TenantName = $TenantName; SkipUdp = [bool]$SkipUdp })
if ($TenantName) { Register-DiagSensitiveValue -Value $TenantName -Category tenant }

$endpoints = @(
    @{ Host = 'login.microsoftonline.com'; Service = 'Entra ID sign-in'; Category = 'Optimize/Allow' }
    @{ Host = 'login.microsoft.com'; Service = 'Entra ID sign-in'; Category = 'Allow' }
    @{ Host = 'device.login.microsoftonline.com'; Service = 'Device sign-in / PRT'; Category = 'Allow' }
    @{ Host = 'enterpriseregistration.windows.net'; Service = 'Device registration'; Category = 'Default' }
    @{ Host = 'graph.microsoft.com'; Service = 'Microsoft Graph'; Category = 'Default' }
    @{ Host = 'outlook.office365.com'; Service = 'Exchange Online / Outlook'; Category = 'Optimize' }
    @{ Host = 'outlook.office.com'; Service = 'Outlook on the web'; Category = 'Optimize' }
    @{ Host = 'autodiscover-s.outlook.com'; Service = 'Autodiscover'; Category = 'Allow' }
    @{ Host = 'smtp.office365.com'; Service = 'SMTP client submission (443 test)'; Category = 'Allow' }
    @{ Host = 'teams.microsoft.com'; Service = 'Teams'; Category = 'Allow' }
    @{ Host = 'teams.cloud.microsoft'; Service = 'Teams (new domain)'; Category = 'Allow' }
    @{ Host = 'statics.teams.cdn.office.net'; Service = 'Teams CDN'; Category = 'Default' }
    @{ Host = 'worldaz.tr.teams.microsoft.com'; Service = 'Teams media relay (TCP fallback)'; Category = 'Optimize' }
    @{ Host = 'officecdn.microsoft.com'; Service = 'Office updates CDN'; Category = 'Default' }
    @{ Host = 'config.office.com'; Service = 'Office cloud policy'; Category = 'Default' }
    @{ Host = 'ols.officeapps.live.com'; Service = 'Office licensing/activation'; Category = 'Default' }
    @{ Host = 'manage.microsoft.com'; Service = 'Intune'; Category = 'Default' }
    @{ Host = 'enrollment.manage.microsoft.com'; Service = 'Intune enrollment'; Category = 'Default' }
    @{ Host = 'oneclient.sfx.ms'; Service = 'OneDrive client updates'; Category = 'Default' }
)
if ($TenantName) {
    $endpoints += @{ Host = "$TenantName.sharepoint.com"; Service = 'SharePoint Online'; Category = 'Optimize' }
    $endpoints += @{ Host = "$TenantName-my.sharepoint.com"; Service = 'OneDrive for Business'; Category = 'Optimize' }
}
$trustedIssuers = 'Microsoft|DigiCert|Baltimore|GlobalSign|Entrust|Sectigo|Let''s Encrypt'

function Test-Endpoint {
    param([string]$HostName)
    $r = [ordered]@{ Host = $HostName; DnsOk = $false; DnsMs = $null; Addresses = ''; TcpOk = $false; ConnectMs = $null; TlsOk = $false; TlsVersion = ''; CertIssuer = ''; Intercepted = $false; Proxy = ''; Error = '' }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostName)
        $r.DnsMs = $sw.ElapsedMilliseconds; $r.DnsOk = $true
        $r.Addresses = (@($addrs | Select-Object -First 3 | ForEach-Object { $_.IPAddressToString }) -join ', ')
    }
    catch { $r.Error = "DNS: $($_.Exception.InnerException.Message)"; return [pscustomobject]$r }
    try {
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $u = [uri]"https://$HostName/"
        $pu = $proxy.GetProxy($u)
        $r.Proxy = if ($pu -and $pu.Host -ne $u.Host) { "$($pu.Host):$($pu.Port)" } else { 'DIRECT' }
    }
    catch { $r.Proxy = '?' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $sw.Restart()
        $ar = $client.BeginConnect($HostName, 443, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(5000)) { throw 'TCP 443 connect timed out (5 s)' }
        $client.EndConnect($ar)
        $r.ConnectMs = $sw.ElapsedMilliseconds; $r.TcpOk = $true
        $cert = $null
        $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $cb)
        $ssl.ReadTimeout = 5000; $ssl.WriteTimeout = 5000
        $ssl.AuthenticateAsClient($HostName)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $r.TlsOk = $true
        $r.TlsVersion = [string]$ssl.SslProtocol
        $r.CertIssuer = $cert.Issuer
        $r.Intercepted = ($cert.Issuer -notmatch $trustedIssuers)
        $ssl.Dispose()
    }
    catch { if (-not $r.Error) { $r.Error = $_.Exception.Message -replace '^Exception calling "\w+" with "\d+" argument\(s\): ', '' } }
    finally { $client.Close() }
    return [pscustomobject]$r
}

function Test-Stun {
    # Sends one RFC 5389 STUN Binding Request and waits for any response.
    param([string]$HostName, [int]$Port = 3478)
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = 3000
        $tid = New-Object byte[] 12
        (New-Object System.Random).NextBytes($tid)
        $req = [byte[]](@(0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42) + $tid)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        [void]$udp.Send($req, $req.Length, $HostName, $Port)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$ep)
        return [pscustomobject]@{ Host = $HostName; Port = $Port; Ok = ($resp.Length -ge 20); Ms = $sw.ElapsedMilliseconds; Error = '' }
    }
    catch { return [pscustomobject]@{ Host = $HostName; Port = $Port; Ok = $false; Ms = $null; Error = $_.Exception.Message } }
    finally { $udp.Close() }
}

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

    Invoke-DiagStep -Name 'Proxy configuration' -Area 'Proxy' -ScriptBlock {
        $winhttp = (& (Join-Path $env:SystemRoot 'System32\netsh.exe') winhttp show proxy 2>&1 | Out-String).Trim()
        $ie = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        Add-DiagData -Section 'Proxy configuration' -Data ([ordered]@{ WinHTTP = ($winhttp -replace '\s+', ' '); UserProxyEnabled = $ie.ProxyEnable; ProxyServer = $ie.ProxyServer; AutoConfigURL = $ie.AutoConfigURL; ProxyOverride = $ie.ProxyOverride; AutoDetect = $ie.AutoDetect })
        if ($ie.ProxyEnable -eq 1 -or $ie.AutoConfigURL) { Add-DiagFinding -Severity Info -Area 'Proxy' -Title 'A user proxy / PAC file is configured' -Detail 'Microsoft recommends sending Optimize-category traffic (Exchange, SharePoint, Teams media) directly, bypassing proxies and TLS inspection.' }
    } | Out-Null

    $results = New-Object System.Collections.Generic.List[object]
    Invoke-DiagStep -Name "Testing $($endpoints.Count) endpoints (DNS, TCP 443, TLS)" -Area 'Endpoints' -ScriptBlock {
        foreach ($e in $endpoints) {
            $r = Test-Endpoint -HostName $e.Host
            $r | Add-Member -NotePropertyName Service -NotePropertyValue $e.Service
            $r | Add-Member -NotePropertyName Category -NotePropertyValue $e.Category
            $results.Add($r)
            $status = if ($r.TlsOk) { "OK  $($r.ConnectMs) ms" } else { "FAIL $($r.Error)" }
            Write-DiagInfo ("{0,-40} {1}" -f $e.Host, $status) -Level $(if ($r.TlsOk) { 'Dim' } else { 'Warn' })
        }
    } | Out-Null
    Add-DiagData -Section 'Endpoint tests' -Data @($results | Select-Object Service, Host, Category, DnsOk, DnsMs, Addresses, TcpOk, ConnectMs, TlsOk, TlsVersion, Proxy, Intercepted, CertIssuer, Error)

    foreach ($r in $results) {
        if (-not $r.DnsOk) { Add-DiagFinding -Severity Critical -Area 'DNS' -Title "Cannot resolve $($r.Host) ($($r.Service))" -Detail $r.Error -Recommendation 'Check DNS servers / split DNS / DNS filtering.' }
        elseif (-not $r.TcpOk) {
            $sev = if ($r.Proxy -ne 'DIRECT' -and $r.Proxy -ne '?') { 'Info' } else { 'Critical' }
            Add-DiagFinding -Severity $sev -Area 'Connectivity' -Title "TCP 443 to $($r.Host) failed ($($r.Service))" -Detail "$($r.Error). Proxy for this URL: $($r.Proxy)" -Recommendation $(if ($sev -eq 'Info') { 'Direct connections are blocked but a proxy is configured - expected if all traffic must use the proxy.' } else { 'Firewall is blocking Microsoft 365. Allow the endpoints from https://aka.ms/o365ip.' })
        }
        elseif (-not $r.TlsOk) { Add-DiagFinding -Severity Warning -Area 'TLS' -Title "TLS handshake to $($r.Host) failed" -Detail $r.Error -Recommendation 'A firewall/proxy is interfering with TLS, or TLS 1.2 is disabled on this PC.' }
        elseif ($r.Intercepted) { Add-DiagFinding -Severity Warning -Area 'TLS' -Title "TLS inspection detected on $($r.Host)" -Detail "Certificate issued by: $($r.CertIssuer)" -Recommendation 'Exclude Microsoft 365 Optimize/Allow endpoints from TLS inspection - it breaks certificate pinning, Teams, OneDrive and device auth.' }
        elseif ($r.ConnectMs -gt 300) { Add-DiagFinding -Severity Warning -Area 'Latency' -Title "High TCP connect time to $($r.Host): $($r.ConnectMs) ms" -Detail 'Expected < 100 ms on a good network. Check VPN hairpinning, proxies, or distant egress.' }
    }
    $okCount = @($results | Where-Object TlsOk).Count
    if ($okCount -eq $results.Count) { Add-DiagFinding -Severity OK -Area 'Endpoints' -Title "All $okCount endpoints reachable over TLS" }
    if (@($results | Where-Object TlsVersion | Where-Object { $_.TlsVersion -notmatch 'Tls12|Tls13' }).Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'TLS' -Title 'Some connections negotiated TLS below 1.2' }

    if (-not $SkipUdp) {
        Invoke-DiagStep -Name 'Teams media: UDP 3478 (STUN) to the Teams relay' -Area 'Teams media' -ScriptBlock {
            $s = Test-Stun -HostName 'worldaz.tr.teams.microsoft.com' -Port 3478
            Add-DiagData -Section 'Teams media UDP' -Data $s
            if ($s.Ok) { Add-DiagFinding -Severity OK -Area 'Teams media' -Title "UDP 3478 to the Teams relay works ($($s.Ms) ms)" }
            else { Add-DiagFinding -Severity Warning -Area 'Teams media' -Title 'UDP 3478 to the Teams media relay is blocked' -Detail $s.Error -Recommendation 'Teams falls back to TCP/TLS 443 - choppy audio/video. Allow UDP 3478-3481 outbound to 52.112.0.0/14 and 52.122.0.0/15.' }
        } | Out-Null
    }

    Invoke-DiagStep -Name 'Clock skew vs Microsoft' -Area 'Time' -ScriptBlock {
        $skew = Get-DiagTimeSkew
        Add-DiagData -Section 'Time' -Data ([ordered]@{ SkewMinutes = $skew })
        if ($null -ne $skew -and [math]::Abs($skew) -ge 5) { Add-DiagFinding -Severity Critical -Area 'Time' -Title "Clock is off by $skew minutes" -Recommendation 'Fix time sync; tokens are rejected when the clock is >5 minutes off.' }
    } | Out-Null

    Add-DiagFinding -Severity Info -Area 'Next steps' -Title 'For a full Microsoft-hosted analysis use https://connectivity.office.com from the same network' -Quiet
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
