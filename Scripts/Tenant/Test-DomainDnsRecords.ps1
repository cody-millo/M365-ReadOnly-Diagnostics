<#
.SYNOPSIS
    Checks public DNS for Microsoft 365: MX, SPF (incl. 10-lookup limit), DKIM, DMARC, Autodiscover, Teams/SfB SRV, Intune and MTA-STS. No sign-in needed.

.DESCRIPTION
    Resolves the records Microsoft 365 depends on and flags the common misconfigurations behind
    mail flow, spoofing/junk, Outlook profile and device enrollment problems.
    Accepts one or more domains, or a CSV/TXT file of domains (file picker).

.PARAMETER Domain
    One or more domains (e.g. contoso.com). Prompted if omitted (type F to pick a file).

.PARAMETER DnsServer
    Optional DNS server to query (e.g. 1.1.1.1) to rule out internal split-brain DNS.

.EXAMPLE
    .\Test-DomainDnsRecords.ps1 -Domain contoso.com,fabrikam.com -DnsServer 8.8.8.8

.NOTES
    Connection : None (public DNS only)
    Roles      : None
    Read-only  : DNS queries only.
#>
[CmdletBinding()]
param(
    [string[]]$Domain,
    [string]$DnsServer,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) { throw 'Resolve-DnsName is not available (Windows DnsClient module required).' }
if (-not $Domain) { $Domain = Read-DiagIdentityList -Prompt 'Domain(s) to check (e.g. contoso.com)' }
if (-not $PSBoundParameters.ContainsKey('DnsServer')) { $DnsServer = Read-DiagValue -Prompt 'DNS server to query (e.g. 8.8.8.8)' -Optional }

$params = @{ Domain = ($Domain -join ', '); DnsServer = $DnsServer }
Start-DiagRun -Name 'Test-DomainDnsRecords' -Title 'Microsoft 365 DNS Record Check' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $params
foreach ($d in $Domain) { Register-DiagSensitiveValue -Value $d -Category domain }

function Resolve-Rec {
    param([string]$Name, [string]$Type)
    $p = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop'; QuickTimeout = $true }
    if ($DnsServer) { $p['Server'] = $DnsServer }
    try { return @(Resolve-DnsName @p | Where-Object { $_.Section -eq 'Answer' }) }
    catch { return @() }
}

function Get-TxtRecords {
    param([string]$Name)
    return @(Resolve-Rec -Name $Name -Type TXT | Where-Object { $_.Type -eq 'TXT' } | ForEach-Object { ($_.Strings -join '') })
}

function Get-Cname {
    param([string]$Name)
    $r = Resolve-Rec -Name $Name -Type CNAME | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
    if ($r) { return $r.NameHost }
    return $null
}

function Get-SpfLookupCount {
    # Counts DNS-querying mechanisms recursively (RFC 7208 limit = 10).
    param([string]$Name, [int]$Depth = 0, [System.Collections.Generic.HashSet[string]]$Seen)
    if (-not $Seen) { $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
    if ($Depth -gt 10 -or -not $Seen.Add($Name)) { return 0 }
    $spf = Get-TxtRecords -Name $Name | Where-Object { $_ -match '^v=spf1' } | Select-Object -First 1
    if (-not $spf) { return 0 }
    $count = 0
    foreach ($term in ($spf -split '\s+')) {
        $t = $term.TrimStart('+', '-', '~', '?')
        if ($t -match '^include:(.+)$') { [void]$script:SpfIncludes.Add($Matches[1]); $count += 1 + (Get-SpfLookupCount -Name $Matches[1] -Depth ($Depth + 1) -Seen $Seen) }
        elseif ($t -match '^redirect=(.+)$') { $count += 1 + (Get-SpfLookupCount -Name $Matches[1] -Depth ($Depth + 1) -Seen $Seen) }
        elseif ($t -match '^(a|mx|ptr|exists)(:|/|$)') { $count += 1 }
    }
    return $count
}

try {
    $summary = New-Object System.Collections.Generic.List[object]
    foreach ($dom in $Domain) {
        $dom = $dom.Trim().TrimEnd('.').ToLowerInvariant()
        Write-DiagInfo "Domain: $dom" -Level Header
        $records = New-Object System.Collections.Generic.List[object]
        $add = { param($Type, $Name, $Value, $Status, $Note) $records.Add([pscustomobject]@{ Type = $Type; Name = $Name; Value = $Value; Status = $Status; Note = $Note }) }

        # MX
        Invoke-DiagStep -Name 'MX' -Area $dom -ScriptBlock {
            $mx = @(Resolve-Rec -Name $dom -Type MX | Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference)
            if ($mx.Count -eq 0) {
                & $add 'MX' $dom '' 'Missing' 'No MX record - inbound mail cannot be delivered.'
                Add-DiagFinding -Severity Critical -Area $dom -Title "$dom has no MX record" -Recommendation 'Add the MX value shown in Admin center > Settings > Domains.'
            }
            foreach ($m in $mx) {
                $isExo = $m.NameExchange -match '\.mail\.protection\.outlook\.com$|\.mx\.microsoft$'
                & $add 'MX' $dom "$($m.Preference) $($m.NameExchange)" ($(if ($isExo) { 'Microsoft 365' } else { 'Third-party' })) ''
            }
            if ($mx.Count -gt 0 -and -not ($mx | Where-Object { $_.NameExchange -match '\.mail\.protection\.outlook\.com$|\.mx\.microsoft$' })) {
                Add-DiagFinding -Severity Info -Area $dom -Title "$dom MX points to a third-party service ($($mx[0].NameExchange))" -Detail 'Mail arrives through a gateway/filter before Exchange Online.' -Recommendation 'Ensure the inbound connector and Enhanced Filtering for Connectors are configured, otherwise SPF/DMARC checks see the gateway IP.'
            }
        } | Out-Null

        # SPF
        Invoke-DiagStep -Name 'SPF' -Area $dom -ScriptBlock {
            $spf = @(Get-TxtRecords -Name $dom | Where-Object { $_ -match '^v=spf1' })
            if ($spf.Count -eq 0) {
                & $add 'SPF' $dom '' 'Missing' ''
                Add-DiagFinding -Severity Warning -Area $dom -Title "$dom has no SPF record" -Recommendation 'Publish: v=spf1 include:spf.protection.outlook.com -all (plus any other senders).'
                return
            }
            if ($spf.Count -gt 1) { Add-DiagFinding -Severity Critical -Area $dom -Title "$dom has $($spf.Count) SPF records (PermError)" -Recommendation 'Merge into a single v=spf1 TXT record - multiple records make SPF fail everywhere.' }
            $rec = $spf[0]
            $script:SpfIncludes = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $lookups = Get-SpfLookupCount -Name $dom
            $all = if ($rec -match '([\+\-~\?])all\b') { $Matches[1] + 'all' } elseif ($rec -match '\ball\b') { '+all' } else { '(none)' }
            & $add 'SPF' $dom $rec "Lookups: $lookups" "Policy: $all"
            if (-not $script:SpfIncludes.Contains('spf.protection.outlook.com')) { Add-DiagFinding -Severity Warning -Area $dom -Title "$dom SPF does not include spf.protection.outlook.com (directly or nested)" -Recommendation 'Mail sent from Exchange Online will fail SPF unless it relays through another listed host.' }
            if ($lookups -gt 10) { Add-DiagFinding -Severity Critical -Area $dom -Title "$dom SPF needs $lookups DNS lookups (limit 10) - PermError" -Recommendation 'Flatten or remove includes. Receivers treat this as SPF failure.' }
            elseif ($lookups -ge 9) { Add-DiagFinding -Severity Warning -Area $dom -Title "$dom SPF uses $lookups of 10 DNS lookups" }
            if ($all -eq '+all') { Add-DiagFinding -Severity Critical -Area $dom -Title "$dom SPF ends with +all (anyone may send as this domain)" -Recommendation 'Use -all or ~all.' }
            elseif ($all -eq '?all' -or $all -eq '(none)') { Add-DiagFinding -Severity Warning -Area $dom -Title "$dom SPF has a neutral policy ($all)" -Recommendation 'Use -all (or ~all while testing).' }
        } | Out-Null

        # DMARC
        Invoke-DiagStep -Name 'DMARC' -Area $dom -ScriptBlock {
            $dmarc = @(Get-TxtRecords -Name "_dmarc.$dom" | Where-Object { $_ -match '^v=DMARC1' })
            if ($dmarc.Count -eq 0) {
                & $add 'DMARC' "_dmarc.$dom" '' 'Missing' ''
                Add-DiagFinding -Severity Warning -Area $dom -Title "$dom has no DMARC record" -Recommendation 'Publish v=DMARC1; p=none; rua=mailto:... then move to quarantine/reject. Large mailbox providers require DMARC for bulk senders.'
                return
            }
            $rec = $dmarc[0]
            $policy = if ($rec -match '\bp=(\w+)') { $Matches[1] } else { '?' }
            & $add 'DMARC' "_dmarc.$dom" $rec "p=$policy" ''
            if ($policy -eq 'none') { Add-DiagFinding -Severity Info -Area $dom -Title "$dom DMARC policy is p=none (monitor only)" -Recommendation 'Spoofed mail is not blocked. Move to p=quarantine/reject once reports are clean.' }
            if ($rec -notmatch 'rua=') { Add-DiagFinding -Severity Info -Area $dom -Title "$dom DMARC has no rua= reporting address" }
        } | Out-Null

        # DKIM
        Invoke-DiagStep -Name 'DKIM (Microsoft 365 selectors)' -Area $dom -ScriptBlock {
            $found = 0
            foreach ($sel in 'selector1', 'selector2') {
                $target = Get-Cname -Name "$sel._domainkey.$dom"
                if ($target) { $found++ }
                $ok = $target -match 'onmicrosoft\.com$|dkim\.mail\.microsoft$'
                & $add 'DKIM' "$sel._domainkey.$dom" $target ($(if ($target) { if ($ok) { 'Microsoft 365' } else { 'Other target' } } else { 'Missing' })) ''
            }
            if ($found -eq 0) { Add-DiagFinding -Severity Warning -Area $dom -Title "$dom has no Microsoft 365 DKIM CNAMEs (selector1/selector2)" -Recommendation 'Create the CNAMEs from Defender portal > Email authentication > DKIM, then enable signing. (Ignore if DKIM is signed by a gateway.)' }
            elseif ($found -eq 1) { Add-DiagFinding -Severity Warning -Area $dom -Title "$dom has only one DKIM selector CNAME" -Recommendation 'Both selector1 and selector2 are needed for key rotation.' }
        } | Out-Null

        # Autodiscover & client records
        Invoke-DiagStep -Name 'Autodiscover, Teams/SfB, Intune' -Area $dom -ScriptBlock {
            $checks = @(
                @{ Name = "autodiscover.$dom"; Expect = 'autodiscover\.outlook\.com'; Label = 'Autodiscover'; Sev = 'Warning'; Why = 'Outlook profile creation and some mobile setup rely on it.' }
                @{ Name = "enterpriseregistration.$dom"; Expect = 'enterpriseregistration\.windows\.net'; Label = 'Entra device registration'; Sev = 'Info'; Why = 'Used for device registration with the custom domain UPN.' }
                @{ Name = "enterpriseenrollment.$dom"; Expect = 'manage(-beta)?\.microsoft\.com'; Label = 'Intune enrollment'; Sev = 'Info'; Why = 'Simplifies Intune enrollment (users do not need to type the server).' }
                @{ Name = "lyncdiscover.$dom"; Expect = 'webdir\.online\.lync\.com'; Label = 'Lyncdiscover (legacy)'; Sev = 'Info'; Why = 'Only needed for some Skype for Business/legacy device scenarios.' }
                @{ Name = "sip.$dom"; Expect = 'sipdir\.online\.lync\.com'; Label = 'SIP (legacy)'; Sev = 'Info'; Why = 'Only needed for some legacy federation/device scenarios.' }
            )
            foreach ($c in $checks) {
                $target = Get-Cname -Name $c.Name
                $status = if (-not $target) { 'Missing' } elseif ($target -match $c.Expect) { 'OK' } else { 'Unexpected target' }
                & $add 'CNAME' $c.Name $target $status $c.Label
                if ($status -eq 'Missing' -and $c.Label -eq 'Autodiscover') {
                    Add-DiagFinding -Severity Warning -Area $dom -Title "$dom has no autodiscover CNAME" -Detail $c.Why -Recommendation 'Create CNAME autodiscover -> autodiscover.outlook.com.'
                }
                elseif ($status -eq 'Unexpected target') {
                    Add-DiagFinding -Severity $c.Sev -Area $dom -Title "$($c.Name) points to $target (expected *$($c.Expect -replace '\\',''))" -Detail $c.Why
                }
            }
            foreach ($srv in @(@{ N = "_sip._tls.$dom"; E = 'sipdir\.online\.lync\.com' }, @{ N = "_sipfederationtls._tcp.$dom"; E = 'sipfed\.online\.lync\.com' })) {
                $r = Resolve-Rec -Name $srv.N -Type SRV | Where-Object { $_.Type -eq 'SRV' } | Select-Object -First 1
                $val = if ($r) { "$($r.NameTarget):$($r.Port)" } else { '' }
                & $add 'SRV' $srv.N $val ($(if (-not $r) { 'Missing' } elseif ($r.NameTarget -match $srv.E) { 'OK' } else { 'Unexpected target' })) 'Teams/SfB legacy'
            }
        } | Out-Null

        # MTA-STS / TLS-RPT
        Invoke-DiagStep -Name 'MTA-STS and TLS-RPT' -Area $dom -ScriptBlock {
            $sts = Get-TxtRecords -Name "_mta-sts.$dom" | Where-Object { $_ -match '^v=STSv1' } | Select-Object -First 1
            $rpt = Get-TxtRecords -Name "_smtp._tls.$dom" | Where-Object { $_ -match '^v=TLSRPTv1' } | Select-Object -First 1
            & $add 'TXT' "_mta-sts.$dom" $sts ($(if ($sts) { 'Present' } else { 'Not configured' })) 'Optional: inbound TLS enforcement'
            & $add 'TXT' "_smtp._tls.$dom" $rpt ($(if ($rpt) { 'Present' } else { 'Not configured' })) 'Optional: TLS failure reports'
        } | Out-Null

        Add-DiagData -Section "DNS - $dom" -Data $records.ToArray()
        $summary.Add([pscustomobject]@{
                Domain = $dom
                MX     = (@($records | Where-Object Type -eq 'MX' | ForEach-Object Status) -join ', ')
                SPF    = (@($records | Where-Object Type -eq 'SPF' | ForEach-Object { "$($_.Status) $($_.Note)" }) -join ', ')
                DMARC  = (@($records | Where-Object Type -eq 'DMARC' | ForEach-Object Status) -join ', ')
                DKIM   = (@($records | Where-Object Type -eq 'DKIM' | ForEach-Object Status) -join ', ')
                Autodiscover = (@($records | Where-Object { $_.Name -like 'autodiscover.*' } | ForEach-Object Status) -join ', ')
            })
    }
    Add-DiagData -Section 'Summary' -Data $summary.ToArray()
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
