<#
.SYNOPSIS
    Offline message header analyzer: hop-by-hop delays, SPF/DKIM/DMARC/CompAuth results, spam verdict decoding (SCL, SFV, CAT, BCL), and a plain-language "why did this go to Junk / get delayed" summary. No sign-in needed.

.DESCRIPTION
    Input options (file picker opens by default):
      - .eml file (drag the message out of Outlook/OWA "Download" or "Save as")
      - .txt file containing the copied headers (Outlook: File > Properties > Internet headers)
      - .msg file (best effort: reads the transport headers block directly from the file)
      - Paste mode: run with -Paste and paste headers, then type END on its own line.

.PARAMETER Path
    Path to a .eml/.txt/.msg file. A file picker opens if omitted.

.PARAMETER Paste
    Paste headers into the console instead of picking a file.

.EXAMPLE
    .\Get-MessageHeaderAnalysis.ps1 -Path .\suspicious.eml

.NOTES
    Connection : None (offline)
    Roles      : None
    Read-only  : Reads the selected file only; nothing is opened in Outlook.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Paste,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

$raw = $null
if (-not $Path -and -not $Paste) {
    $choice = Read-DiagChoice -Prompt 'How do you want to provide the headers?' -Options @(
        [pscustomobject]@{ Label = 'Pick a file (.eml / .txt / .msg)'; Value = 'file' },
        [pscustomobject]@{ Label = 'Paste headers into this window'; Value = 'paste' })
    if ($choice -eq 'paste') { $Paste = $true }
}
if ($Paste) {
    Write-Host '  Paste the headers now. Type END on its own line when finished:' -ForegroundColor Cyan
    $lines = New-Object System.Collections.Generic.List[string]
    while ($true) { $l = Read-Host; if ($l -eq 'END') { break }; $lines.Add($l) }
    $raw = $lines -join "`r`n"
    $source = 'pasted'
}
else {
    if (-not $Path) { $Path = Select-DiagFile -Title 'Select a message (.eml/.msg) or header text file' -Filter 'Messages and headers (*.eml;*.msg;*.txt)|*.eml;*.msg;*.txt|All files (*.*)|*.*' }
    if (-not $Path) { throw 'No file selected.' }
    $source = Split-Path $Path -Leaf
    if ($Path -match '\.msg$') {
        # Best effort: the PR_TRANSPORT_MESSAGE_HEADERS stream is stored as UTF-16 text inside the compound file.
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::Unicode.GetString($bytes)
        $idx = $text.IndexOf('Received: ')
        if ($idx -lt 0) { throw 'Could not find transport headers in the .msg file. Save the message as .eml or copy the headers to a .txt file instead.' }
        $isText = { param($ch) ($ch -ge ' ' -and [int]$ch -lt 0xD800) -or $ch -eq "`r" -or $ch -eq "`n" -or $ch -eq "`t" }
        $s = $idx; while ($s -gt 0 -and (& $isText $text[$s - 1])) { $s-- }
        $e = $idx; while ($e -lt $text.Length -and (& $isText $text[$e])) { $e++ }
        $raw = $text.Substring($s, $e - $s)
    }
    else { $raw = [System.IO.File]::ReadAllText($Path) }
}

Start-DiagRun -Name 'Get-MessageHeaderAnalysis' -Title 'Message Header Analysis' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Source = $source })
try {
    # --- Parse (unfold) headers up to the first blank line
    $headerText = ($raw -split "`r?`n`r?`n", 2)[0]
    $headers = New-Object System.Collections.Generic.List[object]
    foreach ($line in ($headerText -split "`r?`n")) {
        if ($line -match '^[ \t]' -and $headers.Count -gt 0) { $headers[$headers.Count - 1].Value += ' ' + $line.Trim() }
        elseif ($line -match '^([!-9;-~]+):\s?(.*)$') { $headers.Add([pscustomobject]@{ Name = $Matches[1]; Value = $Matches[2] }) }
    }
    if ($headers.Count -eq 0) { throw 'No headers found in the input.' }
    $get = { param($n) @($headers | Where-Object { $_.Name -eq $n } | ForEach-Object Value) }
    $first = { param($n) (& $get $n | Select-Object -First 1) }

    # --- Summary
    $summary = [ordered]@{
        From = & $first 'From'; ReturnPath = & $first 'Return-Path'; ReplyTo = & $first 'Reply-To'; To = & $first 'To'; Subject = & $first 'Subject'
        Date = & $first 'Date'; MessageId = & $first 'Message-ID'; Directionality = & $first 'X-MS-Exchange-Organization-MessageDirectionality'
        AuthAs = & $first 'X-MS-Exchange-Organization-AuthAs'; OriginatingIP = & $first 'X-Originating-IP'; CrossTenantId = & $first 'X-MS-Exchange-CrossTenant-Id'
        HeaderCount = $headers.Count
    }
    Add-DiagData -Section 'Summary' -Data $summary

    # --- Received hops (bottom = first)
    $received = @(& $get 'Received')
    [array]::Reverse($received)
    $hops = New-Object System.Collections.Generic.List[object]
    $prev = $null; $i = 0
    foreach ($r in $received) {
        $i++
        $date = $null
        if ($r -match ';\s*([^;]+)$') {
            $ds = ($Matches[1] -replace '\s*\([A-Z]{2,5}\)\s*$', '').Trim()
            $dto = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse($ds, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$dto)) { $date = $dto.UtcDateTime }
        }
        $from = if ($r -match '\bfrom\s+(\S+)(\s+\(([^)]*)\))?') { $Matches[1] + $(if ($Matches[3]) { " ($($Matches[3]))" } else { '' }) } else { '' }
        $by = if ($r -match '\bby\s+(\S+)') { $Matches[1] } else { '' }
        $with = if ($r -match '\bwith\s+(.+?)(\s+id\s|\s*;|\s+via\s|$)') { $Matches[1] } else { '' }
        $delay = if ($date -and $prev) { [math]::Round(($date - $prev).TotalSeconds) } else { $null }
        $hops.Add([pscustomobject]@{ Hop = $i; TimeUtc = $date; DelaySeconds = $delay; From = $from; By = $by; With = $with })
        if ($date) { $prev = $date }
    }
    Add-DiagData -Section 'Received hops' -Data $hops.ToArray() -Description 'Hop 1 is where the message started. DelaySeconds = time since the previous hop (negative values usually mean clock skew on a server).'
    $total = $null
    $dated = @($hops | Where-Object TimeUtc)
    if ($dated.Count -ge 2) { $total = [math]::Round(($dated[-1].TimeUtc - $dated[0].TimeUtc).TotalMinutes, 1) }
    foreach ($h in @($hops | Where-Object { $_.DelaySeconds -gt 300 })) {
        $sev = if ($h.DelaySeconds -gt 3600) { 'Warning' } else { 'Info' }
        Add-DiagFinding -Severity $sev -Area 'Delivery' -Title "Delay of $([math]::Round($h.DelaySeconds / 60, 1)) min at hop $($h.Hop) ($($h.From) -> $($h.By))" -Recommendation 'The server at the start of this hop held the message (queue, throttling, greylisting, or a gateway scan). If it is a Microsoft server, check Service health / message trace detail.'
    }
    if ($null -ne $total) { Add-DiagFinding -Severity Info -Area 'Delivery' -Title "Total transit time: $total minutes over $($hops.Count) hops" -Quiet }

    # --- Authentication
    $authRows = New-Object System.Collections.Generic.List[object]
    foreach ($ar in @(& $get 'Authentication-Results') + @(& $get 'ARC-Authentication-Results')) {
        $spf = if ($ar -match '\bspf=(\w+)(\s*\(([^)]*)\))?') { $Matches[1] } else { '' }
        $spfDetail = $Matches[3]
        $dkim = if ($ar -match '\bdkim=(\w+)') { $Matches[1] } else { '' }
        $dmarc = if ($ar -match '\bdmarc=(\w+)') { $Matches[1] } else { '' }
        $action = if ($ar -match '\baction=(\w+)') { $Matches[1] } else { '' }
        $compauth = if ($ar -match '\bcompauth=(\w+)') { $Matches[1] } else { '' }
        $reason = if ($ar -match '\breason=(\d+)') { $Matches[1] } else { '' }
        $hfrom = if ($ar -match 'header\.from=([^;\s]+)') { $Matches[1] } else { '' }
        $authRows.Add([pscustomobject]@{ SPF = $spf; DKIM = $dkim; DMARC = $dmarc; DmarcAction = $action; CompAuth = $compauth; Reason = $reason; HeaderFrom = $hfrom; Raw = $ar })
    }
    Add-DiagData -Section 'Authentication results' -Data $authRows.ToArray()
    $a = $authRows | Select-Object -First 1
    if ($a) {
        if ($a.SPF -in 'fail', 'softfail', 'permerror', 'temperror') { Add-DiagFinding -Severity Warning -Area 'Authentication' -Title "SPF = $($a.SPF)" -Recommendation 'The sending IP is not authorized by the sender domain''s SPF (or the record is broken). If mail passes through a gateway/forwarder, configure Enhanced Filtering for Connectors.' }
        if ($a.DKIM -in 'fail', 'permerror') { Add-DiagFinding -Severity Warning -Area 'Authentication' -Title "DKIM = $($a.DKIM)" -Detail 'Signature invalid - the message was modified in transit (disclaimer, gateway rewriting) or the key is wrong.' }
        elseif ($a.DKIM -eq 'none') { Add-DiagFinding -Severity Info -Area 'Authentication' -Title 'Message is not DKIM signed' }
        if ($a.DMARC -eq 'fail') { Add-DiagFinding -Severity Critical -Area 'Authentication' -Title "DMARC = fail (action=$($a.DmarcAction))" -Recommendation 'Neither SPF nor DKIM aligned with the From domain. Sender must fix SPF/DKIM; if it is legitimate forwarded mail, consider ARC trusted sealers.' }
        $caText = switch -Regex ($a.Reason) {
            '^000' { 'Explicit authentication failure - sender DMARC policy reject/quarantine' }
            '^001' { 'Implicit authentication failure - no/weak sender authentication (composite auth)' }
            '^002' { 'Organization has a policy prohibiting this sender/domain pair (spoof block)' }
            '^010' { 'DMARC reject/quarantine policy failed, sender is in an accepted domain' }
            '^(1|7)\d\d' { 'Pass - authenticated (explicit or implicit)' }
            '^2\d\d' { 'Soft pass - partial authentication' }
            '^3\d\d' { 'Not checked (e.g. internal mail)' }
            '^4\d\d' { 'Authentication bypassed (allow list / transport rule)' }
            '^6\d\d' { 'Implicit failure for sender domain' }
            '^905' { 'Complex routing - authentication cannot be determined (configure Enhanced Filtering)' }
            default { '' }
        }
        if ($a.CompAuth) { Add-DiagFinding -Severity $(if ($a.CompAuth -eq 'fail') { 'Warning' } else { 'Info' }) -Area 'Authentication' -Title "Composite authentication = $($a.CompAuth) (reason $($a.Reason))" -Detail $caText }
    }
    else { Add-DiagFinding -Severity Info -Area 'Authentication' -Title 'No Authentication-Results header (internal message, or headers from a non-Microsoft hop)' }

    # --- Microsoft anti-spam headers
    $fs = & $first 'X-Forefront-Antispam-Report'
    $ms = & $first 'X-Microsoft-Antispam'
    $scl = & $first 'X-MS-Exchange-Organization-SCL'
    $fsMap = [ordered]@{}
    if ($fs) { foreach ($kv in ($fs -split ';')) { if ($kv -match '^\s*([A-Z]+):(.*)$') { $fsMap[$Matches[1]] = $Matches[2].Trim() } } }
    $bcl = if ($ms -match 'BCL:(\d+)') { [int]$Matches[1] } else { $null }
    if (-not $scl -and $fsMap['SCL']) { $scl = $fsMap['SCL'] }

    $sfv = @{ SPM = 'Marked as spam by spam filtering'; SKS = 'Marked as spam before filtering (e.g. transport rule)'; SKA = 'Skipped filtering - sender is in an allow list (policy)'; SKB = 'Marked as spam - sender/domain in a block list'; SKN = 'Marked non-spam before filtering (transport rule SCL -1)'; SKI = 'Skipped - intra-organization (SFV:SKI)'; SKQ = 'Released from quarantine'; SKV = 'Marked non-spam - Tenant Allow/Block list allow'; NSPM = 'Not spam'; BLK = 'Blocked - sender in user''s Blocked Senders list'; SFE = 'Allowed - sender in user''s Safe Senders list' }
    $cat = @{ BULK = 'Bulk mail'; DIMP = 'Domain impersonation'; GIMP = 'Mailbox intelligence impersonation'; HPHSH = 'High-confidence phishing'; HPHISH = 'High-confidence phishing'; HSPM = 'High-confidence spam'; MALW = 'Malware'; PHSH = 'Phishing'; SPM = 'Spam'; SPOOF = 'Spoofing'; UIMP = 'User impersonation'; AMP = 'Anti-malware'; SAP = 'Safe Attachments'; FTBP = 'Filetype block policy'; INTOS = 'Intra-org phishing'; OSPM = 'Outbound spam' }
    $decoded = [ordered]@{
        SCL = $scl; SCLMeaning = switch ([string]$scl) { '-1' { 'Bypassed spam filtering (trusted/allow rule)' } { $_ -in '0', '1' } { 'Not spam' } { $_ -in '5', '6' } { 'Spam - delivered to Junk / per policy' } { $_ -in '7', '8', '9' } { 'High-confidence spam' } default { '' } }
        SFV = $fsMap['SFV']; SFVMeaning = $sfv[[string]$fsMap['SFV']]
        CAT = $fsMap['CAT']; CATMeaning = $cat[[string]$fsMap['CAT']]
        BCL = $bcl; BCLMeaning = if ($null -ne $bcl) { if ($bcl -ge 7) { 'Bulk sender with many complaints' } elseif ($bcl -ge 4) { 'Bulk sender with some complaints' } else { 'Not bulk / few complaints' } } else { '' }
        IPV = $fsMap['IPV']; IPVMeaning = switch ($fsMap['IPV']) { 'CAL' { 'IP in connection filter allow list' } 'NLI' { 'IP not on any reputation list' } default { '' } }
        ConnectingIP = $fsMap['CIP']; Country = $fsMap['CTRY']; Language = $fsMap['LANG']; HELO = $fsMap['H']; PTR = $fsMap['PTR']; Direction = $fsMap['DIR']; SFTY = $fsMap['SFTY']; SRV = $fsMap['SRV']; SFP = $fsMap['SFP']
    }
    Add-DiagData -Section 'Spam verdict (decoded)' -Data $decoded
    if ($fsMap.Count -gt 0) { Add-DiagData -Section 'X-Forefront-Antispam-Report (raw fields)' -Data $fsMap }

    if ($decoded.SFV -in 'SPM', 'SKS', 'SKB', 'BLK' -or ($scl -as [int]) -ge 5) {
        $why = @($decoded.SFVMeaning, $decoded.CATMeaning) | Where-Object { $_ }
        Add-DiagFinding -Severity Warning -Area 'Verdict' -Title "Message classified as spam/junk (SCL $scl, SFV $($decoded.SFV), CAT $($decoded.CAT))" -Detail ($why -join '; ') -Recommendation 'If legitimate: fix sender authentication (above), submit as "not junk" in Defender Submissions, or add a time-limited Tenant Allow/Block entry. Avoid SCL -1 transport rules on sender domain.'
    }
    elseif ($decoded.SFV -eq 'BLK') { Add-DiagFinding -Severity Info -Area 'Verdict' -Title 'Sender is in the recipient''s Blocked Senders list' }
    if ($decoded.SFV -in 'SKA', 'SKN', 'SKV' -or [string]$scl -eq '-1') { Add-DiagFinding -Severity Info -Area 'Verdict' -Title "Spam filtering was bypassed ($($decoded.SFVMeaning))" -Detail 'If this was phishing, review the allow entry/transport rule that let it through.' }
    if ($decoded.SRV -eq 'BULK' -or $bcl -ge 7) { Add-DiagFinding -Severity Info -Area 'Verdict' -Title "Bulk mail (BCL $bcl)" -Detail 'Junked when BCL >= the policy BulkThreshold (default 7).' }
    if ($decoded.CAT -in 'PHSH', 'HPHSH', 'HPHISH', 'SPOOF', 'DIMP', 'UIMP', 'GIMP', 'MALW') { Add-DiagFinding -Severity Critical -Area 'Verdict' -Title "Threat category: $($decoded.CATMeaning)" -Recommendation 'Do not release unless verified. Investigate in Defender Explorer.' }
    if ($decoded.IPV -eq 'CAL') { Add-DiagFinding -Severity Info -Area 'Verdict' -Title 'Connecting IP is in the connection filter allow list' }

    # --- Sender sanity
    $fromAddr = @(Get-DiagEmailAddress -Value $summary.From) | Select-Object -First 1
    $rpAddr = @(Get-DiagEmailAddress -Value $summary.ReturnPath) | Select-Object -First 1
    $rtAddr = @(Get-DiagEmailAddress -Value $summary.ReplyTo) | Select-Object -First 1
    if ($fromAddr -and $rpAddr -and ($fromAddr.Split('@')[1] -ne $rpAddr.Split('@')[1])) { Add-DiagFinding -Severity Info -Area 'Sender' -Title 'From domain differs from Return-Path (envelope) domain' -Detail 'Normal for marketing/SaaS senders; SPF then validates the envelope domain, so DMARC needs DKIM alignment.' }
    if ($fromAddr -and $rtAddr -and ($fromAddr.Split('@')[1] -ne $rtAddr.Split('@')[1])) { Add-DiagFinding -Severity Warning -Area 'Sender' -Title 'Reply-To domain differs from From domain' -Detail 'Common in business email compromise (replies go to the attacker). Verify the sender.' }

    $allHeaders = $headers.ToArray()
    if (-not $NoSanitize) {
        $allHeaders = @($allHeaders | ForEach-Object { if ($_.Name -match '^(Subject|Thread-Topic|Thread-Index)$') { [pscustomobject]@{ Name = $_.Name; Value = '[redacted]' } } else { $_ } })
    }
    Add-DiagData -Section 'All headers' -Data $allHeaders
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
