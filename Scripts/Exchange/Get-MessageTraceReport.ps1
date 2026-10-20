<#
.SYNOPSIS
    Message trace ("where is my email?"): finds messages by sender/recipient/subject/Message-ID, decodes NDR codes, pulls trace detail events for failed/quarantined/pending mail and quarantine info.

.DESCRIPTION
    Uses Get-MessageTraceV2 (falls back to Get-MessageTrace on older tenants). Ranges longer than
    10 days are split automatically (V2 supports up to 90 days of history).

.PARAMETER SenderAddress
    Sender to trace. At least one of Sender/Recipient/MessageId is recommended.

.PARAMETER RecipientAddress
    Recipient to trace.

.PARAMETER MessageId
    Internet Message-ID (from the message headers).

.PARAMETER Subject
    Subject contains filter (V2 only).

.PARAMETER Days
    Days back (default 2, max 90).

.PARAMETER DetailCount
    How many non-delivered messages to fetch event detail for (default 25).

.EXAMPLE
    .\Get-MessageTraceReport.ps1 -SenderAddress partner@fabrikam.com -RecipientAddress jane@contoso.com -Days 5

.NOTES
    Connection : Exchange Online
    Roles      : Global Reader, Security Reader or View-Only Organization Management
    Read-only  : Exchange session restricted to Get- cmdlets.
#>
[CmdletBinding()]
param(
    [string]$SenderAddress,
    [string]$RecipientAddress,
    [string]$MessageId,
    [string]$Subject,
    [ValidateRange(1, 90)][int]$Days = 2,
    [int]$MaxResults = 5000,
    [int]$DetailCount = 25,
    [string]$UserPrincipalName,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not ($SenderAddress -or $RecipientAddress -or $MessageId -or $Subject)) {
    Write-DiagInfo 'Enter what you know about the message (Enter to skip a field):'
    $SenderAddress = Read-DiagValue -Prompt 'Sender address' -Optional
    $RecipientAddress = Read-DiagValue -Prompt 'Recipient address' -Optional
    $MessageId = Read-DiagValue -Prompt 'Message-ID' -Optional
    $Subject = Read-DiagValue -Prompt 'Subject contains' -Optional
    if (-not $PSBoundParameters.ContainsKey('Days')) { $Days = [int](Read-DiagValue -Prompt 'Days back (max 90)' -Default '2' -Pattern '^\d{1,2}$') }
    if (-not ($SenderAddress -or $RecipientAddress -or $MessageId -or $Subject)) {
        if (-not (Read-DiagYesNo -Prompt 'No filter given - trace ALL tenant mail for the period (can be large)?' -Default $false)) { return }
    }
}

Start-DiagRun -Name 'Get-MessageTraceReport' -Title 'Exchange Online - Message Trace' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Sender = $SenderAddress; Recipient = $RecipientAddress; MessageId = $MessageId; Subject = $Subject; Days = $Days })
try {
    Connect-DiagExchange -CommandName 'Get-MessageTraceV2', 'Get-MessageTraceDetailV2', 'Get-MessageTrace', 'Get-MessageTraceDetail', 'Get-QuarantineMessage' -UserPrincipalName $UserPrincipalName
    $useV2 = [bool](Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue)
    if (-not $useV2 -and $Days -gt 10) { Write-DiagInfo 'Get-MessageTraceV2 not available - limiting to 10 days' -Level Warn; $Days = 10 }

    $end = (Get-Date).ToUniversalTime()
    $start = $end.AddDays(-$Days)
    $msgs = New-Object System.Collections.Generic.List[object]

    Invoke-DiagStep -Name "Tracing $($start.ToString('yyyy-MM-dd HH:mm')) .. $($end.ToString('yyyy-MM-dd HH:mm')) UTC ($(if ($useV2) {'V2'} else {'legacy'}))" -Area 'Trace' -ScriptBlock {
        $winStart = $start
        while ($winStart -lt $end -and $msgs.Count -lt $MaxResults) {
            $winEnd = $winStart.AddDays(10); if ($winEnd -gt $end) { $winEnd = $end }
            $p = @{ StartDate = $winStart; EndDate = $winEnd; ErrorAction = 'Stop' }
            if ($SenderAddress) { $p['SenderAddress'] = $SenderAddress }
            if ($RecipientAddress) { $p['RecipientAddress'] = $RecipientAddress }
            if ($MessageId) { $p['MessageId'] = $MessageId }
            if ($useV2) {
                if ($Subject) { $p['Subject'] = $Subject; $p['SubjectFilterType'] = 'Contains' }
                $p['ResultSize'] = 5000
                $pg = 0
                while ($true) {
                    $pg++
                    $batch = @(Get-MessageTraceV2 @p)
                    foreach ($b in $batch) { $msgs.Add($b) }
                    if ($batch.Count -lt 5000 -or $msgs.Count -ge $MaxResults -or $pg -ge 20) { break }
                    $last = $batch[-1]
                    $p['EndDate'] = $last.Received
                    $p['StartingRecipientAddress'] = $last.RecipientAddress
                }
            }
            else {
                $page = 1
                while ($true) {
                    $batch = @(Get-MessageTrace @p -PageSize 5000 -Page $page)
                    foreach ($b in $batch) { if (-not $Subject -or [string]$b.Subject -like "*$Subject*") { $msgs.Add($b) } }
                    if ($batch.Count -lt 5000 -or $page -ge 10) { break }
                    $page++
                }
            }
            $winStart = $winEnd
        }
    } | Out-Null

    $rows = @($msgs | Sort-Object Received -Descending | Select-Object -First $MaxResults | ForEach-Object {
            [pscustomobject]@{
                ReceivedUtc = $_.Received; Sender = $_.SenderAddress; Recipient = $_.RecipientAddress; Subject = $_.Subject; Status = $_.Status
                Size = $_.Size; FromIP = $_.FromIP; ToIP = $_.ToIP; MessageId = $_.MessageId; MessageTraceId = $_.MessageTraceId
            }
        })
    Add-DiagData -Section 'Messages' -Data $rows -Description 'Most recent first. Status: Delivered, Failed, Pending, Quarantined, FilteredAsSpam, GettingStatus, Expanded (distribution group).'
    Add-DiagData -Section 'Status summary' -Data @($rows | Group-Object Status | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Status = $_.Name; Count = $_.Count } })

    if ($rows.Count -eq 0) {
        Add-DiagFinding -Severity Warning -Area 'Trace' -Title 'No messages found for these filters' -Recommendation 'The message never reached Exchange Online: check the sender''s side (their NDR), the MX record (Test-DomainDnsRecords.ps1), spelling of addresses, or extend the date range. Messages appear in trace within ~5-30 minutes.'
    }
    else {
        Add-DiagFinding -Severity Info -Area 'Trace' -Title "$($rows.Count) message(s) found" -Quiet
        $counts = $rows | Group-Object Status
        foreach ($g in $counts) {
            switch ($g.Name) {
                'Failed' { Add-DiagFinding -Severity Warning -Area 'Trace' -Title "$($g.Count) message(s) FAILED" -Recommendation 'See the Trace detail section for the NDR code and its meaning.' }
                'Quarantined' { Add-DiagFinding -Severity Warning -Area 'Trace' -Title "$($g.Count) message(s) QUARANTINED" -Recommendation 'Check the Quarantine section; release from the Defender portal if legitimate (release is a change - do it in the portal).' }
                'FilteredAsSpam' { Add-DiagFinding -Severity Info -Area 'Trace' -Title "$($g.Count) message(s) filtered as spam (Junk folder)" -Recommendation 'Run Get-MessageHeaderAnalysis.ps1 on one of them to see why (SCL/SFV/CAT).' }
                'Pending' { Add-DiagFinding -Severity Warning -Area 'Trace' -Title "$($g.Count) message(s) pending/deferred" -Recommendation 'Destination server not accepting yet (temporary 4xx). Check detail for the deferral reason.' }
                'Delivered' { Add-DiagFinding -Severity OK -Area 'Trace' -Title "$($g.Count) message(s) delivered to the mailbox" -Detail 'If the user cannot see it: check inbox rules, Focused/Other, Junk, retention policies and the mobile/Outlook client filters.' }
            }
        }

        # Detail for non-delivered messages
        $targets = @($rows | Where-Object { $_.Status -notin 'Delivered', 'Expanded' } | Select-Object -First $DetailCount)
        if ($targets.Count -eq 0 -and $rows.Count -le 5) { $targets = $rows }
        $details = New-Object System.Collections.Generic.List[object]
        if ($targets.Count -gt 0) {
            Invoke-DiagStep -Name "Trace detail for $($targets.Count) message(s)" -Area 'Detail' -ScriptBlock {
                foreach ($t in $targets) {
                    $ev = if ($useV2) { @(Get-MessageTraceDetailV2 -MessageTraceId $t.MessageTraceId -RecipientAddress $t.Recipient -ErrorAction Stop) }
                    else { @(Get-MessageTraceDetail -MessageTraceId $t.MessageTraceId -RecipientAddress $t.Recipient -StartDate $start -EndDate $end -ErrorAction Stop) }
                    foreach ($e in $ev) {
                        $meaning = Get-DiagNdrInfo -Text ([string]$e.Detail)
                        $details.Add([pscustomobject]@{ MessageTraceId = $t.MessageTraceId; Recipient = $t.Recipient; DateUtc = $e.Date; Event = $e.Event; Action = $e.Action; Detail = $e.Detail; Meaning = $meaning })
                        if ($meaning -and $e.Event -match 'Fail|Defer|Drop') {
                            Add-DiagFinding -Severity Warning -Area 'Detail' -Title "$($e.Event) to $($t.Recipient): $meaning" -Detail ([string]$e.Detail) -Quiet
                        }
                    }
                }
            } | Out-Null
            Add-DiagData -Section 'Trace detail events' -Data $details.ToArray()
            $byMeaning = @($details | Where-Object Meaning | Group-Object Meaning)
            foreach ($m in $byMeaning) { Write-DiagInfo "NDR: $($m.Name) (x$($m.Count))" -Level Warn }
        }

        # Quarantine lookups
        $q = @($rows | Where-Object Status -eq 'Quarantined' | Select-Object -First 25)
        if ($q.Count -gt 0) {
            Invoke-DiagStep -Name 'Quarantine details' -Area 'Quarantine' -ScriptBlock {
                $qrows = foreach ($m in $q) {
                    foreach ($qm in @(Get-QuarantineMessage -MessageId $m.MessageId -ErrorAction SilentlyContinue)) {
                        [pscustomobject]@{ Recipient = (@($qm.RecipientAddress) -join ', '); Sender = $qm.SenderAddress; Type = $qm.QuarantineTypes; Policy = $qm.PolicyName; PolicyType = $qm.PolicyType; Released = $qm.ReleaseStatus; Expires = $qm.Expires; Received = $qm.ReceivedTime; Direction = $qm.Direction }
                    }
                }
                Add-DiagData -Section 'Quarantine' -Data @($qrows)
                foreach ($g in @($qrows | Group-Object Type)) { Add-DiagFinding -Severity Info -Area 'Quarantine' -Title "$($g.Count) quarantined as $($g.Name)" -Detail ('Policies: ' + (@($g.Group.Policy | Select-Object -Unique) -join ', ')) }
            } | Out-Null
        }
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
