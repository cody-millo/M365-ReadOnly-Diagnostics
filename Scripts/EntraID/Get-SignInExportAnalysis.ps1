<#
.SYNOPSIS
    Offline analysis of a sign-in log export (CSV or JSON downloaded from the Entra admin center): failures by error code, user, app, IP and country, legacy auth, password-spray and MFA-fatigue patterns. No sign-in needed.

.DESCRIPTION
    Pick the exported file with the file picker. Works with the "Interactive" or "Non-interactive" CSV/JSON
    exports from Entra ID > Monitoring > Sign-in logs > Download. Column names are matched flexibly.

.PARAMETER Path
    The exported CSV/JSON file. A file picker opens if omitted.

.EXAMPLE
    .\Get-SignInExportAnalysis.ps1 -Path .\InteractiveSignIns_2026-10-20.csv

.NOTES
    Connection : None (offline file)
    Roles      : None
    Read-only  : Reads the selected file only.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Path) {
    Write-DiagInfo 'Select the sign-in log export (Entra admin center > Sign-in logs > Download > CSV or JSON)'
    $Path = Select-DiagFile -Title 'Select sign-in log export' -Filter 'Sign-in exports (*.csv;*.json)|*.csv;*.json|All files (*.*)|*.*' -InitialDirectory ([Environment]::GetFolderPath('UserProfile') + '\Downloads')
}
if (-not $Path) { throw 'No file selected.' }

Start-DiagRun -Name 'Get-SignInExportAnalysis' -Title 'Entra ID - Sign-in Export Analysis' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ File = (Split-Path $Path -Leaf) })
$legacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP', 'MAPI Over HTTP', 'Offline Address Book', 'Outlook Anywhere (RPC over HTTP)', 'Exchange Web Services', 'AutoDiscover', 'Exchange Online PowerShell', 'Other clients')
try {
    $records = Invoke-DiagStep -Name "Reading $(Split-Path $Path -Leaf)" -Area 'Input' -ScriptBlock {
        if ($Path -match '\.json$') {
            $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            if ($j.PSObject.Properties['value']) { $j = $j.value }
            foreach ($s in @($j)) {
                [pscustomobject]@{
                    Time = $s.createdDateTime; User = $s.userPrincipalName; App = $s.appDisplayName; Resource = $s.resourceDisplayName; ClientApp = $s.clientAppUsed
                    ErrorCode = [string]$s.status.errorCode; Failure = $s.status.failureReason; IP = $s.ipAddress; Country = $s.location.countryOrRegion; City = $s.location.city
                    CA = $s.conditionalAccessStatus; MfaResult = $s.status.additionalDetails; OS = $s.deviceDetail.operatingSystem; Browser = $s.deviceDetail.browser
                    Compliant = $s.deviceDetail.isCompliant; JoinType = $s.deviceDetail.trustType; CorrelationId = $s.correlationId
                }
            }
        }
        else {
            $rows = @(Import-Csv -LiteralPath $Path)
            if ($rows.Count -eq 0) { return @() }
            $h = @($rows[0].PSObject.Properties.Name)
            $col = { param([string[]]$cands) foreach ($c in $cands) { $m = $h | Where-Object { $_ -match "^$c$" } | Select-Object -First 1; if ($m) { return $m } }; return $null }
            $map = @{
                Time = & $col @('Date \(UTC\)', 'Date', 'CreatedDateTime', 'Time')
                User = & $col @('Username', 'User principal name', 'UserPrincipalName', 'User')
                App = & $col @('Application', 'App', 'AppDisplayName')
                Resource = & $col @('Resource', 'ResourceDisplayName')
                ClientApp = & $col @('Client app', 'ClientAppUsed')
                ErrorCode = & $col @('Sign-in error code', 'Error code', 'ErrorCode')
                Failure = & $col @('Failure reason', 'FailureReason')
                IP = & $col @('IP address', 'IPAddress')
                Location = & $col @('Location')
                CA = & $col @('Conditional Access', 'ConditionalAccessStatus')
                MfaResult = & $col @('Multifactor authentication result', 'MFA result')
                OS = & $col @('Operating System', 'OperatingSystem')
                Browser = & $col @('Browser')
                Compliant = & $col @('Compliant')
                JoinType = & $col @('Join Type', 'TrustType')
                CorrelationId = & $col @('Correlation ID', 'CorrelationId')
                Status = & $col @('Status')
            }
            foreach ($r in $rows) {
                $code = if ($map.ErrorCode) { [string]$r.($map.ErrorCode) } else { '' }
                if (-not $code -and $map.Status) { $code = if ($r.($map.Status) -match 'Success') { '0' } else { '?' } }
                $loc = if ($map.Location) { [string]$r.($map.Location) } else { '' }
                $g = { param($k) if ($map[$k]) { $r.($map[$k]) } else { $null } }
                [pscustomobject]@{
                    Time = (& $g 'Time'); User = (& $g 'User'); App = (& $g 'App'); Resource = (& $g 'Resource')
                    ClientApp = (& $g 'ClientApp'); ErrorCode = $code; Failure = (& $g 'Failure'); IP = (& $g 'IP')
                    Country = ($loc -split ',\s*')[-1]; City = ($loc -split ',\s*')[0]; CA = (& $g 'CA'); MfaResult = (& $g 'MfaResult')
                    OS = (& $g 'OS'); Browser = (& $g 'Browser'); Compliant = (& $g 'Compliant'); JoinType = (& $g 'JoinType')
                    CorrelationId = (& $g 'CorrelationId')
                }
            }
        }
    }
    $records = @($records)
    if ($records.Count -eq 0) { throw 'No sign-in records could be read from the file.' }
    Write-DiagInfo "$($records.Count) records" -Level Ok

    foreach ($r in $records) {
        $i = Get-DiagSignInErrorInfo -Code $(if ($r.ErrorCode) { $r.ErrorCode } else { '0' })
        $res = if ($r.ErrorCode -in '0', '') { 'Success' } elseif ($i.IsInterrupt) { 'Interrupted' } else { 'Failure' }
        $r | Add-Member -NotePropertyName Result -NotePropertyValue $res -Force
        $r | Add-Member -NotePropertyName Meaning -NotePropertyValue $(if ($res -ne 'Success') { $i.Description } else { '' }) -Force
    }
    $fail = @($records | Where-Object Result -eq 'Failure')
    $times = @($records | ForEach-Object { ConvertTo-DiagDate $_.Time } | Where-Object { $_ } | Sort-Object)
    Add-DiagData -Section 'Overview' -Data ([ordered]@{
            Records = $records.Count; Success = @($records | Where-Object Result -eq 'Success').Count; Failures = $fail.Count
            Interrupted = @($records | Where-Object Result -eq 'Interrupted').Count; Users = @($records.User | Select-Object -Unique).Count
            From = if ($times) { $times[0] } else { '' }; To = if ($times) { $times[-1] } else { '' }
        })

    Add-DiagData -Section 'Errors by code' -Data @($records | Where-Object { $_.Result -ne 'Success' } | Group-Object ErrorCode | Sort-Object Count -Descending | ForEach-Object {
            $i = Get-DiagSignInErrorInfo -Code $_.Name
            [pscustomobject]@{ ErrorCode = $_.Name; Count = $_.Count; Users = @($_.Group.User | Select-Object -Unique).Count; Meaning = $i.Description; Interrupt = $i.IsInterrupt; Hint = $i.Hint }
        })
    Add-DiagData -Section 'Failures by user (top 50)' -Data @($fail | Group-Object User | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object {
            [pscustomobject]@{ User = $_.Name; Failures = $_.Count; Codes = (@($_.Group.ErrorCode | Select-Object -Unique) -join ', '); IPs = @($_.Group.IP | Select-Object -Unique).Count; Apps = (@($_.Group.App | Select-Object -Unique) -join ', ') }
        })
    Add-DiagData -Section 'Failures by IP (top 50)' -Data @($fail | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 50 | ForEach-Object {
            [pscustomobject]@{ IP = $_.Name; Failures = $_.Count; DistinctUsers = @($_.Group.User | Select-Object -Unique).Count; Countries = (@($_.Group.Country | Select-Object -Unique) -join ', '); Codes = (@($_.Group.ErrorCode | Select-Object -Unique) -join ', ') }
        })
    Add-DiagData -Section 'Sign-ins by app' -Data @($records | Group-Object App | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ App = $_.Name; Total = $_.Count; Failures = @($_.Group | Where-Object Result -eq 'Failure').Count }
        })
    Add-DiagData -Section 'Sign-ins by country' -Data @($records | Group-Object Country | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ Country = $_.Name; Total = $_.Count; Success = @($_.Group | Where-Object Result -eq 'Success').Count; Users = @($_.Group.User | Select-Object -Unique).Count }
        })
    Add-DiagData -Section 'Client apps' -Data @($records | Group-Object ClientApp | Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ ClientApp = $_.Name; Total = $_.Count; Legacy = ($legacyClients -contains $_.Name); Success = @($_.Group | Where-Object Result -eq 'Success').Count }
        })

    # Patterns
    foreach ($g in @($fail | Where-Object { $_.ErrorCode -in '50126', '50053' } | Group-Object IP | Where-Object { @($_.Group.User | Select-Object -Unique).Count -ge 5 })) {
        Add-DiagFinding -Severity Critical -Area 'Attack patterns' -Title "Possible password spray from $($g.Name): $(@($g.Group.User | Select-Object -Unique).Count) users, $($g.Count) failures" -Recommendation 'Block the IP (named location / firewall), verify no successful sign-ins from it, enforce MFA and smart lockout.'
    }
    $sprayOk = @($fail | Where-Object { $_.ErrorCode -eq '50126' } | Group-Object IP | Where-Object { @($_.Group.User | Select-Object -Unique).Count -ge 5 } | ForEach-Object Name)
    foreach ($ip in $sprayOk) {
        $succ = @($records | Where-Object { $_.IP -eq $ip -and $_.Result -eq 'Success' })
        if ($succ.Count -gt 0) { Add-DiagFinding -Severity Critical -Area 'Attack patterns' -Title "Successful sign-in(s) from spraying IP $ip by: $((@($succ.User | Select-Object -Unique)) -join ', ')" -Recommendation 'Treat these accounts as compromised: reset password, revoke sessions, review MFA methods and inbox rules.' }
    }
    foreach ($g in @($records | Where-Object { $_.ErrorCode -eq '500121' } | Group-Object User | Where-Object { $_.Count -ge 5 })) {
        Add-DiagFinding -Severity Warning -Area 'Attack patterns' -Title "$($g.Name): $($g.Count) MFA denials/timeouts (500121)" -Recommendation 'Possible MFA fatigue attack if the user did not trigger them. Enable number matching and check password compromise.'
    }
    $legacy = @($records | Where-Object { $legacyClients -contains $_.ClientApp })
    if ($legacy.Count -gt 0) { Add-DiagFinding -Severity Warning -Area 'Legacy auth' -Title "$($legacy.Count) sign-in(s) by legacy clients from $(@($legacy.User | Select-Object -Unique).Count) user(s)" -Recommendation 'Identify devices/apps still using basic auth (see Client apps table) and move to modern auth.' }
    foreach ($g in @($fail | Group-Object ErrorCode | Sort-Object Count -Descending | Select-Object -First 5)) {
        $i = Get-DiagSignInErrorInfo -Code $g.Name
        Add-DiagFinding -Severity Info -Area 'Errors' -Title "Top error $($g.Name) x$($g.Count): $($i.Description)" -Recommendation $i.Hint
    }

    Add-DiagData -Section 'Failed sign-ins (detail)' -Data @($fail | Sort-Object Time -Descending | Select-Object -First 2000)
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
