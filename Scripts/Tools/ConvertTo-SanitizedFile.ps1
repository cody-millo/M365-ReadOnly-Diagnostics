<#
.SYNOPSIS
    Sanitizes any text file before sharing it (logs, CSV exports, message headers, JSON, HTML): pseudonymizes emails/UPNs, domains, tenant names, IPs, GUIDs, SIDs, phone numbers, this PC's name/user, and any extra words you specify. Originals are never modified.

.DESCRIPTION
    Pick one or more files with the file picker. Sanitized copies are written to Reports\<timestamp>_Sanitized\
    and a private de-anonymization map is written to Reports\_private-maps\ (do not share the map).
    The same value always gets the same token across all selected files, so correlations survive.

.PARAMETER Path
    One or more files. A file picker opens if omitted.

.PARAMETER ExtraTerms
    Additional words to mask (company name, project codenames, server names...). Prompted if omitted.

.PARAMETER KeepGuids
    Keep GUIDs (e.g. correlation/request IDs Microsoft support needs).

.EXAMPLE
    .\ConvertTo-SanitizedFile.ps1 -Path .\InteractiveSignIns.csv -ExtraTerms Contoso,ProjectX

.NOTES
    Connection : None (offline)
    Roles      : None
    Read-only  : Reads the selected files; writes only new sanitized copies in the Reports folder.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string[]]$ExtraTerms,
    [switch]$KeepGuids,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Path) {
    $list = New-Object System.Collections.Generic.List[string]
    do {
        $f = Select-DiagFile -Title 'Select a file to sanitize' -Filter 'Text-based files (*.txt;*.log;*.csv;*.json;*.xml;*.eml;*.html;*.htm;*.md)|*.txt;*.log;*.csv;*.json;*.xml;*.eml;*.html;*.htm;*.md|All files (*.*)|*.*'
        if ($f) { $list.Add($f); Write-DiagInfo "Added: $(Split-Path $f -Leaf)" -Level Ok }
    } while ($f -and (Read-DiagYesNo -Prompt 'Add another file?' -Default $false))
    $Path = $list.ToArray()
}
if (-not $Path -or $Path.Count -eq 0) { throw 'No file selected.' }
if (-not $PSBoundParameters.ContainsKey('ExtraTerms')) {
    $t = Read-DiagValue -Prompt 'Extra words to mask, comma separated (company name, server names...)' -Optional
    if ($t) { $ExtraTerms = @($t -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
}
if (-not $PSBoundParameters.ContainsKey('KeepGuids')) { $KeepGuids = Read-DiagYesNo -Prompt 'Keep GUIDs (correlation/request IDs for Microsoft support)?' -Default $false }

Start-DiagRun -Name 'ConvertTo-SanitizedFile' -Title 'Sanitize Files for Sharing' -OutputPath $OutputPath -Parameters ([ordered]@{ Files = (@($Path | ForEach-Object { Split-Path $_ -Leaf }) -join ', '); KeepGuids = [bool]$KeepGuids })
try {
    foreach ($e in @($ExtraTerms)) { Register-DiagSensitiveValue -Value $e -Category name }
    $root = if ($OutputPath) { $OutputPath } else { Get-DiagDefaultOutputRoot }
    $dest = Join-Path $root ((Get-Date).ToString('yyyyMMdd-HHmmss') + '_Sanitized')
    [void][System.IO.Directory]::CreateDirectory($dest)

    $texts = @{}
    foreach ($p in $Path) {
        Invoke-DiagStep -Name "Reading $(Split-Path $p -Leaf)" -Area 'Input' -ScriptBlock {
            $fi = Get-Item -LiteralPath $p -ErrorAction Stop
            if ($fi.Length -gt 200MB) { throw 'File larger than 200 MB - split it first.' }
            $texts[$p] = [System.IO.File]::ReadAllText($p)
        } | Out-Null
    }
    # Pass 1 learns every email domain / tenant name so pass 2 can mask them everywhere, consistently.
    foreach ($p in @($texts.Keys)) { [void](Protect-DiagText -Text $texts[$p] -KeepGuids:$KeepGuids) }
    $rows = foreach ($p in @($texts.Keys)) {
        $clean = Protect-DiagText -Text $texts[$p] -KeepGuids:$KeepGuids
        $name = [System.IO.Path]::GetFileNameWithoutExtension($p) + '.sanitized' + [System.IO.Path]::GetExtension($p)
        $out = Join-Path $dest $name
        [System.IO.File]::WriteAllText($out, $clean, (New-Object System.Text.UTF8Encoding($true)))
        [pscustomobject]@{ Source = (Split-Path $p -Leaf); SanitizedFile = $out; SourceChars = $texts[$p].Length; SanitizedChars = $clean.Length }
    }
    $map = Get-DiagSanitizerMap
    $cats = @($map.Keys | Group-Object { ($_ -replace '\d+.*$', '' -replace '[\.\-]$', '') } | ForEach-Object { [pscustomobject]@{ TokenType = $_.Name; DistinctValues = $_.Count } })
    Add-DiagData -Section 'Sanitized files' -Data @($rows)
    Add-DiagData -Section 'Replacements by type' -Data $cats
    Add-DiagFinding -Severity OK -Area 'Output' -Title "$(@($rows).Count) sanitized file(s) written to $dest" -Detail 'Review the output before sharing - free text such as names inside sentences can only be caught if the name appeared in an identity field or was added as an extra term.'
    Write-DiagInfo "Sanitized copies: $dest" -Level Ok
}
catch {
    Add-DiagFinding -Severity Error -Title 'Sanitization stopped early' -Detail $_.Exception.Message
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
