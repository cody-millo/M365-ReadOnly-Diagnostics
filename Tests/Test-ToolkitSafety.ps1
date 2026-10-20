<#
.SYNOPSIS
    Static guard-rail check for the toolkit: proves (by parsing every script) that it stays READ-ONLY and EDR-friendly.

.DESCRIPTION
    Fails (exit code 1) when any script:
      - has a syntax error
      - calls a command whose verb is not read-only (Set/New/Remove/Add/Update/Enable/Grant/Start/...) unless it is
        an explicitly allow-listed local helper (reporting, console output)
      - calls Invoke-MgGraphRequest with anything other than -Method GET
      - requests a Microsoft Graph scope that is not *.Read / *.Read.All / *.ReadBasic.All
      - uses an alias or bare command name (everything must be a full cmdlet name)
      - uses constructs that endpoint protection commonly treats as suspicious: dynamic code execution,
        encoded commands, decoding, web downloads, reflective loading, inline compilation,
        COM automation, process launching, hidden windows, execution-policy bypass in launchers
      - contains non-ASCII characters (Windows PowerShell 5.1 safety)
    The rules are expressed as allow-lists plus a short deny-list of cmdlet/member names, so this file
    contains no attack-tool names or signature strings.

    Run locally:  .\Tests\Test-ToolkitSafety.ps1
#>
[CmdletBinding()]
param([string]$Root = (Split-Path -Path $PSScriptRoot -Parent))

$readVerbs = @('Get', 'Test', 'Search', 'Select', 'Sort', 'Group', 'Measure', 'Where', 'ForEach', 'Format', 'ConvertTo', 'ConvertFrom', 'Read', 'Resolve', 'Split', 'Join', 'Connect', 'Disconnect', 'Assert', 'Show', 'Compare')
$allowed = @(
    # console / local reporting
    'Write-Host', 'Write-Verbose', 'Write-Warning', 'Write-Output', 'Write-Error', 'Write-DiagInfo', 'Write-DiagFile', 'Write-Wrapped',
    'Out-Null', 'Out-String', 'Import-Module', 'Import-Csv', 'Import-DiagIdentityFile', 'New-Object', 'Add-Member', 'Add-Type', 'Clear-Host', 'Invoke-Item', 'Export-ModuleMember',
    # toolkit helpers (module functions that never touch Microsoft 365 configuration)
    'Start-DiagRun', 'Complete-DiagRun', 'Add-DiagData', 'Add-DiagFinding', 'Invoke-DiagStep', 'Invoke-DiagGraph', 'Invoke-DiagSanitizeNode', 'Invoke-MgGraphRequest',
    'Register-DiagSensitiveValue', 'Register-DiagDomain', 'Register-DiagGraphTenant', 'Protect-DiagText', 'Update-DiagTermRegex', 'New-DiagSanitizer', 'Add-Violation'
)
$allowedPerFile = @{ 'Install-DiagPrerequisites.ps1' = @('Install-Module') }
# Any verb not in the read list / allow list already fails; these are called out by name for clarity.
$neverCommands = @('Invoke-Expression', 'Start-Process', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'Start-Job')
# .NET members that indicate decoding, downloading, dynamic loading or registry/file mutation.
$forbiddenMembers = @('DownloadString', 'DownloadFile', 'DownloadData', 'UploadString', 'UploadFile', 'LoadFrom', 'LoadFile', 'InvokeScript',
    'SetValue', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree', 'CreateSubKey', 'WriteAllBytes', 'AppendAllText', 'SetAccessControl')
$forbiddenTypePattern = '(^|\.)WebClient$|^(System\.)?Reflection\.Assembly$|InteropServices\.Marshal$|^(System\.)?Diagnostics\.Process$|^(System\.)?Convert$'
$writeAllTextAllowed = @('M365Diag.psm1', 'ConvertTo-SanitizedFile.ps1')

$violations = New-Object System.Collections.Generic.List[object]
function Add-Violation { param($File, $Line, $Rule, $Text) $violations.Add([pscustomobject]@{ File = $File; Line = $Line; Rule = $Rule; Text = $Text }) }

$files = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' -and $_.FullName -notmatch '[\\/]Reports[\\/]' })
foreach ($f in $files) {
    $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/')
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in @($errors)) { Add-Violation $rel $e.Extent.StartLineNumber 'ParseError' $e.Message }

    foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $cmd.GetCommandName()
        $line = $cmd.Extent.StartLineNumber
        if (-not $name) { continue }   # & $variable  (native exe invoked by full path, e.g. dsregcmd)
        if ($name -notmatch '-') { Add-Violation $rel $line 'AliasOrBareCommand' $name; continue }
        if ($neverCommands -contains $name) { Add-Violation $rel $line 'ForbiddenCommand' $name; continue }
        $verb = ($name -split '-', 2)[0]
        $ok = ($readVerbs -contains $verb) -or ($allowed -contains $name) -or ($allowedPerFile.ContainsKey($f.Name) -and $allowedPerFile[$f.Name] -contains $name)
        if (-not $ok) { Add-Violation $rel $line 'NonReadOnlyCommand' $cmd.Extent.Text.Split("`n")[0].Trim() }

        $params = @{}
        for ($i = 0; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                $val = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$i + 1] } else { $null }
                $params[$el.ParameterName.ToLowerInvariant()] = $val
            }
        }
        switch ($name) {
            'Invoke-MgGraphRequest' {
                $m = $params['method']
                if (-not $m -or $m.Extent.Text.Trim("'", '"') -ne 'GET') { Add-Violation $rel $line 'GraphNonGet' $cmd.Extent.Text }
            }
            'Add-Type' { foreach ($p in 'typedefinition', 'memberdefinition', 'path', 'literalpath') { if ($params.ContainsKey($p)) { Add-Violation $rel $line 'AddTypeCompile' $cmd.Extent.Text } } }
            'New-Object' { if ($params.ContainsKey('comobject')) { Add-Violation $rel $line 'ComObject' $cmd.Extent.Text } }
            'Connect-DiagGraph' {
                $sc = $params['scopes']
                if ($sc) {
                    foreach ($s in $sc.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
                        if ($s.Value -notmatch '^[A-Za-z][A-Za-z\.]*\.Read(Basic)?(\.All)?$') { Add-Violation $rel $line 'GraphWriteScope' $s.Value }
                    }
                }
            }
        }
        foreach ($pn in $params.Keys) { if ($pn -in 'encodedcommand', 'windowstyle') { Add-Violation $rel $line 'SuspiciousParameter' "-$pn" } }
    }

    foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $mn = [string]$m.Member.Extent.Text
        $target = $m.Expression.Extent.Text
        if ($forbiddenMembers -contains $mn) { Add-Violation $rel $m.Extent.StartLineNumber 'ForbiddenMember' $m.Extent.Text }
        if ($mn -eq 'Load' -and $target -match 'Assembly') { Add-Violation $rel $m.Extent.StartLineNumber 'ReflectiveLoad' $m.Extent.Text }
        if ($mn -in 'Delete', 'Move', 'Replace', 'Copy' -and $target -match 'IO\.(File|Directory)') { Add-Violation $rel $m.Extent.StartLineNumber 'FileMutation' $m.Extent.Text }
        if ($mn -eq 'WriteAllText' -and $writeAllTextAllowed -notcontains $f.Name) { Add-Violation $rel $m.Extent.StartLineNumber 'LocalWriteOutsideReports' $m.Extent.Text }
    }
    foreach ($t in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] -or $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
        if ($t.TypeName.FullName -match $forbiddenTypePattern) { Add-Violation $rel $t.Extent.StartLineNumber 'ForbiddenType' $t.TypeName.FullName }
    }
    $nonAscii = [regex]::Matches([System.IO.File]::ReadAllText($f.FullName), '[^\x00-\x7F]')
    if ($nonAscii.Count -gt 0) { Add-Violation $rel 0 'NonAscii' "$($nonAscii.Count) non-ASCII character(s)" }
}

# Launchers: no execution-policy bypass, no encoded/hidden PowerShell.
foreach ($c in @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.Extension -in '.cmd', '.bat' })) {
    $rel = $c.FullName.Substring($Root.Length).TrimStart('\', '/')
    $n = 0
    foreach ($l in (Get-Content -LiteralPath $c.FullName)) {
        $n++
        if ($l -match '^\s*(rem|::|echo)\b') { continue }
        if ($l -match '(?i)-ExecutionPolicy\s+Bypass|\s-ep\s+bypass|-EncodedCommand|\s-enc\s|-WindowStyle\s+Hidden|\s-w\s+hidden') { Add-Violation $rel $n 'SuspiciousLauncher' $l.Trim() }
    }
}

Write-Host "Checked $($files.Count) PowerShell file(s)."
if ($violations.Count -gt 0) {
    $violations | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    Write-Host "FAILED: $($violations.Count) violation(s)." -ForegroundColor Red
    exit 1
}
Write-Host 'PASSED: all scripts are read-only and free of flagged patterns.' -ForegroundColor Green
exit 0
