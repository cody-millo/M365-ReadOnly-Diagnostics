<#
.SYNOPSIS
    Menu launcher for the M365 Read-Only Diagnostics toolkit.

.DESCRIPTION
    Lists every diagnostic script by service with a one-line description, the connection it needs and the
    admin role it expects, then runs the one you pick. Scripts prompt for their own inputs (and open a file
    picker where a file is needed). Sessions (Graph/Exchange/Teams/SharePoint) are reused between runs in the
    same window and can be signed out on exit.

.PARAMETER List
    Print the script catalog and exit.

.EXAMPLE
    .\Start-M365Diag.ps1
    (or double-click Start-M365Diag.cmd)
#>
[CmdletBinding()]
param([switch]$List)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$version = '1.0.0'
$sanitize = $true

$categories = [ordered]@{
    'Tenant'              = 'Tenant & service health'
    'EntraID'             = 'Entra ID - identity, sign-in, licensing, sync'
    'Exchange'            = 'Exchange Online - mailboxes, mail flow, calendars'
    'Teams'               = 'Microsoft Teams - users, teams, policies, phone'
    'SharePoint-OneDrive' = 'SharePoint & OneDrive'
    'Intune-Devices'      = 'Intune & devices'
    'Client-Local'        = 'This PC - local client checks (no sign-in)'
    'Tools'               = 'Tools - sanitize files for sharing'
}

function Get-ScriptInfo {
    param([System.IO.FileInfo]$File)
    $head = (Get-Content -LiteralPath $File.FullName -TotalCount 80) -join "`n"
    $syn = if ($head -match '\.SYNOPSIS\s*\n\s*(.+)') { $Matches[1].Trim() } else { '' }
    $conn = if ($head -match 'Connection\s*:\s*(.+)') { $Matches[1].Trim() } else { '' }
    $roles = if ($head -match 'Roles\s*:\s*(.+)') { $Matches[1].Trim() } else { '' }
    [pscustomobject]@{ Name = $File.BaseName; Path = $File.FullName; Synopsis = $syn; Connection = $conn; Roles = $roles }
}

function Get-Catalog {
    $cat = [ordered]@{}
    foreach ($k in $categories.Keys) {
        $dir = Join-Path $root "Scripts\$k"
        if (Test-Path -LiteralPath $dir) { $cat[$k] = @(Get-ChildItem -LiteralPath $dir -Filter '*.ps1' | Sort-Object Name | ForEach-Object { Get-ScriptInfo $_ }) }
    }
    return $cat
}

function Write-Wrapped {
    param([string]$Text, [int]$Indent = 8, [string]$Color = 'Gray')
    $cw = 100
    try { $cw = $host.UI.RawUI.WindowSize.Width } catch { $cw = 100 }
    if (-not $cw -or $cw -lt 40) { $cw = 100 }
    $width = [math]::Max(60, $cw - $Indent - 2)
    $line = ''
    foreach ($w in ($Text -split '\s+')) {
        if (($line.Length + $w.Length + 1) -gt $width) { Write-Host ((' ' * $Indent) + $line) -ForegroundColor $Color; $line = $w }
        else { $line = if ($line) { "$line $w" } else { $w } }
    }
    if ($line) { Write-Host ((' ' * $Indent) + $line) -ForegroundColor $Color }
}

function Show-Header {
    Clear-Host
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  M365 READ-ONLY DIAGNOSTICS  v$version" -ForegroundColor Cyan
    Write-Host '  Every script is read-only: back-end diagnostics first, no changes made.' -ForegroundColor DarkGray
    $s = if ($sanitize) { 'ON  - reports are pseudonymized (safe to share)' } else { 'OFF - reports contain real names/addresses' }
    Write-Host "  Output sanitization: $s" -ForegroundColor $(if ($sanitize) { 'Green' } else { 'Yellow' })
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Test-Blocked {
    # Files downloaded from the internet carry a Zone.Identifier stream; RemoteSigned then refuses to run them.
    $blocked = @(Get-ChildItem -LiteralPath $root -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -ErrorAction SilentlyContinue | Where-Object { Get-Item -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue })
    if ($blocked.Count -gt 0) {
        Write-Host ''
        Write-Host "  $($blocked.Count) script file(s) are marked as downloaded from the internet and may be blocked." -ForegroundColor Yellow
        Write-Host '  Run Unblock-M365Diag.cmd once (or clone the repo with git) and start again.' -ForegroundColor Yellow
        Write-Host ''
    }
}

function Disconnect-All {
    try { if (Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue) { if (Get-MgContext) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Write-Host '  Signed out of Microsoft Graph' } } } catch { Write-Verbose $_ }
    try { if (Get-Command -Name Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null; Write-Host '  Signed out of Exchange Online' } } catch { Write-Verbose $_ }
    try { if (Get-Command -Name Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue) { Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null; Write-Host '  Signed out of Microsoft Teams' } } catch { Write-Verbose $_ }
    try { if (Get-Command -Name Disconnect-SPOService -ErrorAction SilentlyContinue) { Disconnect-SPOService -ErrorAction SilentlyContinue; Write-Host '  Signed out of SharePoint Online' } } catch { Write-Verbose $_ }
}

$catalog = Get-Catalog
if ($List) {
    foreach ($k in $catalog.Keys) {
        Write-Host "`n$($categories[$k])" -ForegroundColor Cyan
        foreach ($s in $catalog[$k]) { Write-Host "  $($s.Name)  [$($s.Connection)]"; Write-Wrapped $s.Synopsis 4 }
    }
    return
}

$host.UI.RawUI.WindowTitle = 'M365 Read-Only Diagnostics'
Test-Blocked
while ($true) {
    Show-Header
    $keys = @($catalog.Keys)
    for ($i = 0; $i -lt $keys.Count; $i++) { Write-Host ("   [{0}] {1}  ({2})" -f ($i + 1), $categories[$keys[$i]], $catalog[$keys[$i]].Count) }
    Write-Host '   ---------------------------------------------'
    Write-Host '   [P] Prerequisites - check/install modules'
    Write-Host "   [S] Toggle output sanitization (now: $(if ($sanitize) {'ON'} else {'OFF'}))"
    Write-Host '   [R] Open the Reports folder'
    Write-Host '   [H] Open README'
    Write-Host '   [Q] Quit'
    $c = (Read-Host -Prompt "`n  Choose").Trim()
    switch -Regex ($c) {
        '^[Qq]$' {
            if ((Read-Host -Prompt '  Sign out of all Microsoft 365 sessions opened in this window? [Y/n]') -notmatch '^(n|no)$') { Disconnect-All }
            return
        }
        '^[Pp]$' { & (Join-Path $root 'Scripts\Setup\Install-DiagPrerequisites.ps1'); Read-Host -Prompt "`n  Press Enter to return to the menu" | Out-Null; continue }
        '^[Ss]$' {
            if ($sanitize) {
                Write-Host '  Raw output contains real user names, emails, IPs and IDs. Keep it inside your organization.' -ForegroundColor Yellow
                if ((Read-Host -Prompt '  Turn sanitization OFF? [y/N]') -match '^(y|yes)$') { $sanitize = $false }
            }
            else { $sanitize = $true }
            continue
        }
        '^[Rr]$' {
            $rep = if ($env:M365DIAG_OUTPUT) { $env:M365DIAG_OUTPUT } else { Join-Path $root 'Reports' }
            [void][System.IO.Directory]::CreateDirectory($rep)
            Invoke-Item -LiteralPath $rep
            continue
        }
        '^[Hh]$' { Invoke-Item -LiteralPath (Join-Path $root 'README.md'); continue }
        '^\d+$' {
            $idx = [int]$c - 1
            if ($idx -lt 0 -or $idx -ge $keys.Count) { continue }
            $k = $keys[$idx]
            $scripts = $catalog[$k]
            Show-Header
            Write-Host "  $($categories[$k])" -ForegroundColor Cyan
            Write-Host ''
            for ($j = 0; $j -lt $scripts.Count; $j++) {
                $s = $scripts[$j]
                Write-Host ("   [{0}] {1}" -f ($j + 1), $s.Name) -ForegroundColor White
                Write-Wrapped $s.Synopsis 8 'Gray'
                Write-Wrapped "Needs: $($s.Connection)  |  Role: $($s.Roles)" 8 'DarkGray'
            }
            Write-Host '   [B] Back'
            $sc = (Read-Host -Prompt "`n  Run which script").Trim()
            if ($sc -notmatch '^\d+$' -or [int]$sc -lt 1 -or [int]$sc -gt $scripts.Count) { continue }
            $pick = $scripts[[int]$sc - 1]
            Write-Host ''
            $runArgs = @{}
            $cmd = Get-Command -Name $pick.Path -ErrorAction SilentlyContinue
            if (-not $sanitize -and $cmd -and $cmd.Parameters.ContainsKey('NoSanitize')) { $runArgs['NoSanitize'] = $true }
            try { & $pick.Path @runArgs }
            catch { Write-Host "  Script error: $($_.Exception.Message)" -ForegroundColor Red }
            Read-Host -Prompt "`n  Press Enter to return to the menu" | Out-Null
        }
    }
}
