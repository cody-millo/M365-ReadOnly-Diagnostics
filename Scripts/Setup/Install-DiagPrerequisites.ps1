<#
.SYNOPSIS
    Checks (and optionally installs, per-user, with confirmation) the PowerShell modules the diagnostics use: Microsoft.Graph.Authentication, ExchangeOnlineManagement, MicrosoftTeams, Microsoft.Online.SharePoint.PowerShell.

.DESCRIPTION
    Shows what is installed, the version, and which script categories need it. Nothing is installed unless
    you confirm each module. Installs go to the CurrentUser scope from the PowerShell Gallery (no admin rights,
    no machine-wide changes). This is the only script in the toolkit that changes anything, and only on this PC.

.PARAMETER Install
    Offer to install/update missing or outdated modules.

.EXAMPLE
    .\Install-DiagPrerequisites.ps1
    .\Install-DiagPrerequisites.ps1 -Install

.NOTES
    Connection : PowerShell Gallery (only when installing)
    Roles      : None (CurrentUser install)
    Read-only  : Read-only for Microsoft 365. Installs modules locally only after you confirm.
#>
[CmdletBinding()]
param([switch]$Install)

$required = @(
    [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Min = '2.0.0'; UsedBy = 'Tenant, Entra ID, Intune' }
    [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Min = '3.2.0'; UsedBy = 'Exchange, Audit log' }
    [pscustomobject]@{ Name = 'MicrosoftTeams'; Min = '5.0.0'; UsedBy = 'Teams' }
    [pscustomobject]@{ Name = 'Microsoft.Online.SharePoint.PowerShell'; Min = '16.0.0'; UsedBy = 'SharePoint & OneDrive' }
)

Write-Host ''
Write-Host '  Prerequisites' -ForegroundColor Cyan
Write-Host "  PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))  |  Execution policy (effective): $(Get-ExecutionPolicy)"
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) { Write-Host '  PowerShell 5.1 or later is required.' -ForegroundColor Red }
if ($PSVersionTable.PSEdition -eq 'Core') { Write-Host '  Tip: Windows PowerShell 5.1 gives the best compatibility for the SharePoint module and file pickers.' -ForegroundColor DarkGray }

$status = foreach ($r in $required) {
    $m = Get-Module -ListAvailable -Name $r.Name | Sort-Object Version -Descending | Select-Object -First 1
    $state = if (-not $m) { 'Missing' } elseif ($m.Version -lt [version]$r.Min) { 'Outdated' } else { 'OK' }
    [pscustomobject]@{ Module = $r.Name; Installed = if ($m) { [string]$m.Version } else { '-' }; Minimum = $r.Min; Status = $state; UsedBy = $r.UsedBy }
}
$status | Format-Table -AutoSize | Out-String | Write-Host
Write-Host '  Offline scripts (DNS check, header analyzer, sign-in export analysis, local PC checks, sanitizer) need no modules.' -ForegroundColor DarkGray

$todo = @($status | Where-Object Status -ne 'OK')
if ($todo.Count -eq 0) { Write-Host '  All modules are present.' -ForegroundColor Green; return }
if (-not $Install) {
    $ans = Read-Host -Prompt '  Install/update the missing modules for the current user now? [y/N]'
    if ($ans -notmatch '^(y|yes)$') { Write-Host '  Nothing installed.'; return }
}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
foreach ($t in $todo) {
    $ans = Read-Host -Prompt "  $($t.Status): $($t.Module) - install latest from PowerShell Gallery (CurrentUser)? [y/N]"
    if ($ans -notmatch '^(y|yes)$') { continue }
    try {
        Install-Module -Name $t.Module -Scope CurrentUser -Repository PSGallery -AllowClobber -Force -ErrorAction Stop
        Write-Host "  Installed $($t.Module)." -ForegroundColor Green
    }
    catch { Write-Host "  Failed to install $($t.Module): $($_.Exception.Message)" -ForegroundColor Red }
}
