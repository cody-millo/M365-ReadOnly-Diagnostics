<#
.SYNOPSIS
    Hybrid identity / Entra Connect sync health: last sync times, sync features (PHS, writeback, accidental-delete protection), objects with sync provisioning errors, and an optional single-user sync check.

.DESCRIPTION
    Typical questions answered: "a change in AD did not reach the cloud", "new user has no mailbox",
    "duplicate proxy address/UPN errors", "password changes are not syncing".

.PARAMETER UserPrincipalName
    Optional user to compare against the tenant's last sync time.

.PARAMETER MaxObjects
    Max synced users to scan when the server-side error filter is unavailable (default 20000).

.EXAMPLE
    .\Get-DirectorySyncHealth.ps1 -UserPrincipalName jane@contoso.com

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader / Hybrid Identity Administrator (read)
    Scopes     : Organization.Read.All, Directory.Read.All, User.Read.All, OnPremDirectorySynchronization.Read.All
    Read-only  : HTTP GET requests only.
#>
[CmdletBinding()]
param(
    [string]$UserPrincipalName,
    [int]$MaxObjects = 20000,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $PSBoundParameters.ContainsKey('UserPrincipalName')) { $UserPrincipalName = Read-DiagValue -Prompt 'Also check one synced user (UPN)' -Optional }

Start-DiagRun -Name 'Get-DirectorySyncHealth' -Title 'Entra ID - Directory Sync Health' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ UserPrincipalName = $UserPrincipalName })
try {
    Connect-DiagGraph -Scopes 'Organization.Read.All', 'Directory.Read.All', 'User.Read.All', 'OnPremDirectorySynchronization.Read.All' -TenantId $TenantId
    $now = (Get-Date).ToUniversalTime()

    $org = Invoke-DiagStep -Name 'Tenant sync status' -Area 'Sync' -ScriptBlock { @(Invoke-DiagGraph -Uri 'v1.0/organization?$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime')[0] }
    $lastSync = $null
    if ($org) {
        Add-DiagData -Section 'Tenant sync status' -Data $org
        if (-not $org.onPremisesSyncEnabled) { Add-DiagFinding -Severity Info -Area 'Sync' -Title 'Directory synchronization is not enabled (cloud-only tenant)' }
        else {
            $lastSync = ConvertTo-DiagDate $org.onPremisesLastSyncDateTime
            $h = if ($lastSync) { [math]::Round(($now - $lastSync).TotalHours, 1) } else { 9999 }
            if ($h -gt 24) { Add-DiagFinding -Severity Critical -Area 'Sync' -Title "Last directory sync was $h hours ago" -Recommendation 'Sync server stopped/staging mode/expired credentials. On the server: Get-ADSyncScheduler, check Synchronization Service Manager and the event log.' }
            elseif ($h -gt 3) { Add-DiagFinding -Severity Warning -Area 'Sync' -Title "Last directory sync was $h hours ago (normally every 30 minutes)" }
            else { Add-DiagFinding -Severity OK -Area 'Sync' -Title "Directory sync current (last $h h ago)" }
        }
    }

    Invoke-DiagStep -Name 'Sync features and configuration' -Area 'Sync' -ScriptBlock {
        $cfg = @(Invoke-DiagGraph -Uri 'v1.0/directory/onPremisesSynchronization')
        foreach ($c in $cfg) {
            Add-DiagData -Section 'Sync features' -Data $c.features
            Add-DiagData -Section 'Sync configuration' -Data $c.configuration
            $adp = $c.configuration.accidentalDeletionPrevention
            if ($adp -and $adp.synchronizationPreventionType -eq 'disabled') { Add-DiagFinding -Severity Warning -Area 'Sync' -Title 'Accidental deletion prevention is disabled' -Recommendation 'A bad OU filter change could delete many cloud objects. Enable the threshold.' }
            if ($c.features -and $c.features.passwordSyncEnabled -eq $false) { Add-DiagFinding -Severity Info -Area 'Sync' -Title 'Password hash sync is disabled' -Detail 'Sign-in depends on federation or pass-through authentication agents; no leaked-credential detection.' }
        }
    } | Out-Null

    # Provisioning errors
    $errUsers = Invoke-DiagStep -Name 'Objects with sync provisioning errors' -Area 'Errors' -ScriptBlock {
        $rows = $null
        try {
            $rows = Invoke-DiagGraph -Uri 'v1.0/users?$filter=onPremisesProvisioningErrors/any(x:x/category ne null)&$count=true&$select=id,displayName,userPrincipalName,onPremisesProvisioningErrors,onPremisesLastSyncDateTime&$top=999' -Eventual -All -MaxItems 5000
        }
        catch {
            Write-DiagInfo 'Server-side filter not supported here - scanning synced users client-side' -Level Dim
            $synced = Invoke-DiagGraph -Uri 'v1.0/users?$filter=onPremisesSyncEnabled eq true&$count=true&$select=id,displayName,userPrincipalName,onPremisesProvisioningErrors,onPremisesLastSyncDateTime&$top=999' -Eventual -All -MaxItems $MaxObjects
            $rows = @($synced | Where-Object { @($_.onPremisesProvisioningErrors).Count -gt 0 })
        }
        $out = foreach ($u in @($rows)) {
            foreach ($e in @($u.onPremisesProvisioningErrors)) {
                [pscustomobject]@{ ObjectType = 'User'; Object = $u.userPrincipalName; Category = $e.category; Property = $e.propertyCausingError; Value = $e.value; Occurred = $e.occurredDateTime }
            }
        }
        foreach ($kind in 'groups', 'contacts') {
            try {
                $o = Invoke-DiagGraph -Uri "v1.0/$kind`?`$filter=onPremisesProvisioningErrors/any(x:x/category ne null)&`$count=true&`$select=id,displayName,onPremisesProvisioningErrors&`$top=999" -Eventual -All -MaxItems 2000
                foreach ($g in @($o)) { foreach ($e in @($g.onPremisesProvisioningErrors)) { [pscustomobject]@{ ObjectType = $kind.TrimEnd('s'); Object = $g.displayName; Category = $e.category; Property = $e.propertyCausingError; Value = $e.value; Occurred = $e.occurredDateTime } } }
            }
            catch { Write-DiagInfo "Could not query $kind provisioning errors: $($_.Exception.Message)" -Level Dim }
        }
        @($out)
    }
    if ($null -ne $errUsers) {
        $errUsers = @($errUsers)
        Add-DiagData -Section 'Sync provisioning errors' -Data $errUsers -Description 'PropertyConflict = another object already uses the value (ProxyAddresses / UserPrincipalName). Fix in on-premises AD, then wait for the next sync.'
        if ($errUsers.Count -gt 0) {
            foreach ($g in ($errUsers | Group-Object Property)) {
                Add-DiagFinding -Severity Warning -Area 'Errors' -Title "$($g.Count) object(s) with sync conflict on '$($g.Name)'" -Recommendation 'Find the other object that holds the same value (Get-Recipient / admin center search), remove the duplicate in AD.'
            }
        }
        else { Add-DiagFinding -Severity OK -Area 'Errors' -Title 'No objects with sync provisioning errors' }
    }

    if ($UserPrincipalName) {
        Invoke-DiagStep -Name "User sync state: $UserPrincipalName" -Area 'User' -ScriptBlock {
            $u = Invoke-DiagGraph -Uri ("v1.0/users/" + [uri]::EscapeDataString($UserPrincipalName) + '?$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesDomainName,onPremisesSamAccountName,onPremisesUserPrincipalName,onPremisesDistinguishedName,onPremisesImmutableId,onPremisesProvisioningErrors,proxyAddresses,mail,accountEnabled')
            Register-DiagSensitiveValue -Value $u.displayName -Category name
            Add-DiagData -Section 'User sync state' -Data $u
            if (-not $u.onPremisesSyncEnabled) { Add-DiagFinding -Severity Info -Area 'User' -Title 'User is cloud-only (not synced)' -Detail 'Changes made in on-premises AD do not apply. If it should be synced, check OU filtering and soft/hard matching (ImmutableId).' }
            else {
                $us = ConvertTo-DiagDate $u.onPremisesLastSyncDateTime
                if ($us -and $lastSync -and ($lastSync - $us).TotalDays -gt 2) {
                    Add-DiagFinding -Severity Warning -Area 'User' -Title "User last synced $us UTC, tenant last synced $lastSync UTC" -Detail 'Either nothing changed on the object (normal) or the object fell out of sync scope (moved OU / filtered).' -Recommendation 'If a recent AD change is missing, check the object in Synchronization Service Manager (Metaverse search).'
                }
                if ($u.onPremisesUserPrincipalName -and $u.onPremisesUserPrincipalName -ne $u.userPrincipalName) {
                    Add-DiagFinding -Severity Info -Area 'User' -Title 'Cloud UPN differs from on-premises UPN' -Detail "On-prem: $($u.onPremisesUserPrincipalName)  Cloud: $($u.userPrincipalName)" -Recommendation 'Happens when the on-prem UPN suffix is not a verified domain (falls back to .onmicrosoft.com).'
                }
            }
        } | Out-Null
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
