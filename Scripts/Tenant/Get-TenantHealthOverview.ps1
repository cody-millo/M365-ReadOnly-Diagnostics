<#
.SYNOPSIS
    Tenant overview: active Microsoft 365 service incidents, service health, licenses, domains and directory sync status.

.DESCRIPTION
    First script to run for "is it us or is it Microsoft?" questions. Collects:
      - Service health per workload and all unresolved incidents/advisories
      - Message center posts with upcoming action-required dates
      - Subscribed SKUs (capacity, over-assignment, suspended/warning subscriptions)
      - Domains (verification, federation) and directory sync freshness

.PARAMETER MessageCenterDays
    How many days of Message center posts to include (default 30).

.EXAMPLE
    .\Get-TenantHealthOverview.ps1

.NOTES
    Connection : Microsoft Graph
    Roles      : Global Reader, or Service Support Administrator / Message Center Reader
    Scopes     : ServiceHealth.Read.All, ServiceMessage.Read.All, Organization.Read.All, Domain.Read.All
    Read-only  : HTTP GET requests only.
#>
[CmdletBinding()]
param(
    [int]$MessageCenterDays = 30,
    [string]$TenantId,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

Start-DiagRun -Name 'Get-TenantHealthOverview' -Title 'Microsoft 365 Tenant Health Overview' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters $PSBoundParameters
try {
    Connect-DiagGraph -Scopes 'ServiceHealth.Read.All', 'ServiceMessage.Read.All', 'Organization.Read.All', 'Domain.Read.All' -TenantId $TenantId

    # --- Organization & directory sync
    $org = Invoke-DiagStep -Name 'Organization details' -Area 'Tenant' -ScriptBlock {
        @(Invoke-DiagGraph -Uri 'v1.0/organization?$select=id,displayName,countryLetterCode,createdDateTime,onPremisesSyncEnabled,onPremisesLastSyncDateTime,technicalNotificationMails,preferredLanguage,tenantType')[0]
    }
    if ($org) {
        Add-DiagData -Section 'Organization' -Data $org
        if ($org.onPremisesSyncEnabled) {
            $last = ConvertTo-DiagDate $org.onPremisesLastSyncDateTime
            if ($last) {
                $hours = [math]::Round(((Get-Date).ToUniversalTime() - $last).TotalHours, 1)
                if ($hours -gt 24) { Add-DiagFinding -Severity Critical -Area 'Directory sync' -Title "Directory sync last ran $hours hours ago" -Detail "Last sync (UTC): $last" -Recommendation 'Check the Entra Connect / Cloud Sync server and service; run Scripts\EntraID\Get-DirectorySyncHealth.ps1.' }
                elseif ($hours -gt 3) { Add-DiagFinding -Severity Warning -Area 'Directory sync' -Title "Directory sync last ran $hours hours ago (expected every 30 min)" -Recommendation 'Check the sync server, scheduler and connectivity.' }
                else { Add-DiagFinding -Severity OK -Area 'Directory sync' -Title "Directory sync is current (last ran $hours h ago)" -Quiet }
            }
        }
        if (-not $org.technicalNotificationMails) { Add-DiagFinding -Severity Info -Area 'Tenant' -Title 'No technical notification contact set' -Recommendation 'Set a technical contact so Microsoft can reach you about incidents.' }
    }

    # --- Service health
    $health = Invoke-DiagStep -Name 'Service health per workload' -Area 'Service health' -ScriptBlock {
        Invoke-DiagGraph -Uri 'v1.0/admin/serviceAnnouncement/healthOverviews?$select=service,status,id' -All
    }
    if ($health) {
        Add-DiagData -Section 'Service health' -Data ($health | Sort-Object status, service | Select-Object service, status, id)
        foreach ($h in @($health | Where-Object { $_.status -notin 'serviceOperational', 'serviceRestored', 'falsePositive', 'postIncidentReviewPublished', 'resolved' })) {
            Add-DiagFinding -Severity Warning -Area 'Service health' -Title "$($h.service): $($h.status)" -Recommendation 'Check the active issues table below and the Service health page in the admin center before deep troubleshooting.'
        }
    }

    $issues = Invoke-DiagStep -Name 'Unresolved incidents and advisories' -Area 'Service health' -ScriptBlock {
        Invoke-DiagGraph -Uri 'v1.0/admin/serviceAnnouncement/issues?$filter=isResolved eq false' -All
    }
    if ($null -ne $issues) {
        $rows = @($issues | Sort-Object lastModifiedDateTime -Descending | ForEach-Object {
                [pscustomobject]@{
                    Id = $_.id; Service = $_.service; Classification = $_.classification; Status = $_.status; Feature = $_.featureGroup
                    Title = $_.title; Impact = $_.impactDescription; Started = $_.startDateTime; LastUpdated = $_.lastModifiedDateTime
                }
            })
        Add-DiagData -Section 'Active issues' -Data $rows -Description 'Unresolved incidents and advisories reported by Microsoft for this tenant.'
        foreach ($i in @($rows | Where-Object { $_.Classification -eq 'incident' })) {
            Add-DiagFinding -Severity Critical -Area 'Service health' -Title "Active Microsoft incident $($i.Id) - $($i.Service): $($i.Title)" -Detail $i.Impact -Recommendation 'If your issue matches this incident, track it instead of troubleshooting locally.'
        }
        $adv = @($rows | Where-Object { $_.Classification -ne 'incident' }).Count
        if ($adv -gt 0) { Add-DiagFinding -Severity Info -Area 'Service health' -Title "$adv active advisory(ies) - see Active issues table" }
        if ($rows.Count -eq 0) { Add-DiagFinding -Severity OK -Area 'Service health' -Title 'No unresolved Microsoft incidents or advisories' }
    }

    # --- Message center
    $msgs = Invoke-DiagStep -Name "Message center (last $MessageCenterDays days)" -Area 'Message center' -ScriptBlock {
        $since = (Get-Date).ToUniversalTime().AddDays(-$MessageCenterDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        Invoke-DiagGraph -Uri "v1.0/admin/serviceAnnouncement/messages?`$filter=lastModifiedDateTime ge $since&`$select=id,title,services,category,severity,isMajorChange,actionRequiredByDateTime,startDateTime,lastModifiedDateTime,tags" -All -MaxItems 500
    }
    if ($null -ne $msgs) {
        $rows = @($msgs | Sort-Object lastModifiedDateTime -Descending | ForEach-Object {
                [pscustomobject]@{
                    Id = $_.id; Title = $_.title; Services = (@($_.services) -join ', '); Category = $_.category; Severity = $_.severity
                    MajorChange = $_.isMajorChange; ActionRequiredBy = $_.actionRequiredByDateTime; LastUpdated = $_.lastModifiedDateTime
                }
            })
        Add-DiagData -Section 'Message center' -Data $rows
        $soon = @($rows | Where-Object { $d = ConvertTo-DiagDate $_.ActionRequiredBy; $d -and $d -gt (Get-Date).ToUniversalTime() -and $d -lt (Get-Date).ToUniversalTime().AddDays(30) })
        if ($soon.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Message center' -Title "$($soon.Count) message center post(s) require action within 30 days" -Detail (($soon | ForEach-Object { "$($_.Id): $($_.Title)" }) -join ' | ') }
    }

    # --- Licenses
    $skus = Invoke-DiagStep -Name 'Subscriptions and license capacity' -Area 'Licensing' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/subscribedSkus' -All }
    if ($skus) {
        $rows = @($skus | ForEach-Object {
                $enabled = [int]$_.prepaidUnits.enabled
                [pscustomobject]@{
                    SkuPartNumber = $_.skuPartNumber; SkuId = $_.skuId; Status = $_.capabilityStatus; Enabled = $enabled
                    Consumed = [int]$_.consumedUnits; Available = ($enabled - [int]$_.consumedUnits)
                    Suspended = [int]$_.prepaidUnits.suspended; Warning = [int]$_.prepaidUnits.warning; AppliesTo = $_.appliesTo
                }
            } | Sort-Object SkuPartNumber)
        Add-DiagData -Section 'Licenses' -Data $rows
        foreach ($r in $rows) {
            if ($r.Status -in 'Suspended', 'LockedOut') { Add-DiagFinding -Severity Critical -Area 'Licensing' -Title "Subscription $($r.SkuPartNumber) is $($r.Status)" -Recommendation 'Users with this license lose service. Check billing in the admin center.' }
            elseif ($r.Status -eq 'Warning' -or $r.Warning -gt 0) { Add-DiagFinding -Severity Warning -Area 'Licensing' -Title "Subscription $($r.SkuPartNumber) is in warning/grace state" -Recommendation 'Renew or reduce assignments before it is suspended.' }
            if ($r.Enabled -gt 0 -and $r.Consumed -gt $r.Enabled) { Add-DiagFinding -Severity Warning -Area 'Licensing' -Title "$($r.SkuPartNumber) over-assigned ($($r.Consumed)/$($r.Enabled))" -Recommendation 'New assignments will fail (CountViolation). Buy licenses or remove unused ones.' }
            elseif ($r.Enabled -ge 10 -and $r.Available -eq 0) { Add-DiagFinding -Severity Info -Area 'Licensing' -Title "$($r.SkuPartNumber) has no licenses left ($($r.Consumed)/$($r.Enabled))" }
        }
    }

    # --- Domains
    $domains = Invoke-DiagStep -Name 'Domains' -Area 'Domains' -ScriptBlock { Invoke-DiagGraph -Uri 'v1.0/domains' -All }
    if ($domains) {
        $rows = @($domains | ForEach-Object {
                [pscustomobject]@{
                    Domain = $_.id; Verified = $_.isVerified; Default = $_.isDefault; Initial = $_.isInitial; Authentication = $_.authenticationType
                    SupportedServices = (@($_.supportedServices) -join ', ')
                }
            })
        Add-DiagData -Section 'Domains' -Data $rows
        foreach ($d in @($rows | Where-Object { -not $_.Verified })) { Add-DiagFinding -Severity Warning -Area 'Domains' -Title "Domain $($d.Domain) is not verified" -Recommendation 'Users/addresses with this domain will not work until verified.' }
        foreach ($d in @($rows | Where-Object { $_.Authentication -eq 'Federated' })) { Add-DiagFinding -Severity Info -Area 'Domains' -Title "Domain $($d.Domain) is federated" -Detail 'Sign-ins for this domain are redirected to the federation server (e.g. AD FS / 3rd-party IdP). Sign-in failures may originate there.' }
        Add-DiagFinding -Severity Info -Area 'Domains' -Title 'Tip: check public DNS records with Scripts\Tenant\Test-DomainDnsRecords.ps1' -Quiet
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
