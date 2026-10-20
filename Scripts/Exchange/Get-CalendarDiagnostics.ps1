<#
.SYNOPSIS
    Calendar & room/resource booking diagnostics: calendar processing (auto-accept, booking policies, delegates), room metadata/room lists, calendar permissions, working hours, and the change history of a specific meeting.

.DESCRIPTION
    Typical tickets: "room doesn't accept/decline", "meeting subject replaced by organizer name",
    "nobody can book the room", "meeting disappeared/was moved", "free/busy not visible",
    "delegate not receiving invites". With -MeetingSubject, Get-CalendarDiagnosticObjects shows who changed
    the meeting, when, and from which client (ClientInfoString).

.PARAMETER Identity
    User or room/resource mailbox. Prompted if omitted.

.PARAMETER MeetingSubject
    Optional subject (or part of it) of a meeting to pull the change log for.

.PARAMETER Days
    Window for the meeting history search (default 90 days back to 90 days ahead).

.EXAMPLE
    .\Get-CalendarDiagnostics.ps1 -Identity room-boardroom@contoso.com -MeetingSubject "Weekly sync"

.NOTES
    Connection : Exchange Online
    Roles      : Global Reader or View-Only Organization Management (meeting history may require Exchange Recipient Administrator read rights)
    Read-only  : Exchange session restricted to Get- cmdlets.
#>
[CmdletBinding()]
param(
    [string]$Identity,
    [string]$MeetingSubject,
    [int]$Days = 90,
    [string]$UserPrincipalName,
    [switch]$NoSanitize,
    [string]$OutputPath,
    [switch]$NoOpen
)
Import-Module (Join-Path $PSScriptRoot '..\..\Modules\M365Diag\M365Diag.psd1') -DisableNameChecking

if (-not $Identity) { $Identity = Read-DiagValue -Prompt 'User or room mailbox (email)' }
if (-not $PSBoundParameters.ContainsKey('MeetingSubject')) { $MeetingSubject = Read-DiagValue -Prompt 'Meeting subject to trace history for' -Optional }

Start-DiagRun -Name 'Get-CalendarDiagnostics' -Title 'Exchange Online - Calendar & Room Booking Diagnostics' -NoSanitize:$NoSanitize -OutputPath $OutputPath -Parameters ([ordered]@{ Identity = $Identity; MeetingSubject = $MeetingSubject; Days = $Days })
$commands = 'Get-Mailbox', 'Get-CalendarProcessing', 'Get-MailboxFolderStatistics', 'Get-MailboxFolderPermission', 'Get-MailboxCalendarConfiguration',
'Get-CalendarDiagnosticObjects', 'Get-Place', 'Get-DistributionGroup', 'Get-DistributionGroupMember', 'Get-OrganizationRelationship', 'Get-SharingPolicy', 'Get-Recipient'
try {
    Connect-DiagExchange -CommandName $commands -UserPrincipalName $UserPrincipalName
    $mbx = Invoke-DiagStep -Name 'Mailbox' -Area 'Mailbox' -ScriptBlock { Get-Mailbox -Identity $Identity -ErrorAction Stop }
    if (-not $mbx) { throw "Mailbox '$Identity' not found." }
    $upn = [string]$mbx.PrimarySmtpAddress
    Register-DiagSensitiveValue -Value ([string]$mbx.DisplayName) -Category name
    $isResource = $mbx.RecipientTypeDetails -in 'RoomMailbox', 'EquipmentMailbox'
    Add-DiagData -Section 'Mailbox' -Data ($mbx | Select-DiagObject -Property DisplayName, PrimarySmtpAddress, RecipientTypeDetails, ResourceCapacity, ResourceType, HiddenFromAddressListsEnabled, GrantSendOnBehalfTo)
    if ($isResource -and $mbx.HiddenFromAddressListsEnabled) { Add-DiagFinding -Severity Warning -Area 'Room' -Title 'Resource is hidden from the address list' -Recommendation 'Users cannot find it in Room Finder/GAL.' }

    $cp = Invoke-DiagStep -Name 'Calendar processing' -Area 'Processing' -ScriptBlock { Get-CalendarProcessing -Identity $upn -ErrorAction Stop }
    if ($cp) {
        Add-DiagData -Section 'Calendar processing' -Data ($cp | Select-DiagObject -Property AutomateProcessing, AllowConflicts, ConflictPercentageAllowed, MaximumConflictInstances, BookingWindowInDays, MaximumDurationInMinutes, MinimumDurationInMinutes, AllowRecurringMeetings, EnforceSchedulingHorizon, ScheduleOnlyDuringWorkHours, EnforceCapacity,
            AllBookInPolicy, BookInPolicy, AllRequestInPolicy, RequestInPolicy, AllRequestOutOfPolicy, RequestOutOfPolicy, ResourceDelegates, ForwardRequestsToDelegates, TentativePendingApproval,
            DeleteSubject, AddOrganizerToSubject, DeleteComments, RemovePrivateProperty, DeleteAttachments, RemoveOldMeetingMessages, RemoveForwardedMeetingNotifications, ProcessExternalMeetingMessages, AddAdditionalResponse, BookingType)
        if ($isResource) {
            if ($cp.AutomateProcessing -ne 'AutoAccept') { Add-DiagFinding -Severity Warning -Area 'Processing' -Title "Room AutomateProcessing = $($cp.AutomateProcessing) (not AutoAccept)" -Detail 'Requests are not accepted/declined automatically (AutoUpdate = only tentative, None = nothing).' -Recommendation 'Set AutomateProcessing AutoAccept (change - do it deliberately).' }
            $nobody = (-not $cp.AllBookInPolicy) -and @($cp.BookInPolicy).Count -eq 0 -and (-not $cp.AllRequestInPolicy) -and @($cp.RequestInPolicy).Count -eq 0
            if ($nobody) { Add-DiagFinding -Severity Critical -Area 'Processing' -Title 'Nobody is allowed to book or request this room' -Detail 'AllBookInPolicy and AllRequestInPolicy are False with empty BookIn/RequestIn lists - every request is declined.' }
            elseif (-not $cp.AllBookInPolicy -and @($cp.BookInPolicy).Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Processing' -Title "Only $(@($cp.BookInPolicy).Count) user(s)/group(s) can book directly (BookInPolicy)" -Detail 'Others are declined or go to delegates (RequestInPolicy).' }
            if ($cp.AllRequestInPolicy -and @($cp.ResourceDelegates).Count -eq 0 -and -not $cp.AllBookInPolicy) { Add-DiagFinding -Severity Warning -Area 'Processing' -Title 'Requests need approval but no ResourceDelegates are set' -Detail 'Requests stay tentative forever.' }
            if ($cp.DeleteSubject -or $cp.AddOrganizerToSubject) { Add-DiagFinding -Severity Info -Area 'Processing' -Title 'Room replaces/deletes the meeting subject' -Detail "DeleteSubject=$($cp.DeleteSubject), AddOrganizerToSubject=$($cp.AddOrganizerToSubject). Explains 'subject shows organizer name' in the room calendar." }
            if (-not $cp.ProcessExternalMeetingMessages) { Add-DiagFinding -Severity Info -Area 'Processing' -Title 'External meeting requests are ignored (ProcessExternalMeetingMessages = False)' }
            if (-not $cp.AllowRecurringMeetings) { Add-DiagFinding -Severity Info -Area 'Processing' -Title 'Recurring meetings are not allowed' }
            if ($cp.BookingWindowInDays -lt 180) { Add-DiagFinding -Severity Info -Area 'Processing' -Title "Booking window is $($cp.BookingWindowInDays) days" -Detail 'Recurring series extending past the window are declined (unless EnforceSchedulingHorizon = False).' }
            if ($cp.MaximumDurationInMinutes -and $cp.MaximumDurationInMinutes -lt 1440) { Add-DiagFinding -Severity Info -Area 'Processing' -Title "Maximum meeting duration is $($cp.MaximumDurationInMinutes) minutes" }
            if (-not $cp.AllowConflicts -and $cp.MaximumConflictInstances -eq 0) { Add-DiagFinding -Severity Info -Area 'Processing' -Title 'Any conflict in a recurring series declines the whole series' -Detail 'Increase ConflictPercentageAllowed/MaximumConflictInstances to accept series with a few conflicts.' }
            if ($cp.ScheduleOnlyDuringWorkHours) { Add-DiagFinding -Severity Info -Area 'Processing' -Title 'Room only accepts meetings within its working hours' }
        }
        else {
            if ($cp.AutomateProcessing -eq 'None') { Add-DiagFinding -Severity Warning -Area 'Processing' -Title 'Calendar Attendant is disabled for this user (AutomateProcessing = None)' -Detail 'Meeting requests are not added to the calendar as tentative and updates are not processed.' }
        }
    }

    Invoke-DiagStep -Name 'Calendar configuration (working hours)' -Area 'Config' -ScriptBlock {
        $cc = Get-MailboxCalendarConfiguration -Identity $upn -ErrorAction Stop
        Add-DiagData -Section 'Calendar configuration' -Data ($cc | Select-DiagObject -Property WorkDays, WorkingHoursStartTime, WorkingHoursEndTime, WorkingHoursTimeZone, ShowWeekNumbers, DefaultReminderTime, RemindersEnabled,CreateEventsFromEmail, OnlineMeetingsByDefaultEnabled, DefaultOnlineMeetingProvider, EventsFromEmailEnabled)
    } | Out-Null

    $calFolder = Invoke-DiagStep -Name 'Calendar folder statistics' -Area 'Folder' -ScriptBlock { Get-MailboxFolderStatistics -Identity $upn -FolderScope Calendar -ErrorAction Stop | Where-Object { $_.FolderType -eq 'Calendar' } | Select-Object -First 1 }
    $calPath = 'Calendar'
    if ($calFolder) {
        $calPath = $calFolder.FolderPath.TrimStart('/') -replace '/', '\'
        Add-DiagData -Section 'Calendar folder' -Data ($calFolder | Select-DiagObject -Property FolderPath, ItemsInFolder, FolderSize, NewestItemReceivedDate)
        if ([int]$calFolder.ItemsInFolder -gt 100000) { Add-DiagFinding -Severity Warning -Area 'Folder' -Title "Calendar contains $($calFolder.ItemsInFolder) items" -Detail 'Very large calendars slow down Outlook/mobile sync and room processing.' }
    }

    Invoke-DiagStep -Name 'Calendar permissions' -Area 'Permissions' -ScriptBlock {
        $perm = @(Get-MailboxFolderPermission -Identity "$($upn):\$calPath" -ErrorAction Stop)
        $rows = @($perm | ForEach-Object { [pscustomobject]@{ User = [string]$_.User; AccessRights = (@($_.AccessRights) -join ','); SharingPermissionFlags = (@($_.SharingPermissionFlags) -join ',') } })
        Add-DiagData -Section 'Calendar permissions' -Data $rows
        $def = $rows | Where-Object { $_.User -eq 'Default' } | Select-Object -First 1
        if ($def -and $def.AccessRights -eq 'None') { Add-DiagFinding -Severity Warning -Area 'Permissions' -Title 'Default calendar permission is None - colleagues cannot see free/busy' -Recommendation 'Normally AvailabilityOnly (free/busy) or LimitedDetails.' }
        $delegates = @($rows | Where-Object { $_.SharingPermissionFlags -match 'Delegate' })
        if ($delegates.Count -gt 0) { Add-DiagFinding -Severity Info -Area 'Permissions' -Title "$($delegates.Count) calendar delegate(s): $((@($delegates.User)) -join ', ')" -Detail 'Delegates receive meeting requests depending on the delegate setting in Outlook.' }
    } | Out-Null

    if ($isResource) {
        Invoke-DiagStep -Name 'Room metadata (Places) and room lists' -Area 'Room' -ScriptBlock {
            $pl = Get-Place -Identity $upn -ErrorAction Stop
            Add-DiagData -Section 'Room metadata' -Data ($pl | Select-DiagObject -Property DisplayName, Type, Capacity, Building, Floor, FloorLabel, City, CountryOrRegion, Label, Tags, IsWheelChairAccessible, AudioDeviceName, VideoDeviceName, DisplayDeviceName, MTREnabled, IsManagedPlace)
            if (-not $pl.City -or -not $pl.Building) { Add-DiagFinding -Severity Info -Area 'Room' -Title 'Room has no City/Building metadata' -Detail 'Room Finder in Outlook groups rooms by city/building; rooms without it do not show there.' }
            $lists = @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop)
            $inLists = foreach ($l in $lists) { if (@(Get-DistributionGroupMember -Identity $l.Identity -ResultSize Unlimited | Where-Object { [string]$_.PrimarySmtpAddress -eq $upn }).Count -gt 0) { [string]$l.DisplayName } }
            Add-DiagData -Section 'Room lists' -Data ([ordered]@{ RoomListsInTenant = $lists.Count; MemberOf = @($inLists) })
            if ($lists.Count -gt 0 -and @($inLists).Count -eq 0) { Add-DiagFinding -Severity Info -Area 'Room' -Title 'Room is not a member of any room list' }
        } | Out-Null
    }

    Invoke-DiagStep -Name 'Cross-org free/busy (organization relationships & sharing policy)' -Area 'Free/busy' -ScriptBlock {
        $or = @(Get-OrganizationRelationship -ErrorAction Stop)
        Add-DiagData -Section 'Organization relationships' -Data @($or | Select-DiagObject -Property Name, Enabled, DomainNames, FreeBusyAccessEnabled, FreeBusyAccessLevel, TargetAutodiscoverEpr, TargetApplicationUri)
        $sp = @(Get-SharingPolicy -ErrorAction Stop)
        Add-DiagData -Section 'Sharing policies' -Data @($sp | Select-DiagObject -Property Name, Default, Enabled, Domains)
    } | Out-Null

    if ($MeetingSubject) {
        Invoke-DiagStep -Name "Change history for meetings matching '$MeetingSubject'" -Area 'History' -ScriptBlock {
            $now = Get-Date
            $objs = @(Get-CalendarDiagnosticObjects -Identity $upn -Subject $MeetingSubject -StartDate $now.AddDays(-$Days) -EndDate $now.AddDays($Days) -ResultSize 2000 -ErrorAction Stop)
            $rows = @($objs | Sort-Object OriginalLastModifiedTime | ForEach-Object {
                    [pscustomobject]@{
                        ModifiedUtc = $_.OriginalLastModifiedTime; Action = $_.CalendarLogTriggerAction; ItemClass = $_.ItemClass; Client = $_.ClientInfoString
                        ModifiedBy = $_.LastModifiedName; From = $_.SenderEmailAddress; Start = $_.StartTime; End = $_.EndTime; ResponseType = $_.ResponseType
                        AppointmentState = $_.AppointmentState; IsCancelled = ($_.AppointmentState -band 4) -eq 4; Recurring = $_.AppointmentRecurring; MeetingId = $_.CleanGlobalObjectId; Subject = $_.NormalizedSubject
                    }
                })
            Add-DiagData -Section 'Meeting change history' -Data $rows -Description 'Each row is a version of the item. ClientInfoString shows what changed it (Outlook, OWA, mobile, Teams, Calendar Attendant "Client=CalendarRepairAssistant/ResourceBookingAssistant", delegates...).'
            if ($rows.Count -eq 0) { Add-DiagFinding -Severity Info -Area 'History' -Title 'No calendar items matched that subject in the window' }
            else {
                $meetings = @($rows.MeetingId | Select-Object -Unique).Count
                Add-DiagFinding -Severity Info -Area 'History' -Title "$($rows.Count) item version(s) across $meetings meeting(s) found" -Quiet
                foreach ($d in @($rows | Where-Object { $_.Action -match 'Delete|MoveToDeletedItems|SoftDelete|HardDelete' } | Select-Object -First 5)) { Add-DiagFinding -Severity Warning -Area 'History' -Title "Meeting deleted/moved on $($d.ModifiedUtc) via $($d.Client)" -Detail "By: $($d.ModifiedBy)" }
                foreach ($d in @($rows | Where-Object { $_.IsCancelled } | Select-Object -First 3)) { Add-DiagFinding -Severity Info -Area 'History' -Title "Cancellation recorded on $($d.ModifiedUtc) from $($d.From)" }
                $clients = @($rows | Where-Object Client | ForEach-Object { ($_.Client -split ';')[0] } | Select-Object -Unique)
                if ($clients -match 'ActiveSync|Mobile|iOS|Android') { Add-DiagFinding -Severity Info -Area 'History' -Title 'Mobile/third-party clients modified this meeting' -Detail ($clients -join ', ') -Recommendation 'Native phone calendar apps are a frequent cause of duplicated/moved/declined meetings; Outlook mobile is recommended.' }
            }
        } | Out-Null
    }
}
catch {
    Add-DiagFinding -Severity Error -Title 'Diagnostic stopped early' -Detail $_.Exception.Message -Recommendation (Get-DiagErrorHint $_.Exception.Message)
}
Complete-DiagRun -NoOpen:$NoOpen | Out-Null
