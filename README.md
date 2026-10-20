# M365 Read-Only Diagnostics

Read-only, sanitized PowerShell troubleshooting scripts for Microsoft 365. They collect back-end diagnostics first, flag the usual root causes in plain language, and write a shareable report. **No script changes anything in Microsoft 365 or on the PC.**

```
Double-click  Start-M365Diag.cmd   ->  pick a service  ->  pick a script  ->  answer the prompts
```

Every run produces `Reports\<timestamp>_<Script>\report.html` (opens automatically), plus `report.json`, `00_Findings.csv` and one CSV per data section.

---

## Quick start

1. **Get the files.** Use `git clone` (recommended), or download the ZIP. If you used the ZIP, run `Unblock-M365Diag.cmd` once.
2. **Run `Start-M365Diag.cmd`.** It starts Windows PowerShell 5.1 with the `RemoteSigned` execution policy for that process only.
3. Press **P** to check prerequisites. Missing modules can be installed per user after you confirm each one.
4. Pick a category and a script. Scripts ask for what they need. When a script needs a file (a CSV of users, an `.eml`, a sign-in export), a standard Windows **file picker** opens.

Run any script directly if you prefer:

```powershell
.\Scripts\Exchange\Get-MailboxDiagnostics.ps1 -Identity jane@contoso.com
.\Scripts\EntraID\Get-UserSignInDiagnostics.ps1 -UserPrincipalName jane@contoso.com -Days 3 -IncludeNonInteractive
.\Scripts\Tenant\Test-DomainDnsRecords.ps1 -Domain contoso.com -DnsServer 8.8.8.8
```

Common switches on every diagnostic script: `-NoSanitize` (raw output), `-OutputPath <folder>` and `-NoOpen` (don't open the HTML).

---

## Script catalog

| Area | Script | Answers | Connection | Minimum role |
|---|---|---|---|---|
| **Tenant** | `Get-TenantHealthOverview` | Is it Microsoft? Active incidents and advisories, service health, licenses (suspended or over-assigned), domains, sync freshness | Graph | Global Reader / Message Center Reader |
| | `Test-DomainDnsRecords` | MX, SPF (with the 10-lookup count), DKIM, DMARC, Autodiscover, Teams SRV, Intune CNAMEs, MTA-STS | none | none |
| | `Search-AuditLogActivity` | Who did what: presets for deleted files, inbox rules/forwarding, mailbox permissions, sharing, Teams membership, admin roles | Exchange | View-Only Audit Logs |
| **Entra ID** | `Get-UserSignInDiagnostics` | Can't sign in or keeps prompting: account state, decoded sign-in errors, failed CA policies, MFA methods, risk, licenses, devices | Graph | Global Reader (sign-in logs need Entra ID P1) |
| | `Get-ConditionalAccessReport` | Every CA policy in plain language, recent changes, missing legacy-auth block, which policies target a user | Graph | Global Reader / Security Reader |
| | `Get-LicensingDiagnostics` | License errors (users and groups), plans stuck in PendingInput/Error, no usage location | Graph | Global Reader / License Admin |
| | `Get-DirectorySyncHealth` | Entra Connect last sync, features, provisioning conflicts (duplicate proxy address/UPN), one user's sync state | Graph | Global Reader |
| | `Get-SignInExportAnalysis` | *Offline:* analyzes a portal sign-in export for spray, MFA fatigue, legacy auth and top errors (file picker) | none | none |
| **Exchange** | `Get-MailboxDiagnostics` | Quota, Recoverable Items, holds, archive, forwarding, hidden/suspicious inbox rules, delegates, protocols, mobile devices, migration. Single mailbox or bulk via CSV | Exchange | Global Reader / View-Only Org Mgmt |
| | `Get-MessageTraceReport` | Where is my email: trace V2 with NDR decoding, detail events, quarantine | Exchange | Global Reader |
| | `Get-MailFlowConfiguration` | Blocked senders, connectors, transport rules, DKIM, forwarding policy, anti-spam/phish, SMTP AUTH, modern auth | Exchange | Global Reader / Security Reader |
| | `Get-CalendarDiagnostics` | Room booking policies, calendar permissions, room lists, meeting change history (who or what changed it) | Exchange | Global Reader |
| | `Get-MessageHeaderAnalysis` | *Offline:* hop delays, SPF/DKIM/DMARC/CompAuth, SCL/SFV/CAT/BCL decoded (picker for .eml/.txt/.msg, or paste) | none | none |
| **Teams** | `Get-TeamsUserDiagnostics` | License feature types, coexistence mode, policies, phone number, Enterprise Voice, forwarding, voicemail | Teams | Global Reader / Teams Comms Support |
| | `Get-TeamsTeamDiagnostics` | Owners/members/guests, archived, channels; or a tenant scan for ownerless teams | Teams | Global Reader |
| | `Get-TeamsTenantConfiguration` | Federation, guest access, meeting/messaging/app/channel policies, upgrade mode | Teams | Global Reader |
| | `Get-TeamsPhoneDiagnostics` | SBCs, routes, usages and policies (broken references), dial plans, call queues, auto attendants, resource accounts, offline route test | Teams | Global Reader |
| **SharePoint/OneDrive** | `Get-SharePointSiteDiagnostics` | Locked/read-only, storage, sharing, group/hub/label/archive, admins; recycle bin if the site is missing | SPO shell | SharePoint Admin* |
| | `Get-OneDriveUserDiagnostics` | Provisioned or not, locked, full, deleted, who has admin access (bulk via CSV) | SPO shell | SharePoint Admin* |
| | `Get-SharePointTenantSettings` | Tenant sharing, unmanaged devices, legacy auth, IP restrictions, sync restrictions, storage, locked or full sites | SPO shell | SharePoint Admin* |
| **Intune/Devices** | `Get-DeviceDiagnostics` | Compliance with the exact failing settings, check-in, profile errors/conflicts, Entra join state, duplicates, Autopilot | Graph | Global Reader / Intune Read Only Operator |
| **This PC** | `Get-LocalEntraJoinStatus` | Join/hybrid state, PRT (SSO) health, Windows Hello, MDM enrollment, IME, clock skew | none | run as the affected user |
| | `Get-M365AppsClientDiagnostics` | Office channel/version, WAM and identity overrides, Outlook profiles/OST/Autodiscover, Teams add-in, OneDrive KFM | none | run as the affected user |
| | `Test-M365NetworkConnectivity` | DNS, TCP 443 latency, TLS inspection detection, proxy/PAC per URL, Teams UDP 3478 (STUN) | none | none |
| **Tools** | `ConvertTo-SanitizedFile` | Pseudonymize any log/CSV/JSON/header file before sharing (file picker, multiple files) | none | none |

\* The SharePoint Online Management Shell does not support Global Reader.

**Recommended:** run the tenant scripts with a **Global Reader** account. That role cannot change anything, so it guarantees read-only access on its own, independent of this code.

---

## How read-only is guaranteed

1. **Microsoft Graph:** all calls go through `Invoke-DiagGraph`, which has no method parameter and always sends `GET`. `Connect-DiagGraph` refuses any scope that isn't `*.Read`, `*.Read.All` or `*.ReadBasic.All`. No POST-based APIs are used (no What-If, batch or audit-query jobs).
2. **Exchange Online:** sessions are opened with `Connect-ExchangeOnline -CommandName <list>`, and the list may only contain `Get-*` and `Search-*` cmdlets. Write cmdlets don't exist in the session at all.
3. **Teams / SharePoint:** scripts only call `Get-Cs*`, `Get-Team*` and `Get-SPO*`.
4. **Static check (CI):** `Tests\Test-ToolkitSafety.ps1` parses every script. It fails the build on any non-read verb (Set/New/Remove/Add/Update/Grant/...), a non-GET Graph call, a write Graph scope, aliases, or EDR-flagged constructs (see below). It runs on every push via GitHub Actions.
5. **Local writes:** only the report files under `Reports\`. The single exception is the opt-in module installer (`Scripts\Setup\Install-DiagPrerequisites.ps1`), which asks before each module and installs per user.

Things the scripts deliberately do **not** do, even though they're read operations: read BitLocker keys, LAPS passwords, credential stores, tokens or license files, or message bodies.

---

## AV/EDR friendliness

The toolkit avoids the behaviors endpoint protection scores as malicious:

- no `-ExecutionPolicy Bypass`, `-EncodedCommand` or hidden windows. The launcher uses `RemoteSigned` for its own process only.
- no `Invoke-Expression`, base64 decoding, web downloads, reflection loading, inline C# (`Add-Type -TypeDefinition`), COM automation (e.g. Outlook), or `Start-Process`
- no credential stores or browser data, no persistence (tasks, services, registry run keys)
- full cmdlet names only (no aliases), plain ASCII files
- network tests target a fixed list of Microsoft endpoints one at a time (no scanning). The only UDP traffic is one STUN request to the Teams relay.

**Expected telemetry** (benign, but your EDR may log it): `dsregcmd /status` and `netsh winhttp show proxy` (local client scripts), TLS handshakes to Microsoft 365 endpoints, and module imports for Graph/Exchange/Teams/SPO. If your EDR uses script allow-listing, sign the scripts with your code-signing certificate and run with `AllSigned`.


---

## Sanitization (on by default)

Before anything is written to disk, reports pass through a **consistent pseudonymizer**. The same real value always gets the same token, so you can still correlate:

| Data | Becomes |
|---|---|
| UPNs / emails | `user001@domain01.example` |
| Tenant/custom domains, `contoso.onmicrosoft.com`, `contoso.sharepoint.com` | `domain01.example`, `tenant01.onmicrosoft.com`, `tenant01.sharepoint.com` |
| Display names and other person fields (on user/recipient objects) | `Name001` |
| Device/computer names, proxy hosts | `host001` |
| IPv4 / IPv6 | `public-ip-001` / `private-ip-001` / `ipv6-001` |
| Object/tenant GUIDs, SIDs, phone numbers | `00000000-0000-0000-0000-000000000001`, `S-1-5-21-REDACTED-1`, `+15550000001` |
| Mail subjects, message text, immutable IDs | `[redacted]` |

What stays readable on purpose: SKU/service-plan IDs, **correlation and request IDs** (Microsoft support needs them), Microsoft server names, versions, error codes, policy names.

The private reverse map is written to `Reports\_private-maps\<run>.map.json`, **outside** the report folder, so you can zip and share the report folder safely. Keep the map internal.

Turn sanitization off with **S** in the launcher or `-NoSanitize` (raw data, internal use only). Note that the console shows live values while a script runs; only files on disk are sanitized.

---

## Prerequisites

- Windows 10/11 or Server 2016+, **Windows PowerShell 5.1** (PowerShell 7 also works. File pickers need an STA console; otherwise you type the path.)
- Modules, installed only for the services you use (launcher option **P**):
  - `Microsoft.Graph.Authentication` 2.x (Tenant, Entra ID, Intune). The first sign-in may ask an admin to consent the read scopes for "Microsoft Graph Command Line Tools".
  - `ExchangeOnlineManagement` 3.2+ (Exchange, audit log)
  - `MicrosoftTeams` 5+ (Teams)
  - `Microsoft.Online.SharePoint.PowerShell` (SharePoint/OneDrive)
- Offline and local scripts need no modules.

## Troubleshooting the toolkit

| Symptom | Fix |
|---|---|
| "running scripts is disabled" / "not digitally signed" | Run `Unblock-M365Diag.cmd` once (ZIP downloads), or clone with git. If GPO enforces AllSigned, sign the scripts. |
| `Could not load file or assembly Microsoft.Identity.Client` | Graph and Exchange/Teams modules loaded different MSAL versions in one session. Close the window and run that script from a fresh launcher. |
| Sign-in log sections empty / 403 | The tenant needs Entra ID P1 for sign-in logs (P2 for risk), and the account needs Reports Reader / Security Reader / Global Reader. |
| SharePoint scripts fail to connect | The SPO shell requires the SharePoint Administrator role; MFA prompts appear in a separate window. |

## Repository layout

```
Start-M365Diag.cmd / .ps1     launcher (menu)
Unblock-M365Diag.cmd          one-time unblock for ZIP downloads
Modules\M365Diag\             shared module: guards, GET-only Graph, sanitizer, file picker, HTML/JSON/CSV report
Scripts\<Service>\*.ps1       one script per common issue, grouped by service
Scripts\Setup\                prerequisite checker/installer (opt-in)
Tests\Test-ToolkitSafety.ps1  static read-only / EDR safety check (CI)
Reports\                      output (git-ignored)
```

## Adding a script

Copy any script in `Scripts\<Service>`, keep the comment-based help (`.SYNOPSIS`, plus `Connection :` and `Roles :` in `.NOTES`, which the launcher shows), and use the module helpers (`Start-DiagRun`, `Invoke-DiagStep`, `Add-DiagData`, `Add-DiagFinding`, `Complete-DiagRun`). Run `.\Tests\Test-ToolkitSafety.ps1` before committing.
