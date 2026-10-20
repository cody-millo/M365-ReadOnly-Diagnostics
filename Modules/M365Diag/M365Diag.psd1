@{
    RootModule        = 'M365Diag.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '5b7e0c1e-3f5a-4d6c-9a43-6f2a8f0d9c11'
    Author            = 'M365 Read-Only Diagnostics'
    Description       = 'Shared helpers for the M365 read-only diagnostic scripts: read-only connection guards, GET-only Graph wrapper, output sanitization, file pickers and HTML/JSON/CSV reporting.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Start-DiagRun', 'Complete-DiagRun', 'Add-DiagData', 'Add-DiagFinding', 'Invoke-DiagStep', 'Write-DiagInfo',
        'Register-DiagSensitiveValue', 'Protect-DiagText', 'Get-DiagSanitizerMap', 'New-DiagSanitizer',
        'Connect-DiagGraph', 'Invoke-DiagGraph', 'Connect-DiagExchange', 'Connect-DiagTeams', 'Connect-DiagSharePoint',
        'Assert-DiagModule', 'Get-DiagDefaultOutputRoot',
        'Select-DiagFile', 'Read-DiagValue', 'Read-DiagChoice', 'Read-DiagYesNo', 'Read-DiagIdentityList', 'Import-DiagIdentityFile',
        'ConvertTo-DiagBytes', 'ConvertTo-DiagDate', 'Format-DiagBytes', 'Select-DiagObject', 'Get-DiagEmailAddress', 'Test-DiagExternalAddress',
        'Get-DiagSignInErrorInfo', 'Get-DiagNdrInfo', 'Get-DiagErrorHint', 'Get-DiagTimeSkew'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('M365', 'Diagnostics', 'ReadOnly') } }
}
