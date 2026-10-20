@echo off
rem M365 Read-Only Diagnostics launcher.
rem Uses Windows PowerShell 5.1 (best compatibility for SharePoint module and file pickers).
rem Execution policy is set to RemoteSigned for this process only (no system change, no "Bypass").
title M365 Read-Only Diagnostics
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Start-M365Diag.ps1" %*
if errorlevel 1 (
  echo.
  echo If PowerShell refused to run the scripts because they were downloaded from the internet,
  echo run Unblock-M365Diag.cmd once, then start this launcher again.
  pause
)
