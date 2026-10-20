@echo off
rem Removes the "downloaded from the internet" mark (Zone.Identifier) from the files in THIS folder only,
rem so the RemoteSigned execution policy allows them to run. Not needed if you cloned with git.
echo This removes the internet download mark from the toolkit files in:
echo   %~dp0
set /p ok=Continue? [y/N]
if /i not "%ok%"=="y" goto :eof
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Get-ChildItem -LiteralPath '%~dp0.' -Recurse -File | Unblock-File; Write-Host 'Done.'"
pause
