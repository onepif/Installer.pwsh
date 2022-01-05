@echo off

powershell -Command Set-ExecutionPolicy RemoteSigned

cd /d %~dp0

powershell ..\install_wmf.ps1

powershell ..\install_ps7.ps1

"C:\Program Files\PowerShell\7\pwsh.exe" ..\Run-Installer.ps1 %*
