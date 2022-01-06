@echo off

cd /d %~dp0

net user %USERNAME% /time:all 2>nul >nul
if not %errorlevel% == 0 (
	if "%*" == "" (
		powershell Start-Process .\run.cmd -Verb RunAs
	) else (
		powershell Start-Process .\run.cmd -Verb RunAs -ArgumentList %*
	)
	exit 0
)

powershell -Command Set-ExecutionPolicy RemoteSigned

powershell ..\install_wmf.ps1 %*

powershell ..\install_ps7.ps1

"C:\Program Files\PowerShell\7\pwsh.exe" ..\Run-Installer.ps1 -I 2 -B 1 -Force
::%*
