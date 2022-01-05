<# Embedding Management Scripts #>

"if( (Get-Service w32time).Status -eq 'Running' ) { Set-Service -InputObject w32time -Status Stopped; Sleep 4 }" >$env:WINDIR\w32time.ps1
"Set-Service -InputObject w32time -Status Running" >>$env:WINDIR\w32time.ps1

"Remove-Item -Recurse -Path `"$($Data.TMP)`" -Force *>`$null" >>$env:WINDIR\w32time.ps1
"New-Item -ItemType Directory -Path `"$($Data.TMP)`" -Force *>`$null" >>$env:WINDIR\w32time.ps1

Copy-Item .\Share\reboot.ico -Destination $env:WINDIR *>$null
Copy-Item .\Share\coverPeleng.jpg -Destination $env:WINDIR\Web\Wallpaper\Windows\img1.jpg *>$null

Set-Content -Path $env:WINDIR\reboot.cmd	-Value "shutdown /r /t 1"
Set-Content -Path $env:WINDIR\poweroff.cmd	-Value "shutdown /s /t 1"
Set-Content -Path $env:WINDIR\rst.cmd		-Value "$env:PROGRAMFILES\Intel\Intel(R) Rapid Storage Technology\IAStorUI.exe"

Set-Content -Path $env:WINDIR\stopSS.ps1	-Value "rc.SS.ps1 stop"
Set-Content -Path $env:WINDIR\restartSS.ps1	-Value "rc.SS.ps1 restart"

Set-Content -Path $env:WINDIR\run_as_switch.ps1		-Value "Set-AsRun 3"
Set-Content -Path $env:WINDIR\run_as_desktop.ps1	-Value "Set-AsRun 1"
Set-Content -Path $env:WINDIR\run_as_programm.ps1	-Value "Set-AsRun 2"
