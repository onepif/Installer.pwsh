CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="

# Установка Notepad++, Sumatra
$ver = $jsonCFG.npp_version		# "7.8.6"
if( [Environment]::Is64BitOperatingSystem ){ $fNAME = "Installer.x64" } else { $fNAME = "Installer" }
Start-Process "$SOFT_ENV\npp.$ver.$fNAME.exe" /S

$ver = $jsonCFG.sumatra_version		# "3.1.2"
if( [Environment]::Is64BitOperatingSystem ){
	Expand-Archive -LiteralPath $SOFT_ENV\SumatraPDF-${ver}-64.zip -Destination "$env:PROGRAMFILES" -Force
} else {
	Expand-Archive -LiteralPath $SOFT_ENV\SumatraPDF-${ver}.zip -Destination "$env:PROGRAMFILES" -Force
}
if( !(Test-Path ("$env:PROGRAMFILES\OpenSSH")) ){
	if( !$Force ){
		Write-Host
		choice /c ynq /n /m "Install OpenSSH? [Y/n]: "
		if( $LASTEXITCODE -eq 3 ){ Stop-Work }
		if( $LASTEXITCODE -eq 1 ){
			if( [Environment]::Is64BitOperatingSystem ){ $fNAME = "OpenSSH-Win64" } else { $fNAME = "OpenSSH-Win32" }

			Expand-Archive -LiteralPath $SOFT_ENV\sys\ssh\$fNAME.zip -Destination "$env:PROGRAMFILES" -Force
			Rename-Item -Path "$env:PROGRAMFILES\$fNAME" -NewName OpenSSH >$null

			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value "$env:PROGRAMFILES\OpenSSH;$env:PATH" >$null

			Push-Location
			Set-Location "$env:PROGRAMFILES\OpenSSH"
			.\install-sshd.ps1
            Write-Host `n`n >empty.txt
			cat empty.txt|.\ssh-keygen.exe
            Remove-Item empty.txt
			Set-Service -Name sshd -StartupType Automatic -Status Running
			Pop-Location
		}
	}
}

CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"

<#
	ip_bri="131 132 133 134"
	ip_bvi="135 136"
	ip_bvz="141 142 143 144"

	for ix in $ip_bri $ip_bvi $ip_bvz; do ssh User@192.168.10.$ix "echo $(cat ~/.ssh/id_rsa.pub) >>c:/Users/User/.ssh/authorized_keys"; done
#>
