<#
=============================================================================
	./install_tachyon.ps1
=============================================================================
.Description
	The install script for soft @Tachyon.
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

# Настройка правил Брандмауэра Windows для работы с табло...
Set-Rules 5520 5522

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install soft environment" -cr

#if( [Environment]::Is64BitOperatingSystem ){ $fNAME="vcredist_x64_2015sp3.exe" } else { $fNAME="vcredist_x86_2015sp3.exe" }
$fNAME="vcredist_x86_2015sp3.exe"
if( Test-Path -Path $SOFT_ENV\$fNAME ){ & $SOFT_ENV\$fNAME /q *>$null } else {
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "$SOFT_ENV\$fNAME not found!" -cr
}

Install-Soft "$SOFT_INST\tachyon\base.zip"

$Version = $jsonCFG.TACHYON.version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, Release.[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

Install-Soft "$SOFT_INST\tachyon\Release.$Version.zip"

$Version = $jsonCFG.TACHYON.version_snd
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of sound for installation, Sound.[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

Install-Soft "$SOFT_INST\tachyon\Sound.$Version.zip"

if( !$Force ){
	Write-Host
	choice /c ynq /n /m "Install VGrabber? [y/n]: "
	if( $LASTEXITCODE -eq 3 ){ Stop-Work } elseif( $LASTEXITCODE -eq 1 ) { .\install_vg.ps1 }
} elseif( $FLAG_VG -eq $true ){ .\install_vg.ps1 }

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
