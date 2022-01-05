<#
=============================================================================
	./install_armv.ps1
=============================================================================
.Description
	The install script for soft @SMAR-T [ARMv].
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

$Version = $jsonCFG.SMART.Player3.version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, setup_armv_[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

if( Install-Soft "$SOFT_INST\smar-t\setup_armv_$Version.zip" -Force ){
	"[paths]"|Out-File "$($Data.PATH_PELENG)/config.ini"
	"size=2"|Out-File -Append "$($Data.PATH_PELENG)/config.ini"
	"1\path=//$($jsonCFG.subNET).$($jsonCFG.stepNET).$($jsonCFG.SMART.ip_base+1)"|Out-File -Append "$($Data.PATH_PELENG)/config.ini"
	"1\islast=false"|Out-File -Append "$($Data.PATH_PELENG)/config.ini"
	"2\path=//$($jsonCFG.subNET).$($jsonCFG.stepNET).$($jsonCFG.SMART.ip_base+2)"|Out-File -Append "$($Data.PATH_PELENG)/config.ini"
	"2\islast=false"|Out-File -Append "$($Data.PATH_PELENG)/config.ini"
}

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
