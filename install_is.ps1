<#
=============================================================================
	./install_is.ps1
=============================================================================
.Description
	The install script for soft @RTS.
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install soft environment" -cr

if( [Environment]::Is64BitOperatingSystem ){ $fNAME="vcredist_x64_2008sp1.exe" } else { $fNAME="vcredist_x86_2008sp1.exe" }

if( Test-Path -Path $SOFT_ENV\$fNAME ){ & $SOFT_ENV\$fNAME /q *>$null } else {
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "$SOFT_ENV\$fNAME not found!" -cr
}

Install-Soft "$SOFT_INST\is\base.zip"

$Version = $jsonCFG.Server.Version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, Release.[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

Install-Soft "$SOFT_INST\is\Release.$Version.zip"

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
