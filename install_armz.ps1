<#
=============================================================================
	./install_armz.ps1
=============================================================================
.Description
	The install script for soft @SMAR-T [ARMz].
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>
# ==============================================================================

Function Run-Configure(){
	$Branch = "HKLM:\SOFTWARE\peleng\recorder\Complect"
	New-Item -Path $Branch -Force >$null
	New-ItemProperty -Path "$Branch" -Name "ComplectNumber" -Value (($BLOCK-1)%2+1) -Force >$null

	$Branch = "HKLM:\SOFTWARE\peleng\recorder\Network"
	New-Item -Path $Branch -Force >$null
	New-ItemProperty -Path "$Branch" -Name "LocalIP" -Value (`
		"$('{0:X2}' -f [int]$subNET.Split('.')[0])"	+
		"$('{0:X2}' -f [int]$subNET.Split('.')[1])"	+
		"$('{0:X2}' -f [int]$stepNET*2)"			+
		"$('{0:X2}' -f [int]$($ip_base+$BLOCK))") -Force >$null

	New-ItemProperty -Path "$Branch" -Name "RemoteIP" -Value (`
		"$('{0:X2}' -f [int]$subNET.Split('.')[0])"	+
		"$('{0:X2}' -f [int]$subNET.Split('.')[1])"	+
		"$('{0:X2}' -f ([int]$stepNET*2))"			+
		"$('{0:X2}' -f  [int]$($ip_base+[Math]::Truncate($BLOCK/3)*2+$BLOCK%2+1))") -Force >$null

	$Branch = "HKLM:\SOFTWARE\peleng\recorder\Storages"
	New-Item -Path $Branch -Force >$null
	$var = $jsonCFG.SMART.Recorder.path_to_gnrl
	New-ItemProperty -Path "$Branch" -Name "GeneralStoragePath" -Value $var -Force >$null
	if( !(Test-Path -Path $var) ) { New-Item -type Directory -Path $var -Force *>$null }
	$var = $jsonCFG.SMART.Recorder.path_to_arch
	New-ItemProperty -Path "$Branch" -Name "ArchiveStoragePath" -Value $var -Force >$null
	if( !(Test-Path -Path $var) ) { New-Item -type Directory -Path $var -Force *>$null }
}
# ==============================================================================
CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

if( $WINVER -eq 6 ){
	label c:System *>$null
	label d:Data *>$null
} else {
	Set-Volume -DriveLetter "C" -NewFileSystemLabel "System" *>$null
	Set-Volume -DriveLetter "D" -NewFileSystemLabel "Data" *>$null
}

$Version = $jsonCFG.SMART.Recorder.version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, setup_armz_[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

if( Install-Soft "$SOFT_INST\smar-t\setup_armz_$Version.zip" -Force ){ Remove-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -Name "ARMZ" -Force *>$null }

if( !$Force ){
	Write-Host
	choice /c ynq /n /m "Run configuring section? [y/n]: "
	if( $LASTEXITCODE -eq 3 ){ Stop-Work } elseif( $LASTEXITCODE -eq 1 ) { Run-Configure }
} else { Run-Configure }

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
# ==============================================================================
