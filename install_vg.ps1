<#
=============================================================================
 ./install_vg.ps1
=============================================================================
.Description
 The install script for soft @VGrabber.
 For the correct operation of the script must be run with administrator privileges

  Developer Dmitriy L. Ivanov aka onepif
  JSC PELENG 2020
  All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

if( $BLOCK -lt 10 ){
	$GLOBAL:pVG = $jsonCFG.SMART.VGRABBER.path_to_install
	if( !$Force ){
		Write-Host
		$var = Read-Host "Specify the folder name for install VGrabber [ $pVG ]"
		if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $GLOBAL:pVG = $var } }
	}

	if( [Environment]::Is64BitOperatingSystem -and !($pVG.Contains("(x86)")) ) {
		$GLOBAL:pVG = ($pVG).ToLower().Replace("program files", "Program Files (x86)")
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "pVG=$pVG"

} else { $GLOBAL:pVG = $Data.PATH_PELENG }

$Version = $jsonCFG.SMART.VGRABBER.version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, VGrabber.[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

#if( Install-Soft "$SOFT_INST\smar-t\VGrabber_screen_$Version.zip" -Force ){
if( Install-Soft "$SOFT_INST\smar-t\VGrabber_screen_$Version.zip" ){
	$IP_BRI = @($([int]$jsonCFG.SMART.ip_base+1), $([int]$jsonCFG.SMART.ip_base+2))
	if( !$Force ){
		Write-Host
		$var = (Read-Host "Specify the IP addresses of the BRI blocks [ $IP_BRI ]")
		if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $IP_BRI = $var.Split(' ') } }
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "IP_BRI=$IP_BRI"

	$Branch = "HKCU:\Software\peleng\vgrabber"
	New-Item -Path $BRANCH -Force >$null
	New-ItemProperty -Path "$Branch" -Name "output_folder" -Value "" -Force >$null
	New-ItemProperty -Path "$Branch" -Name "output_hosts" -Value "$subNET.$stepNET.$($IP_BRI[0]) $subNET.$stepNET.$($IP_BRI[1])" -Force >$null
	New-ItemProperty -Path "$Branch" -Name "frame_rate" -PropertyType DWord -Value "2" -Force >$null
	New-ItemProperty -Path "$Branch" -Name "sv_port" -PropertyType DWord -Value "5544" -Force >$null
	New-ItemProperty -Path "$Branch" -Name "rotate" -PropertyType DWord -Value "2" -Force >$null
	New-ItemProperty -Path "$Branch" -Name "is_recording" -Value "false" -Force >$null

	Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "vgrabber" -Force *>$null
}

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
