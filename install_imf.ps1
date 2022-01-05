<#
=============================================================================
	./install_imf.ps1
=============================================================================
.Description
	The install script for soft @IMF.
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

if( [Environment]::Is64BitOperatingSystem ){ & $SOFT_ENV\vlc-3.0.11-win64.exe /S } else { & $SOFT_ENV\vlc-3.0.11-win32.exe /S }

Install-Soft "$SOFT_INST\imf\Imitator.zip" "$($Data.PATH_PELENG)\Imitator"
Install-Soft "$SOFT_INST\imf\E1SS.zip" "$($Data.PATH_PELENG)\E1SS"
Install-Soft "$SOFT_INST\imf\YourSender.zip" "$($Data.PATH_PELENG)\YourSender"
Install-Soft "$SOFT_INST\imf\mSocUDP.zip" "$($Data.PATH_PELENG)\mSocUDP"
Install-Soft "$SOFT_INST\smar-t\VGrabber_screen_$($jsonCFG.SMART.VGRABBER.version).zip" "$($Data.PATH_PELENG)\VGrabber"
Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install Master" -cr
Install-Soft "$SOFT_INST\master\base.zip" "$($Data.PATH_PELENG)\Master"
Install-Soft "$SOFT_INST\master\Release.$($jsonCFG.MASTER.version).zip" "$($Data.PATH_PELENG)\Master"

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
