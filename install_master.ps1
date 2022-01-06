<#
=============================================================================
	./install_master.ps1
=============================================================================
.Description
	The install script for soft @Master.
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install soft environment" -cr

$fNAME="vcredist_x86_2008sp1.exe"

if( Test-Path -Path $SOFT_ENV\$fNAME ){ & $SOFT_ENV\$fNAME /q *>$null } else {
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "$SOFT_ENV\$fNAME not found!" -cr
}

#& sc query OracleXETNSListener *>$null
#if( $LASTEXITCODE -eq 1060 ){
if( !(Get-Service |Where-Object {$_.Name -eq "OracleXETNSListener"}) ){

#	if( Install-Soft "$SOFT_ENV\OracleXE112_Win_x86.zip" "$($Data.TMP)" -Force ){
	if( !(Install-Soft "$SOFT_ENV\OracleXE112_Win_x86.zip" "$($Data.TMP)") ){
		if( Test-Path -Path C:\oraclexe ) { Remove-Item -Recurse -Path C:\oraclexe }
		Set-Content -Path "$($Data.TMP)\DISK1\response\OracleXE-install.iss" -Value ((Get-Content "$($Data.TMP)\DISK1\response\OracleXE-install.iss") -Replace "SYSPassword=.*", "SYSPassword=password")
		Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Run install OracleXE Database in parallel process" -cr
		Remove-Item -Path "$($Data.TMP)\DISK1\setup.log" *>$null
		$app = $($Data.TMP).Replace("\", "\\") + "\\DISK1\\setup.exe"
#		& $app /S -f1"$($Data.TMP)\DISK1\response\OracleXE-install.iss"
		& $app -f1"$($Data.TMP)\DISK1\response\OracleXE-install.iss"
	}
} else {
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t w -m "OracleXE database allready installed" -cr
	$FLAG_INST_ORACLE = $true
}

Install-Soft "$SOFT_INST\master\Base.zip"

$Version = $jsonCFG.MASTER.version
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify the build number of software for installation, Release.[ $Version ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

Install-Soft "$SOFT_INST\master\Release.$Version.zip"

$Sound = $jsonCFG.MASTER.sound
if( !$Force ){
	Write-Host
	"Specify the sound scheme:"; "  Notify - 1"; "  Ivona  - 2"; "  Valera - 3"
	choice /c 123q /n /m "?: "
	$Sound = $LASTEXITCODE
	if( $Sound -eq 4 ){ Stop-Work }
}

if( Install-Soft "$SOFT_INST\master\Sound.zip" -Force ){
	Switch( $Sound ){
		"1" { $name_sheme = "Notify"; Break }
		"2" { $name_sheme = "Ivona"; Break }
		Default { $name_sheme = "Valera" }
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "Choice sheme $name_sheme"
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Sound sheme '$name_sheme' [code: $Sound] copy... "
	Move-Item -Path "$($Data.PATH_PELENG)\wav\wav_${name_sheme}\*.wav" -Destination "$($Data.PATH_PELENG)" -Force *>$null
	if( $? ){ CMD_Ok } else { CMD_Err }
	Remove-Item -Recurse -Path "$($Data.PATH_PELENG)\wav" -Force *>$null
	if( $? ){ CMD_OkCr } else { CMD_ErrCr }
}

$GLOBAL:FLAG_HOTR = $jsonCFG.MASTER.hot_reserv
if( !$Force ){
	Write-Host
	choice /c ynq /n /m "Install 'Hot Reserv'? [y/n]: "
	if( $LASTEXITCODE -eq 3 ){ Stop-Work } elseif( $LASTEXITCODE -eq 2 ) { $GLOBAL:FLAG_HOTR = $false } else { $GLOBAL:FLAG_HOTR = $true }
}
CMD_Dbg 2 $MyInvocation.MyCommand.Name "FLAG_HOTR=$FLAG_HOTR"

if( $FLAG_HOTR -eq $true ) {
	$IP_DBL_BLOCK = $($([int]$ip_base+1) + $($($BLOCK+2)%2))
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "ip_base=$ip_base; BLOCK=$BLOCK; IP_DBL_BLOCK=$IP_DBL_BLOCK"

	$GLOBAL:pDBS = $jsonCFG.DBSYNC.path_to_install
	if( !$Force ){
		Write-Host
		$var = Read-Host "Specify the folder name for install DBsync [ $pDBS ]"
		if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $GLOBAL:pDBS = $var } }
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "pDBS=$pDBS"

	$Version = $jsonCFG.DBSYNC.version
	if( !$Force ){
		Write-Host
		$var = Read-Host "Specify the build number of DBsync.[ $Version ]"
		if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Version = $var } }
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "Version=$Version"

	if( Install-Soft "$SOFT_INST\master\DBsync.$version.zip" "$pDBS" -Force ){
		Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Run command sed for editing config.xml... "
		$xmlDBS = (Get-Content $pDBS\config.xml -Encoding UTF8) -Replace "<Connect2>.*", "<Connect2>DRIVER=Microsoft ODBC for Oracle;DSN=;UID=aero;PWD=aero;Server=$subNET.$stepNET.$IP_DBL_BLOCK/xe</Connect2>"
		Set-Content -Path $pDBS\config.xml -Value $xmlDBS
		if( $? ){ CMD_OkCr } else { CMD_ErrCr }
	}
} else { Remove-Variable FLAG_HOTR -Force 2>$null}

if( !$Force ){
	Write-Host
	choice /c ynq /n /m "Install VGrabber? [y/n]: "
	if( $LASTEXITCODE -eq 3 ){ Stop-Work } elseif( $LASTEXITCODE -eq 1 ) { .\install_vg.ps1 }
} elseif( $jsonCFG.MASTER.install_vg -eq $true ){ .\install_vg.ps1 }

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
