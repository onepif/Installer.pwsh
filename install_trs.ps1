<#
=============================================================================
	./install_trs.ps1
=============================================================================
.Description
	The install script for soft @TRS.
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
#>

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

# ru, po, dl, dp, ts, zip
$LIST = @( "ru", "po1", "dl1", "dl2", "zip" )

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install TRS pack... "

foreach( $ix in (Get-ChildItem -Path $SOFT_INST\tdk\*.zip).Name ){ Install-Soft "$SOFT_INST\tdk\$ix" }
CMD_EMPTY

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Make scripts... "
foreach( $ix in $LIST ){
	Set-Content -Path "$($Data.PATH_PELENG)\etc\rc.d\set_host_$ix.cmd" -Value "cd /d %%~dp0"
	Add-Content -Path "$($Data.PATH_PELENG)\etc\rc.d\set_host_$ix.cmd" -Value "set_host.cmd -m $ix"
}
CMD_DnCr

Set-Shared -u "pilot" -p "pilot" -d "$($Data.PATH_PELENG)" -s "trs"
if( !(Test-Path -Path "$($Data.PATH_PELENG)\rec") ) { New-Item -type Directory -Path "$($Data.PATH_PELENG)\rec" -Force *>$null }
Set-Shared -u "pilot" -p "pilot" -d "$($Data.PATH_PELENG)\rec" -s "rec"

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
