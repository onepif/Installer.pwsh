[CmdletBinding()]
Param(
	[Parameter(Mandatory = $true)]
    [string]$sectors,

	[Parameter(Mandatory = $true)]
    [string]$runways
)

Set-Location "$($Data.PATH_PELENG)\configDB"

$env:PATH += "C:\oraclexe\app\oracle\product\11.2.0\server\bin"

sqlplus.exe SYSTEM/password "@db_prepare.sql"

imp.exe master/master file=master.dmp
imp.exe aero/aero file=aero.dmp

sqlplus.exe master/master "@db_update.sql" "$sectors" $runways.split()
