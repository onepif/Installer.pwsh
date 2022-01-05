Set-Location (Split-Path -Path $MyInvocation.MyCommand.Path)

$pSQL = "C:\oraclexe\app\oracle\product\11.2.0\server\bin"

$pSQL\sqlplus SYSTEM/password @db_prepare.sql

$pSQL\imp master/master file=master.dmp
$pSQL\imp aero/aero file=aero.dmp

$pSQL\sqlplus master/master @db_update.sql $Args
