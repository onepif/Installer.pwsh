<#
=============================================================================
	./configure_trs.ps1
=============================================================================
.SYNOPSIS
	The configuring script for soft @TRS.
	For the correct operation of the script must be run with administrator privileges

	Developer Dmitriy L. Ivanov aka onepif
	JSC PELENG 2020
	All rights reserved
.DESCRIPTION
	Quick reference on the use of the script: -d, -m {ru[X]| po[X]| dl[X]| dp[X]| ts[X]| zip[X]}"
#>

#$LIST_NAME	= @("Руководитель упражнения", "Пилот Оператор", "Дисп. РЛК", "Дисп. ПК", "Технический супервизор", "ЗИП")
$LIST_NAME	= @("Exercise leader", "Pilot Operator", "Radar Dispatcher", "Procedural Control Manager", "Technical Supervisor", "SPTA")
$LIST_ALIAS	= @("RU", "PO", "DL", "DP", "TS", "ZIP")

CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="

CMD_Dbg 2 $MyInvocation.MyCommand.Name "ip_base=$ip_base, Args: $Args"

if( $Args ){
	$GLOBAL:ALIAS_WS = $Args.ToUpper() -replace "\d$"
	$GLOBAL:NUMB_WS = $Args.ToUpper() -replace "$ALIAS_WS"
	if( !$NUMB_WS ){ $GLOBAL:NUMB_WS = 1 }
	Switch( $ALIAS_WS ){
		"RU"	{ $ws = 1; Break }
		"PO"	{ $ws = 2; Break }
		"DL"	{ $ws = 3; Break }
		"DP"	{ $ws = 4; Break }
		"TS"	{ $ws = 5; Break }
		"ZIP"	{ $ws = 6; Break }
	}
} else {
	Write-Host
	"Select mode WS:"; "  1 - Exercise leader"; "  2 - Pilot Operator"; "  3 - Radar Dispatcher"; "  4 - Procedural Control Manager"; "  5 - Technical Supervisor"; "  6 - SPTA"
	choice /c 123456q /n /m "?: "
	$GLOBAL:ws = $LASTEXITCODE
	if( $ws -eq 7 ){ Stop-Work }
	Write-Host
	$GLOBAL:NUMB_WS = Read_Host -Prompt "Specify the number WS [1..5]"
    if(($NUMB_WS -gt 0) -and ($NUMB_WS -lt 6)){
        $GLOBAL:ALIAS_WS = $LIST_ALIAS[$ws-1]
	   $GLOBAL:NAME_WS = $LIST_NAME[$ws-1]
    } else {
        Stop-Work 
    }
}

if( ($ws -eq 1) -or ($ws -ge 5) ){ Rename-PC "BS-$ALIAS_WS" } else { Rename-PC "BS-$ALIAS_WS$NUMB_WS" }
Rename-Lan $($([int]$ws - 1) * 10 + $ip_base + $NUMB_WS)

Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Configuring DPI... "
$Branch = "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers\ScaleFactors\CMN15C50_03_07DE_C4^B87E39C17B9D3B50DE4BD4E519D81377"
New-Item -Path $Branch -Force *>$null
New-ItemProperty -Path $Branch -Name "DpiValue" -PropertyType DWord -Value 2 *>$null
if( $? ){ CMD_Ok } else { CMD_Err }

$Branch = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$strSID\Control Panel\Desktop\PerMonitorSettings\CMN15C50_03_07DE_C4^B87E39C17B9D3B50DE4BD4E519D81377"
New-Item -Path $Branch -Force >$null
New-ItemProperty -Path $Branch -Name "DpiValue" -PropertyType DWord -Value 0 *>$null
if( $? ){ CMD_Ok } else { CMD_Err }

$Branch = "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$strSID\Control Panel\Desktop\WindowMetrics"
New-Item -Path $Branch -Force >$null
New-ItemProperty -Path $Branch -Name "AppliedDPI" -PropertyType DWord -Value 134 *>$null
if( $? ){ CMD_OkCr } else { CMD_ErrCr }

CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
