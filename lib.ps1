function Set-Color {
	(Get-Host).PrivateData.ErrorForegroundColor		= "Red"
	(Get-Host).PrivateData.ErrorBackgroundColor		= "Black"
	(Get-Host).PrivateData.WarningForegroundColor	= "Yellow"
	(Get-Host).PrivateData.WarningBackgroundColor	= "Black"
	(Get-Host).PrivateData.DebugForegroundColor		= "Magenta"
	(Get-Host).PrivateData.DebugBackgroundColor		= "Black"
	(Get-Host).PrivateData.VerboseForegroundColor	= "Yellow"
	(Get-Host).PrivateData.VerboseBackgroundColor	= "Black"
	(Get-Host).PrivateData.ProgressForegroundColor	= "Yellow"
	(Get-Host).PrivateData.ProgressBackgroundColor	= "DarkGray"

	(Get-Host).UI.RawUI.ForegroundColor				= "DarkGray"
	(Get-Host).UI.RawUI.BackgroundColor				= "Black"
	(Get-Host).UI.RawUI.CursorSize					= 15
}

Function Out-Logging(){
<#
.SYNOPSIS
	The initial configuration script windows.
	For the correct operation of the script must be run with administrator privileges
.DESCRIPTION
	Использование: Out-Logging [args]
	[args] могут принимать следующие значения:
.PARAMETER	-D [1^|..] : включить отладочный режим. Будет производится вывод дополнительной информации;
#>
	[CmdletBinding()]
	Param(
		[Switch]$empty,	[Switch]$ok, [Switch]$er, [Switch]$dn, [Switch]$cr, [Switch]$sk ,

		[Alias('t')]
		[string]$TYPE	= "INFO",

		[string]$SRC	= "Out-Logging",
		[Alias('m')]

		[string]$MSG,

		[Alias('out')]
		[string]$FILE
	)

	Switch( $TYPE ){
		{$_[0] -eq "w"}	{ $TYPE	= "WARNING";	Break }
		{$_[0] -eq "e"}	{ $TYPE	= "ERROR";		Break }
		{$_[0] -eq "d"}	{ if( $_[1] -eq $null ){ $TYPE = "DEBUG LVL 1" } else { $TYPE = "DEBUG LVL $($_[1])" }
						  Break
						}
		Default 		{ $TYPE = $_.ToUpper() }
	}

	if( $empty ){
		Function CMD_Out-Logging{ Write-Host }
		Function CMD_Out-LogFile{ ''|Out-File -Append $FILE}
	} elseif( $ok ){
		if( $cr ){
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Green -noNewLine 'OK'; Write-Host ' ]'
			}
			Function CMD_Out-LogFile{ '[ OK ]'|Out-File -Append $FILE }
		} else {
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Green -noNewLine 'OK'; Write-Host -noNewLine ' ]'
			}
			Function CMD_Out-LogFile{ '[ OK ]'|Out-File -noNewLine -Append $FILE }
		}
	} elseif( $er ){
		if( $cr ){
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Red -noNewLine 'ERROR'; Write-Host ' ]'
			}
			Function CMD_Out-LogFile{ '[ ERROR ]'|Out-File -Append $FILE }
		} else {
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Red -noNewLine 'ERROR'; Write-Host -noNewLine ' ]'
			}
			Function CMD_Out-LogFile{ '[ ERROR ]'|Out-File -noNewLine -Append $FILE }
		}
	} elseif( $dn ){
		if( $cr ){
			Function CMD_Out-Logging {
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor White -noNewLine 'DONE'; Write-Host ' ]'
			}
			Function CMD_Out-LogFile{ '[ DONE ]'|Out-File -Append $FILE }
		} else {
			Function CMD_Out-Logging {
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor White -noNewLine 'DONE'; Write-Host -noNewLine ' ]'
			}
			Function CMD_Out-LogFile{ '[ DONE ]'|Out-File -noNewLine -Append $FILE }
		}
	} elseif( $sk ){
		if( $cr ){
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Yellow -noNewLine '.'; Write-Host ' ]'
			}
			Function CMD_Out-LogFile{ '[ . ]'|Out-File -Append $FILE }
		} else {
			Function CMD_Out-Logging{
				Write-Host -noNewLine '[ '; Write-Host -ForegroundColor Yellow -noNewLine '.'; Write-Host -noNewLine ' ]'
			}
			Function CMD_Out-LogFile{ '[ . ]'|Out-File -noNewLine -Append $FILE }
		}
	} else {
		$dt = (get-date -UFormat "%Y.%m.%d - %H:%M:%S.")+(get-date).Millisecond
		if( $cr ){
			Function CMD_Out-Logging{
				Write-Host -noNewLine "$dt [ "
				Switch( $TYPE.Remove(3) ){
					"WAR"	{ Write-Host -noNewLine -ForegroundColor Yellow "$TYPE"; Break }
					"ERR"	{ Write-Host -noNewLine -ForegroundColor RED "$TYPE"; Break }
					"DEB"	{ Write-Host -noNewLine -ForegroundColor Magenta "$TYPE"; Break }
					Default	{ Write-Host -noNewLine -ForegroundColor Cyan "$TYPE" }
				}
				Write-Host " ] - < $SRC > : $MSG"
			}
			Function CMD_Out-LogFile{ "$dt [ $TYPE ] - < $SRC > : $MSG"|Out-File -Append $FILE }
		} else {
			Function CMD_Out-Logging{
				Write-Host -noNewLine "$dt [ "
				Switch( $TYPE.Remove(3) ){
					"WAR"	{ Write-Host -noNewLine -ForegroundColor Yellow "$TYPE"; Break }
					"ERR"	{ Write-Host -noNewLine -ForegroundColor RED "$TYPE"; Break }
					"DEB"	{ Write-Host -noNewLine -ForegroundColor Magenta "$TYPE"; Break }
					Default	{ Write-Host -noNewLine -ForegroundColor Cyan "$TYPE" }
				}
				Write-Host -noNewLine " ] - < $SRC > : $MSG"
			}
			Function CMD_Out-LogFile{ "$dt [ $TYPE ] - < $SRC > : $MSG"|Out-File -noNewLine -Append $FILE }
		}
	}

	if( $FILE ){ CMD_Out-LogFile }
	if( $FLAG_CONS ){ CMD_Out-Logging }
}

Function Stop-Work(){
	$ArgList = "Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t w -m `"Work interrupted by the user`" -cr"
	Start-Process 'pwsh' -ArgumentList $ArgList -Verb RunAs
	Stop-Process $PID
}

# Настройка правил Брандмауэра Windows
Function Set-Rules(){
	CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="

	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Configuring Windows Firewall rules for ports: $Args... "
	foreach( $port in $Args ){
		foreach( $protokol in "TCP","UDP" ){
			if( $WINVER -eq 6 ){
				foreach( $direct in "In","Out" ){
					if( !(netsh advfirewall firewall show rule name=all|where {$_ -match "port $port $protokol $direct is enable"}) ){
						netsh advfirewall firewall add rule name="port $port $protokol $direct is enable" dir=$direct action=allow protocol=$protokol localport=$port *>$null
						if( $? ){ CMD_Ok } else { CMD_Err }
					} else { CMD_Skip }
				}
			} else {
				foreach( $direct in "Inbound","Outbound" ){
					if( (Get-NetFirewallRule -DisplayName "port $port $protokol $direct is enable*").Enabled -ne $true ){
						New-NetFirewallRule -Action allow -DisplayName "port $port $protokol $direct is enable" -Direction $direct -LocalPort $port -Protocol $protokol *>$null
						if( (Get-NetFirewallRule -DisplayName "port $port $protokol $direct is enable").Enabled -eq $true ){ CMD_Ok } else { CMD_Err }
					} else { CMD_Skip }
				}
			}
		}
	}
	CMD_Empty

	CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Rename-Lan_Old(){
	CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="

	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Rename network connections and sets the IP address... "
	$ALL_IF=netsh interface show interface
	$CNT_IF = ($ALL_IF.Count)-4

	if( $Args ){ $IP_WS = $Args[0] } else { $IP_WS = $BLOCK }
	for( $iy=0; $iy -lt $CNT_IF; $iy++ ){
		$Name = $ALL_IF[($ALL_IF.Count)-$CNT_IF-1+$iy]
		$CNT=0; $FLAG=$true
		for( $ix=0; $ix -lt $Name.Length; $ix++ ){
			if( $Name[$ix] -eq " " ){
				if( $FLAG ){ $CNT++; $FLAG=$false }
			} else {
				$FLAG=$true
				if($CNT -eq 3){
					$var = $Name.Substring($ix)
					if( $var.Substring(0,3) -eq "LAN" ){ CMD_Skip } else {
						netsh interface set interface name="$var" newname="LAN$($iy+1)" *>$null
						if($?){
							CMD_Ok
							netsh interface ipv4 set address "LAN$($iy+1)" static "$($jsonCFG.subNET).$($($jsonCFG.stepNET)*($iy+1)).$IP_WS" 255.255.255.0 "$($jsonCFG.subNET).$($($jsonCFG.stepNET)*($iy+1)).2" 1 *>$null
							if( $? ){ CMD_Ok } else { CMD_Err }
						} else { CMD_Err }
					}
					break
				}
			}
		}
	}
	CMD_Empty
	CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Rename-Lan(){
	CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="

	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Rename network connections and sets the IP address... "
	if( (Get-NetAdapter).Count -ge 2){
		if( !((Get-NetAdapter).Name[0]).Contains("LAN") ){
			if( $Args ){ $IP_WS = $Args[0] } else { $IP_WS = $BLOCK }
			for( $ix=0; $ix -lt (Get-NetAdapter).Count; $ix++ ){
				Rename-NetAdapter -Name "$((Get-NetAdapter).Name[$ix])" -NewName "LAN$($ix+1)"
				if( $? ){ CMD_Ok } else { CMD_Err }
			}
			for( $ix=0; $ix -lt (Get-NetAdapter).Count; $ix++ ){
				$var = "$($($jsonCFG.stepNET)*($ix+1))"
				New-NetIPAddress -InterfaceAlias "LAN$($ix+1)" -IPAddress "$($jsonCFG.subNET).$var.$IP_WS" -PrefixLength 24 -DefaultGateway "$($jsonCFG.subNET).$var.2" *>$null
				if( $? ){ CMD_Ok } else { CMD_Err }
			}
			CMD_Empty
		} else { CMD_SkipCr }
	} else {
		if( !((Get-NetAdapter).Name).Contains("LAN") ){
			if( $Args ){ $IP_WS = $Args[0] } else { $IP_WS = $BLOCK }
			Rename-NetAdapter -Name "$((Get-NetAdapter).Name)" -NewName "LAN1"
			if( $LASTEXITCODE -eq 0 ){ CMD_Ok } else { CMD_Err }

			New-NetIPAddress -InterfaceAlias "LAN1" -IPAddress "$($jsonCFG.subNET).$($jsonCFG.stepNET).$IP_WS" -PrefixLength 24 -DefaultGateway "($jsonCFG.subNET).($jsonCFG.stepNET).2" *>$null
			if( $LASTEXITCODE -eq 0 ){ CMD_Ok } else { CMD_Err }
			CMD_Empty
		} else { CMD_SkipCr }
	}

	CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Rename-PC(){
	CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="
	Rename-Computer -NewName "$($Args)" *>$null
	Set-ItemProperty -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$strSID\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Name "(Default)" -Value "$($Args)"
	CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Set-AsRun(){
	if( $Args ){ $var = $Args } else {
		Write-Host
		"How to run software:";"  as Shell   - 1";"  as Program - 2"
		choice /c 123q /n /m "?: "
		$var = $LASTEXITCODE
	}

	$BRANCH_WINLOGON = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
	$BRANCH_RUN = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	$VALUE = "cmd.exe /u /c pwsh.exe -Command rc.SS.ps1"
	Switch( $var ){
		1 {
			CMD_DBG 2 $MyInvocation.MyCommand.Name "Selected run as shell"
			Set-ItemProperty -Path $BRANCH_WINLOGON -Name "Shell" -Value $VALUE
			Remove-ItemProperty -Path $BRANCH_RUN -Name "SS" *>$null
			Break
		}
		2 {
			CMD_DBG 2 $MyInvocation.MyCommand.Name "Selected run as programm"
			Set-ItemProperty -Path $BRANCH_WINLOGON -Name "Shell" -Value explorer.exe
			Set-ItemProperty -Path $BRANCH_RUN -Name "SS" -Value $VALUE
			Break
		}
		3 {
			if( (Get-ItemProperty $BRANCH_WINLOGON -Name Shell).Shell -eq "explorer.exe" ){
				CMD_DBG 2 $MyInvocation.MyCommand.Name "Selected run as shell"
				Set-ItemProperty -Path $BRANCH_WINLOGON -Name "Shell" -Value $VALUE
				Remove-ItemProperty -Path $BRANCH_RUN -Name "SS" *>$null
			} else {
				CMD_DBG 2 $MyInvocation.MyCommand.Name "Selected run as programm"
				Set-ItemProperty -Path $BRANCH_WINLOGON -Name "Shell" -Value explorer.exe
				Set-ItemProperty -Path $BRANCH_RUN -Name "SS" -Value $VALUE
			}
			Break
		}
		Default { Stop-Work }
	}
}

Function Set-TimeClt(){
<#
	SpecialPollInterval:
		0x003c - 60 сек;
		0x0258 - 600 сек;
		0x0e10 - 3600 сек;

	LargePhaseOffset	Specifies the time offset, in tenths of a microsecond (A tenth of a microsecond is equal to 10 to the power of -7). Times that are larger than or equal to this value are considered suspicious and possibly incorrect.
	SpikeWatchPeriod	Specifies how long, in seconds, that a suspicious time offset must persist before it is accepted as correct.
	EventLogFlags   Stores configuration data for the policy setting, Configure Windows NTP Client.
	Enabled Indicates whether the NtpServer provider is enabled in the current Time Service.

	После настройки необходимо обновить конфигурацию сервиса. Сделать это можно командой w32tm /config /update.
	И еще несколько команд для настройки, мониторинга и диагностики службы времени:
	w32tm /monitor – при помощи этой опции можно узнать, насколько системное время данного компьютера отличается от времени на контроллере домена или других компьютерах. Например: w32tm /monitor /computers:time.nist.gov
	w32tm /resync – при помощи этой команды можно заставить компьютер синхронизироваться с используемым им сервером времени.
	w32tm /stripchart –  показывает разницу во времени между текущим и удаленным компьютером. Команда w32tm /stripchart /computer:time.nist.gov /samples:5 /dataonly произведет 5 сравнений с указанным источником и выдаст результат в текстовом виде.
	w32tm /config – это основная команда, используемая для настройки службы NTP. С ее помощью можно задать список используемых серверов времени, тип синхронизации и многое другое. Например, переопределить значения по умолчанию и настроить синхронизацию времени с внешним источником, можно командой w32tm /config /syncfromflags:manual /manualpeerlist:time.nist.gov /update
	w32tm /query — показывает текущие настройки службы. Например команда w32tm /query /source  покажет текущий источник времени, а w32tm /query /configuration  выведет все параметры службы.

	net stop w32time - останавливает службу времени, если запущена.
	w32tm /unregister — удаляет службу времени с компьютера.
	w32tm /register – регистрирует службу времени на компьютере.  При этом создается заново вся ветка параметров в реестре.
	net start w32time - запускает службу.

	MaxAllowedPhaseOffset - максимально допустипое расхождение:
		0x012c - 5 мин
		0x0e10 - 1 час
#>

	if( $Args[0] -eq "" ) {
		$s1 = "192.168.10.2"
		$s2 = "192.168.10.3"
	} else {
		$s1 = $Args[0]
		if( $Args[1] -eq "" ) { $s2 = "192.168.10.2" } else { $s2 = $Args[1] }
	}

	$Branch = "KKLM:\SYSTEM\CurrentControlSet\Services\W32Time"
	Set-ItemProperty -Path "$Branch\Config" -Name "MaxAllowedPhaseOffset" -Value 1 *>$null
	Set-ItemProperty -Path "$Branch\Config" -Name "MaxPosPhaseCorrection" -Value 0xFFFFFFFF *>$null
	Set-ItemProperty -Path "$Branch\Config" -Name "MaxNegPhaseCorrection" -Value 0xFFFFFFFF *>$null
	Set-ItemProperty -Path "$Branch\Config" -Name "SpikeWatchPeriod" -Value 1 *>$null

	Set-ItemProperty -Path "$Branch\Parameters" -Name "NtpServer" -Value "$s1,0x1 $s2,0x1" *>$null
	Set-ItemProperty -Path "$Branch\Parameters" -Name "Type" -Value "NTP" *>$null

	Set-ItemProperty -Path "$Branch\TimeProviders\NtpClient" -Name "Enabled" -Value 1 *>$null
	Set-ItemProperty -Path "$Branch\TimeProviders\NtpClient" -Name "SpecialPollInterval" -Value 0x0e10 *>$null
	Set-ItemProperty -Path "$Branch\TimeProviders\NtpServer" -Name "Enabled" -Value 0 *>$null

	$Branch = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers"
	Set-ItemProperty -Path "$Branch\Config" -Name "(Default)" -Value "6" *>$null
	Set-ItemProperty -Path "$Branch\Config" -Name "6" -Value "$s1" *>$null
}

Function Set-Shared( [string]$s, [string]$d, [string]$u="User" ){
	CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "Share: ${s}, Path: ${d}, User: ${u}"

	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Create share: ${s}... "

	net share $s=$d /grant:$u,full *>$null
	if( $? ){ CMD_OkCr } else { CMD_ErrCr }

	CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Invoke-W32Time(){
	if( (Get-Service w32time).Status -eq 'Running' ) { Set-Service -InputObject w32time -Status Stopped; Sleep 4 }
	Set-Service -InputObject w32time -Status Running
}

Function Set-PathPeleng([string]$dev, [string]$def){
	CMD_Dbg 1 $MyInvocation.MyCommand.Name "========= started ========="
	if( !$dev ){ if( !$Data.DEVICE ){ Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "DEVICE not defined!" -cr; Stop-Work } }

	if( !$Force ){
		Write-Host
		$var = Read-Host "Specify the folder name for install $dev [ $def ]"
		if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { $Data.PATH_PELENG = $var } } else { $Data.PATH_PELENG = $def }
	}

	if( [Environment]::Is64BitOperatingSystem -and !(($Data.PATH_PELENG).Contains("(x86)")) -and ($dev -ne "RTS") ){
		$Data.PATH_PELENG = ($Data.PATH_PELENG).ToLower().Replace("program files", "Program Files (x86)")
	}
	CMD_Dbg 2 $MyInvocation.MyCommand.Name "PATH_PELENG=$($Data.PATH_PELENG)"

	Set-Content -Path .\PelengData.json -Value "$($Data|ConvertTo-JSON)"

	CMD_Dbg 1 $MyInvocation.MyCommand.Name "======== completed ========"
}

Function Get-ComFolderItem() {
	[CMDLetBinding()]
	param(
		[Parameter(Mandatory=$true)] $Path
	)

	$ShellApp = New-Object -ComObject 'Shell.Application'

	$Item = Get-Item $Path -ErrorAction Stop

	if ($Item -is [System.IO.FileInfo]) {
		$ComFolderItem = $ShellApp.Namespace($Item.Directory.FullName).ParseName($Item.Name)
	} elseif ($Item -is [System.IO.DirectoryInfo]) {
		$ComFolderItem = $ShellApp.Namespace($Item.Parent.FullName).ParseName($Item.Name)
	} else {
		throw "Path is not a file nor a directory"
	}

	return $ComFolderItem
}

Function Install-TaskBarPinnedItem() {
	[CMDLetBinding()]
	param(
		[Parameter(Mandatory=$true)] [System.IO.FileInfo] $Item
	)

	$Pinned = Get-ComFolderItem -Path $Item

	$Pinned.invokeverb('taskbarpin')
}

Function Uninstall-TaskBarPinnedItem() {
	[CMDLetBinding()]
	param(
		[Parameter(Mandatory=$true)] [System.IO.FileInfo] $Item
	)

	$Pinned = Get-ComFolderItem -Path $Item

	$Pinned.invokeverb('taskbarunpin')
}

Function Get-NetworkConfig {
  Get-WmiObject Win32_NetworkAdapter -Filter 'NetConnectionStatus=2' |
	ForEach-Object {
	  $result = 1 | Select-Object Name, IP, MAC
	  $result.Name = $_.Name
	  $result.MAC = $_.MacAddress
	  $config = $_.GetRelated('Win32_NetworkAdapterConfiguration') 
	  $result.IP = $config | Select-Object -expand IPAddress
	  $result
	}
 
}

Function Get-FolderSize($Path=$home) {
  $code = { ('{0:0.0} MB' -f ($this/1MB)) }
  Get-ChildItem -Path $Path |
	Where-Object { $_.Length -eq $null } |
	ForEach-Object {
	  Write-Progress -Activity 'Calculating Total Size for:' -Status $_.FullName
	  $sum = Get-ChildItem $_.FullName -Recurse -ErrorAction SilentlyContinue |
		Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue
	  $bytes = $sum.Sum
	  if ($bytes -eq $null) { $bytes = 0   }
	  $result = 1 | Select-Object -Property Path, TotalSize
	  $result.Path = $_.FullName
	  $result.TotalSize = $bytes | 
		Add-Member -MemberType ScriptMethod -Name toString -Value $code -Force -PassThru	
	  $result
	}
}

Function New-ArchiveDisk() {
<#
.LINK
	https://winitpro.ru/index.php/2019/01/10/powershell-upravlenie-diskami-i-razdelami/
.SYNOPSIS
	The initial configuration script windows.
	For the correct operation of the script must be run with administrator privileges
.DESCRIPTION

.PARAMETER  DiskLetter

.PARAMETER  Count
.EXAMPLE
	New-ArchiveDisk -DiskLetter "E" -Count 3 -Force
	будет выполнена очистка диска, создание раздела в размер диска, форматирование и создание метки 'архивный'
.NOTES
	Copyright (C) 2020 Dmitriy L. Ivanov aka onepif
	CJSC PELENG 2020

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#>

	[CmdletBinding()]
	Param(
		[ValidatePattern("[a-z,A-Z]")]
		[char]$DiskLetter,

		[int]$Count = 1
	)

	$MAX_NUM_HDD=20

	if( !$DiskLetter ){
		$var=(Get-PSDrive -PSProvider FileSystem).Name
		choice.exe /c ([string]$var -replace "\s","") /m "Select a drive letter"
		$DiskLetter = $var[$LASTEXITCODE-1]
	}

#$Count = Read-Host -Prompt "Укажите начальный номер архивного накопителя"

	for( $ix=$Count; $ix -lt $MAX_NUM_HDD; $ix++ ){
		if( Test-Path "${DiskLetter}:\Signals\.arch.id" ){
			choice.exe /c yn /n /m "You have selected an already partitioned archive drive. Continue? [Y/N]: "
			if( $LASTEXITCODE -eq 2 ){ Stop-Work }
		}
		"list disk"|diskpart.exe
		choice.exe /c 0123456 /n /m "Specify the disk number: "
		$DISK_NUM = $LASTEXITCODE-1

		choice.exe /c yn /n /m "All data on your hard drive will be destroyed! Continue? [Y/N]: "
		if( $LASTEXITCODE -eq 2 ){ Stop-Work }

		"select disk $DISK_NUM"|Out-File -Encoding UTF8 "$($Data.tmp)\dp.sc"
		"clean"|Out-File -Append "$($Data.tmp)\dp.sc"
		diskpart.exe /s $Data.tmp\dp.sc

		"select disk $DISK_NUM"|Out-File -Encoding UTF8 "$($Data.tmp)\dp.sc"
		"create partition primary"|Out-File -Append "$($Data.tmp)\dp.sc"
		diskpart.exe /s $($Data.tmp)\dp.sc

		"list volume"|diskpart.exe
		choice.exe /c 0123456 /n /m "Specify volume number: "
		$VOLUME_NUM = $LASTEXITCODE

		"select disk $DISK_NUM"|Out-File -Encoding UTF8 "$($Data.tmp)\dp.sc"
		"select volume $VOLUME_NUM"|Out-File -Append "$($Data.tmp)\dp.sc"
		"format fs=ntfs quick"|Out-File -Append "$($Data.tmp)\dp.sc"
		"assign letter=$DiskLetter"|Out-File -Append "$($Data.tmp)\dp.sc"
		diskpart.exe /s $($Data.tmp)\dp.sc

		New-Item -Type Directory ${DiskLetter}:\Signals -Force
		((mountvol.exe ${DiskLetter}:\ /L) -Replace "^.*{") -Replace "}.*" >${DiskLetter}:\Signals\.arch.id

		icacls ${DiskLetter}:\Signals /inheritance:d /t
		icacls ${DiskLetter}:\ /restore _DACL_Signals.dacl

		"select disk $DISK_NUM"|Out-File -Encoding UTF8 "$($Data.tmp)\dp.sc"
		"select volume $VOLUME_NUM"|Out-File -Append "$($Data.tmp)\dp.sc"
		"remove letter=$DiskLetter"|Out-File -Append "$($Data.tmp)\dp.sc"
		"offline volume"|Out-File -Append "$($Data.tmp)\dp.sc"
		diskpart.exe /s $($Data.tmp)\dp.sc

		Write-Host -ForegroundColor Yellow "Remove the archived hard drive."
		choice.exe /c yn /n /m "`n`nCreate next archived hard drive? [Y/N]: "
		if( $LASTEXITCODE -eq 2 ){ Stop-Work }
	}
}

Function Install-Soft(){
	[CmdletBinding()]
	Param(
		[Switch]$Force,

		[Parameter(Mandatory=$true)]
		[string]$SRC,

		[string]$DEST=$Data.PATH_PELENG
	)

	$RETVAL = 0
    $Name = [System.IO.Path]::GetFileNameWithoutExtension(([System.IO.Path]::GetFileName($SRC)))
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Install $Name... "

	if( Test-Path -Path $SRC ) {
		if( !(Test-Path -Path $DEST) ) { New-Item -type Directory -Path $DEST -Force *>$null }
		Expand-Archive -LiteralPath $SRC -Destination $DEST -Force
		if( $? ){
			if( !$Force ){ CMD_Ok }

			$ExcludeDLL = @( "U_BaseClasses.dll","av*.dll","lib*.dll","sw*.dll","qt*.dll" )
			if( [Environment]::Is64BitOperatingSystem ){
				Move-Item -Path "$DEST\*.dll" -Destination "$env:WINDIR\sysWOW64" -Exclude "U_BaseClasses.dll,av*.dll,lib*.dll,sw*.dll,qt*.dll" -Force *>$null
			} else {
				Move-Item -Path "$DEST\*.dll" -Destination "$env:WINDIR\system32" -Exclude "U_BaseClasses.dll,av*.dll,lib*.dll,sw*.dll,qt*.dll" -Force *>$null
			}
			if( $? ){ if( !$Force ){CMD_OkCr} } else { $RETVAL = 1; if( !$Force ){CMD_ErrCr} }
		} else {
			$RETVAL = 2
			if( !$Force ){
				CMD_ErrCr
				Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "Unpacking error" -cr
			}
		}
	} elseif( Test-Path -Path "$(Split-Path $SRC)\$Name.exe" ) {
		& "$(Split-Path $SRC)\$Name.exe /S /D=$DEST"
		Wait-Process $Name
		if( !$Force ){ CMD_DnCr }
	} else {
		$RETVAL = 3
		if( !$Force ){
			CMD_ErrCr
			Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t e -m "File ${SRC}[.exe] not found" -cr
		}
	}
#	if( $Force ){ return $RETVAL }
	return $RETVAL
}

Function Write-Mill(){
	[CmdletBinding()]
	Param(
		[string]$Prompt="Waiting",

		[Parameter(Mandatory=$true)]
		[string]$Name
	)
	Write-Host -noNewLine "${Prompt}:  "
	while(Get-Process |where {$_.ProcessName -eq $Name} ){
		foreach($ix in "|","/","-","\"){
			Write-Host -ForegroundColor Green -noNewLine "`b$ix"
			Start-Sleep -Milliseconds 250
		}
	}
	Write-Host -noNewLine "`b[ "; Write-Host -ForegroundColor Green -noNewLine "OK"; Write-Host " ]"
}

Function CMD_Empty(){ Out-Logging -out $FileLog -empty }
Function CMD_Dn(){ Out-Logging -out $FileLog -dn }
Function CMD_DnCr(){ Out-Logging -out $FileLog -dn -cr }
Function CMD_Ok(){ Out-Logging -out $FileLog -ok }
Function CMD_OkCr(){ Out-Logging -out $FileLog -ok -cr }
Function CMD_Err(){ Out-Logging -out $FileLog -er }
Function CMD_ErrCr(){ Out-Logging -out $FileLog -er -cr }
Function CMD_Skip(){ Out-Logging -out $FileLog -sk }
Function CMD_SkipCr(){ Out-Logging -out $FileLog -sk -cr }
Function CMD_DBG( $dbg_lvl=1, $name="CMD_Dbg" ){
	if( ($Dbg -band $dbg_lvl) -eq $dbg_lvl ){
		Out-Logging -out $FileLog -src $name -t d$dbg_lvl -m ([string]$Args+";") -cr
	}
}
