# ./add_user

Function Set-Pass(){
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t w -m "user `< ${pUser} `> already exists" -cr
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Setting password for users ${pUser}: ${pPass}... "
	net user ${pUser} ${pPass} *>$null
	if( $LASTEXITCODE -eq 0 ){ CMD_OkCr } else { CMD_ErrCr }
}
# ==============================================================================
CMD_DBG 1 $MyInvocation.MyCommand.Name "========= started ========="

# UAC -> off
if( (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA).EnableLUA -eq 1 ){
	Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "UAC off" -cr
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0
} else { Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -t w -m "UAC allready off" -cr }

${pUser} = "$env:USERNAME"
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify 'USERNAME' [ "${pUser}" ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { ${pUser} = $var } }
}

${pPass} = $jsonCFG.password
if( !$Force ){
	Write-Host
	$var = Read-Host "Specify 'PASSWORD' [ ${pPass} ]"
	if( $var ){ if( $var -eq "Q" ){ Stop-Work } else { ${pPass} = $var } }
}

# [Auto logon]
Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Configure autologon started" -cr
$BRANCH = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path "$BRANCH" -Name "AutoAdminLogon" -Value 1
Set-ItemProperty -Path "$BRANCH" -Name "DefaultDomainName" -Value "PELENG"
Set-ItemProperty -Path "$BRANCH" -Name "DefaultUserName" -Value ${pUser}
Set-ItemProperty -Path "$BRANCH" -Name "DefaultPassword" -Value ${pPass}

if( $env:USERNAME -ne ${pUser} ){
	$Data.USER_PELENG = $pUser
	Set-Content -Path .\PelengData.json -Value "$($Data|ConvertTo-JSON)"

	if( !(wmic useraccount list full|where { $_ -eq "Name=${pUser}" }) ){
		Out-Logging -out $FileLog -src $MyInvocation.MyCommand.Name -m "Create user's ${pUser}... "
		net user ${pUser} ${pPass} /add /expires:never *>$null
		if( $LASTEXITCODE -eq 0 ){ CMD_Ok } else { if( $LASTEXITCODE -eq 2 ){ CMD_Skip } else { CMD_Err } }
		if( $LOCALE -eq 00000419 ){ net localgroup "Администраторы" ${pUser} /add *>$null } else { net localgroup "Administrators" ${pUser} /add *>$null }
		if( $LASTEXITCODE -eq 0 ){ CMD_OkCr } else { CMD_ErrCr }
	} else { Set-Pass }

	choice /c rlq /d l /t 7 /n /m "Press 'R' for reboot or 'L' for logoff [R/L]: "
	if( $LASTEXITCODE -eq 3 ){ Stop-Work } elseif( $LASTEXITCODE -eq 2 ) { logoff } else { Restart-Computer -Force }
} else { Set-Pass }

CMD_DBG 1 $MyInvocation.MyCommand.Name "======== completed ========"
