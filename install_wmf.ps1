$SOFT_ENV = "$(Split-Path -Path $(Split-Path -Path $MyInvocation.MyCommand.Path))\soft_environment"
$BRANCH_RUN = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

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

if( (Get-Host).Version.Major -eq 2 ){
# ===== Install .NET 4.5.2 =====
	$Name = "NDP452-KB2901907-x86-x64-AllOS-ENU"
	& $SOFT_ENV\sys\$Name.exe /q /norestart
	Write-Mill "Install .NET 4.5.2" $Name

	$Name = "wusa"
# ===== Install WMF-4.0 =====
	if( [Environment]::Is64BitOperatingSystem ){
		& $SOFT_ENV\sys\pwsh\Windows6.1-KB2819745-x86-MultiPkg.msu /quiet /norestart
	} else {
		& $SOFT_ENV\sys\pwsh\Windows6.1-KB2819745-x64-MultiPkg.msu /quiet /norestart
	}
	Write-Mill "Install WMF-4.0" $Name

# сдинем вывод на 10 строк вниз
	Add-Type -AssemblyName System.Windows.Forms
	$current = [System.Windows.Forms.Cursor]::Position
	$current.Y += 10
	[System.Windows.Forms.Cursor]::Position = $current

# ===== Install WMF-5.1 =====
#	Expand-Archive	-LiteralPath $SOFT_ENV\sys\pwsh\Win7AndW2K8R2-KB3191566-x64.zip \
#					-Destination $SOFT_ENV\sys\pwsh\ -Force

	& $SOFT_ENV\sys\pwsh\Install-WMF5.1.ps1 -AcceptEULA
	Write-Mill "Install WMF-5.1" $Name

# Add autorestart run.cmd
	$VALUE = "cmd.exe /u /c powershell.exe Start-Process $(Split-Path -Path $MyInvocation.MyCommand.Path)\bin\run.cmd -Verb RunAs"
	if( $Args ){ $VALUE += " -ArgumentList @Args" }
	Set-ItemProperty -Path $BRANCH_RUN -Name "run" -Value $VALUE

	"press 'E/Q' to exit or 'R' to restart immediately "
	for ($ix = 30; $ix -ge 0; $ix-- ){
		Write-Progress -Activity "Time to reboot..." -Status "$($ix)s left" -PercentComplete ($ix*3.3)
		choice.exe /c neqr /n /d n /t 1 >$null
		if( $LASTEXITCODE -ne 1 ) { if( $LASTEXITCODE -eq 4 ) { Restart-Computer } else { return 0 } }
	}
	Restart-Computer
} else {
	Remove-ItemProperty -Path $BRANCH_RUN -Name "run" *>$null
}
