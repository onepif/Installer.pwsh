function prompt {
#	Set-Color

	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [Security.Principal.WindowsPrincipal] $identity

	"pwsh-$($Host.Version.Major).$($Host.Version.Minor)" +
	$( if($principal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{ "# " } else { "$ " } )
}

if( Test-Path $env:WINDIR\PelengData.json ){
	$Data = Get-Content $env:WINDIR\PelengData.json|ConvertFrom-JSON
}
