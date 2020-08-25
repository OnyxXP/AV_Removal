<#	
	.NOTES
	===========================================================================
	 Created on:   	20200428
	 Created by:   	jmeyer
	 Organization: 	Helion Technologies
	 Filename:     	RemoveMcAfee.0.2
	===========================================================================
	.DESCRIPTION
		This will remove the following McAfee software with no GUI or reboots.

		McAfee VirusScan Enterprise
		McAfee Agent
#>

Write-Host "Setting up..." -ForegroundColor Yellow

$ScriptVersion = "RemoveMcAfee.0.2"

Write-Host "Checking OS version..." -ForegroundColor Yellow
If ((Get-WmiObject Win32_OperatingSystem).Caption -like '*server*')
{
	Write-Warning "This script is not designed to run on a Server OS. The script will now close."
		## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
		## Self destructs script.
	Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	Write-Warning "Press any key to exit...";
	$x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown");
}
else
{
	Write-Host "OS Version verified. Continuing..." -ForegroundColor Green
}

Write-Host "Checking for administrative rights..." -ForegroundColor Yellow
	## Get the ID and security principal of the current user account.
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID);

	## Get the security principal for the administrator role.
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;

	## Check to see if we are currently running as an administrator.
if ($myWindowsPrincipal.IsInRole($adminRole))
{
		## We are running as an administrator, so change the title and background colour to indicate this.
	Write-Host "We are running as administrator, changing the title to indicate this." -ForegroundColor Green
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)";
}
else
{
	Write-Host "We are not running as administrator. Relaunching as administrator." -ForegroundColor Yellow
		## We are not running as admin, so relaunch as admin.
	$NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
		## Specify the current script path and name as a parameter with added scope and support for scripts with spaces in it's path.
	$NewProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
		## Indicate that the process should be elevated.
	$NewProcess.Verb = "runas";
		## Start the new process
	[System.Diagnostics.Process]::Start($newProcess);
		## Exit from the current, unelevated, process.
	Exit;
}

Write-Host "Continuing with setup..." -ForegroundColor Yellow

	## Start log.
if ($PSVersionTable.PSVersion.Major -ge 3)
{
	Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
	If ((Test-Path C:\Logs\) -eq $false)
	{
		New-Item C:\Logs\ -ItemType Directory
	}
	Start-Transcript -Path "C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
}

$INFO = "
McAfee Removal script written by Josh Meyer.
Please contact the author if you have any questions or concerns.
Contact info: jmeyer@heliontechnologies.com
**For complete ChangeLog, please contact the author.**

Script version: $ScriptVersion
"

Write-Host "Removing McAfee VirusScan Enterprise..." -ForegroundColor Yellow
	## 20200428.jmeyer.Removing McAfee VirusScan Enterprise
wmic product where "description= 'McAfee VirusScan Enterprise' " uninstall

Write-Host "Removing McAfee Agent..." -ForegroundColor Yellow
	## 20200428.jmeyer.Removing McAfee Agent
wmic product where "description= 'McAfee Agent' " uninstall

if ((Test-Path -Path "C:\Program Files\McAfee\Common Framework\FrmInst.exe") -eq $true)
{
	Write-Host "Found McAfee..." -ForegroundColor Green
	Write-Host "Removing McAfee..." -ForegroundColor Yellow
	Start-Process -FilePath "C:\Program Files\McAfee\Common Framework\FrmInst.exe" -ArgumentList "/Remove=Agent", "/Silent" -Wait
}

if ((Test-Path -Path "C:\Program Files\McAfee\MSC\mcuihost.exe") -eq $true)
{
	Write-Host "Found McAfee..." -ForegroundColor Green
	Write-Host "Removing McAfee..." -ForegroundColor Yellow
	Start-Process -FilePath "C:\Program Files\McAfee\MSC\mcuihost.exe" -ArgumentList "/body:misp://MSCJsRes.dll::uninstall.html", "/id:uninstall
" -Wait
}

if ((Test-Path -Path "C:\Program Files\McAfee\WebAdvisor\Uninstaller.exe") -eq $true)
{
	Write-Host "Found McAfee..." -ForegroundColor Green
	Write-Host "Removing McAfee..." -ForegroundColor Yellow
	Start-Process -FilePath "C:\Program Files\McAfee\WebAdvisor\Uninstaller.exe" -ArgumentList -Wait
}

## Removing all script files for security reasons.
Write-Warning "Removing script files for security purposes..."
	## Self destructs script.
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force

Write-Host "File deletion completed" -ForegroundColor Green
	## Stops Log.
if ($PSVersionTable.PSVersion.Major -ge 3)
{
	Write-Warning "Stopping log.."
	Stop-Transcript
}