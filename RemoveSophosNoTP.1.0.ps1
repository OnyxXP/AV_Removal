<#	
	.NOTES
	===========================================================================
	 Created on:   	20200723
	 Created by:   	jmeyer
	 Organization: 	Helion Technologies
	 Filename:     	RemoveSophos.1.0
	===========================================================================
	.DESCRIPTION
		This will remove the software listed below with no GUI or reboots.

		Sophos: (In the order listed below)
			Sophos Remote Management System
 			Sophos Network Threat Protection
 			Sophos Client Firewall
 			Sophos Anti-Virus
 			Sophos AutoUpdate
 			Sophos Diagnostic Utility
 			Sophos Exploit Prevention
 			Sophos Clean
 			Sophos Patch Agent
 			Sophos Endpoint Defense
#>

################
## Parameters ##
################

###########
## Setup ##
###########

Write-Host "Setting up..." -ForegroundColor Yellow

$ScriptVersion = "RemoveSophos.1.0"
## Setting colors for various messages.
$Warningcolor = (Get-Host).PrivateData
$Warningcolor.WarningBackgroundColor = "Red"
$Warningcolor.WarningForegroundColor = "White"
$DebugPreference = 'Continue'
$Debugcolor = (Get-Host).PrivateData
$Debugcolor.DebugBackgroundColor = "White"
$Debugcolor.DebugForegroundColor = "DarkBlue"

####################################
## Self elevates to Administrator ##
####################################

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

#############
## Logging ##
#############

if ($PSVersionTable.PSVersion.Major -ge 3)
{
	Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
	if ((Test-Path C:\Logs\) -eq $false)
	{
		$null = New-Item C:\Logs\ -ItemType Directory
	}
	Start-Transcript -Path "C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
}

$INFO = "
Sophos Anti-Virus Removal script written by Josh Meyer.
Please contact the author if you have any questions or concerns.
Contact info: jmeyer@heliontechnologies.com
**For complete ChangeLog, please contact the author.**

Script version: $ScriptVersion
"

#############
## Modules ##
#############


###############
## Variables ##
###############
Write-Host "Setting Variables..." -ForegroundColor Yellow
$OSCaption = (Get-WmiObject Win32_OperatingSystem).Caption
$SophosSoftware = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Sophos*" }
if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
{
	$SophosSoftware += Get-ChildItem HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*Sophos*" }
}
$SophosSoftwareList = @("Sophos Remote Management System", "Sophos Network Threat Protection", "Sophos Client Firewall", "Sophos Anti-Virus",
	"Sophos AutoUpdate", "Sophos Diagnostic Utility", "Sophos Exploit Prevention", "Sophos Clean", "Sophos Patch Agent", "Sophos Endpoint Defense",
	"Sophos Management Communication System", "Sophos Compliance Agent", "Sophos System Protection")

###############
## Functions ##
###############

function SophosRemoval ()
{
	Write-Host "Found Sophos software..." -ForegroundColor Green
	Stop-Service -Name "Sophos Anti-Virus" -Force
	Stop-Service -Name "Sophos AutoUpdate Service" -Force
	
	foreach ($Software in $SophosSoftwareList)
	{
		if ($SophosSoftware | Where-Object DisplayName -like $Software)
		{
			$SophosSoftware | Where-Object DisplayName -like $Software | ForEach-Object {
				Write-Host "Uninstalling $($_.DisplayName)"
				
				if ($_.uninstallstring -like "msiexec*")
				{
					Write-Debug "Uninstall string: Start-Process $($_.UninstallString.split(' ')[0]) -ArgumentList `"$($_.UninstallString.split(' ', 2)[1]) /qn REBOOT=SUPPRESS`" -Wait"
					Start-Process $_.UninstallString.split(" ")[0] -ArgumentList "$($_.UninstallString.split("  ", 2)[1]) /qn REBOOT=SUPPRESS" -Wait
				}
				else
				{
					Write-Debug "Uninstall string: Start-Process $($_.UninstallString) -Wait"
					Start-Process $_.UninstallString -Wait
				}
			}
		}
	}
	Write-Host "Finished removing Sophos." -ForegroundColor Green
}

function ScriptEnding ()
{
		## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
		## Self destructs script.
	Remove-Item -LiteralPath $PSCommandPath -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	
		## Stops Log.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Warning "Stopping log.."
		Stop-Transcript
	}
	exit
}

Write-Host "Setup completed!" -ForegroundColor Green
###################
## Prerequisites ##
###################

## Script OS limitations
Write-Host "Checking OS version..." -ForegroundColor Yellow
if ($OSCaption -like '*server*')
{
	Write-Warning "This script is not designed to run on a Server OS. The script will now close."
	ScriptEnding
}
else
{
	Write-Host "OS Version verified. Continuing..." -ForegroundColor Green
}

#######################
## Start main script ##
#######################

	## Removing Sophos AV suite, in a specific order. 
Write-Host "Checking for Sophos software..." -ForegroundColor Yellow
if (($SophosSoftware) -ne $null)
{
	## Calling Sophos removal function
	SophosRemoval
}
else
{
	Write-Host "Sophos software not found..." -ForegroundColor Yellow
}

#######################
#  Ending of script   #
#######################

ScriptEnding

###########################
# Do not write below here #
###########################