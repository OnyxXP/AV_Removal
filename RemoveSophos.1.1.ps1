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
			Circumvent Tamper Protection if enabled
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
function SophosTPRemoval ()
{
	Write-Host "Found Sophos software..." -ForegroundColor Green
	Stop-Service -Name "Sophos Anti-Virus" -Force
	Stop-Service -Name "Sophos AutoUpdate Service" -Force
	Write-Host "Checking for Tamper Protection..." -ForegroundColor Yellow
	$file = "C:\ProgramData\Sophos\Sophos Anti-Virus\Config\machine.xml"
	$xml = New-Object XML
	$xml.Load($file)
	$pw = $xml.SelectSingleNode("//password")
	
	if ($pw)
	{
		Write-Warning "Found Tamper Protection..."
		Write-Warning "Attempting to circumvent Tamper Protection..."
		Write-Host "Checking encrypted password..." -ForegroundColor Yellow
		if ($pw.InnerText -eq "E8F97FBA9104D1EA5047948E6DFB67FACD9F5B73")
		{
			Write-Host "Password already set!" -ForegroundColor Green
			$PWCheck = $true
			$PWResults = "Password already set!"
		}
		else
		{
			Write-Host "Attempting to change encrypted password"
			$pw.InnerText = "E8F97FBA9104D1EA5047948E6DFB67FACD9F5B73"
			$xml.Save($file)
			$xml.Load($file)
			Write-Host "Verifying password change..." -ForegroundColor Yellow
			if ($pw.InnerText -eq "E8F97FBA9104D1EA5047948E6DFB67FACD9F5B73")
			{
				Write-Host "Password changed successuflly!" -ForegroundColor Green
				$PWCheck = $true
				$PWResults = "Password changed successfully!"
			}
			else
			{
				Write-Warning "Password change failed!"
				$PWCheck = $false
				$PWResults = "Password change failed!"
				ScriptEnding
				exit
			}
		}
		## Reg key changes for Sophos Enterprise Console and Sophos Central software.
		Write-Host "Changing registry keys to match Tamper Protection removal..." -ForegroundColor Yellow
		Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" -Name "SAVEnabled" -Value 0 -Force -Verbose
		Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" -Name "SEDEnabled" -Value 0 -Force -Verbose
		
		if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
		{
			Set-ItemProperty -Path "HKLM:SOFTWARE\WOW6432Node\Sophos\SAVService\TamperProtection" -Name "Enabled" -Value 0 -Force -Verbose
		}
		else
		{
			Set-ItemProperty -Path "HKLM:SOFTWARE\Sophos\SAVService\TamperProtection" -Name "Enabled" -Value 0 -Force -Verbose
		}
		
		## Sophos Central ONLY
		if ((Test-Path -Path "HKLM:SYSTEM\CurrentControlSet\Services\Sophos MCS Agent") -eq $true)
		{
			Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\Sophos MCS Agent" -Name "Start" -Value "0x00000004" -Force -Verbose
		}
		Write-Host "Registry keys changed!" -ForegroundColor Green
		
		Write-Host "Checking for SEDCli.exe..."
		$ResolveSEDcliPath = Resolve-Path -Path "C:\Prog*\Sophos\Endpoint*\"
		$SEDcliPath = Join-Path -Path $ResolveSEDcliPath -ChildPath "SEDCli.exe"
		$SEDcliPathCheck = Test-Path -Path $SEDcliPath
		## Checking for the file required to turn off Tamper Protection and verifying the password was changed successfully. Running if found.
		if ((($SEDcliPathCheck) -eq $true) -and (($PWCheck) -eq $true))
		{
			Write-Host "Found SEDCli.exe." -ForegroundColor Green
			Write-Host "Running Tamper Protection Removal command..." -ForegroundColor Yellow
			Start-Process -FilePath "$SEDcliPath" -ArgumentList "-TPoff password" -Wait
			Write-Host "Command completed." -ForegroundColor Green
		}
		else
		{
			Write-Warning "UNABLE TO LOCATE FILE: SEDcli.exe! TAMPER PROTECTION MUST BE DISABLED MANUALLY!"
			Write-Warning "$PWResults"
			## Stops Log.
			if ($PSVersionTable.PSVersion.Major -ge 3)
			{
				Write-Warning "Stopping log.."
				Stop-Transcript
			}
			## Exit script
			exit
		}
	}
	else
	{
		Write-Host "No Tamper Protection..." -ForegroundColor Green
		Write-Host "Continuing to remove Sophos Software..." -ForegroundColor Green
	}
}

function SophosRemoval ()
{
	
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
	Remove-Item -Path "C:\Temp\mbstcmd.exe" -Force
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
	## Calling Sophos TP Removal function
	SophosTPRemoval
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