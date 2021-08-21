
# Authored by: Adam H. Meadvin 
# Email: h3rbert@protonmail.ch
# GitHub: @GhostMach 
# Creation Date: 5 June 2021

<#
.SYNOPSIS
Function: Start-HKLMAppUninstall
Paramaters: 'AppName', 'ExcludeAppVersion', 'AppProcess'
Switches: 'Credential', 'Search', 'RemovePSDrive'
.DESCRIPTION
Uninstalls applications found in the HKEY_LOCAL_MACHINE registry with an uninstall string value that uses an MSIEXEC.
Please also use the -Search switch to examine if an application exists before running full uninstall command.
Note some applications WILL NOT uninstall if the application or its dependencies are running; ergo find the app process to stop.
.EXAMPLE
Start-HKLMAppUninstall "Salesforce for Outlook" "3.4.08.222" "OUTLOOK, SfdcMsOl" -RemovePSDrive

Uninstalls 'Salesforce for Outlook', but excludes any installation with version '3.4.08.222' and will shutdown Outlook & Salesforce applications if are running.
The -RemovePSDrive switch will disconnect the temporary drives created to map the registry hives once the uninstall routine has completed.
#>



function Start-HKLMAppUninstall{
	[cmdletbinding(SupportsPaging = $true)]
	param (
	[Parameter (Mandatory=$true, position=0)][string]$AppName, [Parameter (position=1)][string]$ExcludeAppVersion, `
	[Parameter (position=2)][string]$AppProcess, [Parameter (position=3)][switch]$Credential, `
	[Parameter (position=4)][switch]$Search, [Parameter (position=5)][switch]$RemovePSDrive
	)
#	Creates new (temporary) drive, named "Uninstall" that points to the x64 Local_Machine registry.
	if(!(Get-PSDrive | Where-Object { $_.Name -eq "Uninstall" })){
	New-PSDrive -Name Uninstall -PSProvider Registry HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
	}

#	Creates new (temporary) drive, named "Uninstallx86" that points to the x86 (WOW6432) Local_Machine registry.
	if(!(Get-PSDrive | Where-Object { $_.Name -eq "Uninstallx86" })){
	New-PSDrive -Name Uninstallx86 -PSProvider Registry HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
	}

	$UninstallApps = Get-ChildItem -Path Uninstall:
	$Uninstallx86 = Get-ChildItem -Path Uninstallx86:
	$UninstallApps += $Uninstallx86

#	If-else statement that uses a registry's 'DisplayName' value to verify if application is installed.
	
	if(!($UninstallApps | Where-Object -FilterScript { $_.GetValue("DisplayName") -eq $AppName })){
		Write-Host "`n$AppName " -NoNewLine -Foreground Red
		Write-Host "is " -NoNewLine
		Write-Host "NOT Installed in the Local Machine Registry " -NoNewLine -Foreground Red
		Write-Host "- Please use the correct 'Display Name' for the application in question if app is currently installed in this registry."
		Write-Host "`n**HINT**" -NoNewLine -Foreground Yellow
		Write-Host " One can find the " -NoNewLine 
		Write-Host "'Display Name'" -NoNewLine -Foreground Yellow
		Write-Host " of an application through the " -NoNewLine
		Write-Host "'Add or remove programs'" -NoNewLine -Foreground Yellow 	
		Write-Host " section of the Windows " -NoNewLine
		Write-Host "'System settings'." -Foreground Yellow
	} else {

#		'Stop-AppProcess' function written to terminate any open application(s) that could prevent successful uninstall of (desired) application.
#		$AppProcessParam accepts multiple arguments that are 'split' or seperated by commas or whitespace.
	
		function Stop-AppProcess {
			[cmdletbinding()]
			Param (
			[Parameter (Mandatory=$True, position=0)][AllowEmptyString()][string]$AppProcessParam
			)
		
		
		
#			'AppProcessExit' function written with "While" loop that will execute ONLY if process has NOT stopped, which will
#			incrementally pause script every 9 seconds--for up to 36 seconds before exiting loop and resume script's routine.

			function AppProcessExit {
			[cmdletbinding()]
			Param (
			[Parameter (Mandatory=$True, position=0)][AllowEmptyString()][string]$AppProcessParam
			)			
				$ProcessCheck = (Get-Process | Where-Object { $_.ProcessName -Match $AppProcessParam}).HasExited
				While($ProcessCheck -eq $False){
				Start-Sleep -s 45
				$ProcessCheck = $True			
				}
			}		

			if($AppProcessParam -ne ""){
				if($AppProcessParam -match ',\s'){
					$AppProcessParamSplit = $AppProcessParam -split ", "
					foreach($AppProcessParamInstance in $AppProcessParamSplit){
						$ProcessRunning = $(Get-Process | Where-Object { $_.ProcessName -eq $AppProcessParamInstance}) -ne $null
						if($ProcessRunning){
							Stop-Process -Name $AppProcessParamInstance -Force
							AppProcessExit $AppProcessParamInstance
						}
					}
				} elseif($AppProcessParam -match ','){
					$AppProcessParamSplit = $AppProcessParam -split ","
					foreach($AppProcessParamInstance in $AppProcessParamSplit){
						$ProcessRunning = $(Get-Process | Where-Object { $_.ProcessName -eq $AppProcessParamInstance}) -ne $null
						if($ProcessRunning){
							Stop-Process -Name $AppProcessParamInstance -Force
							AppProcessExit $AppProcessParamInstance
						}
					}
				} else{
					$ProcessRunning = $(Get-Process | Where-Object { $_.ProcessName -eq $AppProcessParam}) -ne $null					
					if($ProcessRunning){
						Stop-Process -Name $AppProcessParam -Force
						AppProcessExit $AppProcessParam
					}
				}
				
			}
		
		}

#		'New-UninstallString' function written to reformat the original (MSI) "uninstall string" (registry value) and convert any "/i" switch found
#		to an "x" switch, in addition to appending a "/q" switch to the "uninstall string" so it may run in silent mode.
	
		function New-UninstallString {
			[cmdletbinding()]
			Param (
			[Parameter (Mandatory=$true, position=0)][string]$AppInstanceParam
			)
		
			if($AppInstanceParam -match '\/(i|I)\{'){
				$AppInstanceConv = $AppInstanceParam -replace "\/(i|I)\{", "/X{"
				$AppUninstallFormatted = "$AppInstanceConv /q"
			} else {
				$AppUninstallFormatted = "$AppInstanceParam /q"
			}
		
			return $AppUninstallFormatted
		}

#		'Write-AppInfo' function exists for the '-Search' switch's 'else' statements to uniformally output information related to an installed application.

		function Write-AppInfo {
			[cmdletbinding()]		
			param (
			[Parameter (Mandatory=$true, position=0)][string]$AppNameParam, [Parameter (Mandatory=$true, position=1)][string]$AppDisplayVersionParam, `
			[Parameter (Mandatory=$true, position=2)][string]$AppHKLMLocationInstanceParam, [Parameter (Mandatory=$true, position=3)] [string]$AppUninstallValParam, `
			[Parameter (Mandatory=$true, position=4)][AllowEmptyString()][string]$AppInstallLocationParam, [Parameter (Mandatory=$true, position=5)] [string]$LocalUserNameParam
			)
		
			Write-Host "`n$AppNameParam v. $AppDisplayVersionParam has been installed in the Local Machine Registry with the following information: " -Foreground Yellow
			Write-Host "Registry hive location: " -NoNewLine
			Write-Host "$AppHKLMLocationInstanceParam" -Foreground Green
			Write-Host "Uninstall String: " -NoNewLine
			Write-Host "$AppUninstallValParam" -Foreground Green
			if($AppInstallLocationParam -ne ""){
				Write-Host "Current install location: " -NoNewLine
				Write-Host "$AppInstallLocationParam" -Foreground Cyan
			} elseif($AppInstallLocationParam -Match "C:\\Users\\"){
				Write-Host "On User Profile: " -NoNewLine
				Write-Host $LocalUserNameParam -Foreground Green
			} else{
				Write-Host "Current install location: " -NoNewLine
				Write-Host "value is not listed as an entry in this registry hive location." -Foreground Red
			}
		
		}

#		'Test-Uninstall' function written to confirm if uninstall string successfully removed app from Local Machine registry.
	
		function Test-Uninstall {
			[cmdletbinding()]
			Param (
			[Parameter (Mandatory=$true, position=0)][string]$UninstallParam, `
			[Parameter (Mandatory=$true, position=1)][string]$Uninstallx86Param, `
			[Parameter (Mandatory=$true, position=2)][string]$AppNameParam, `
			[Parameter (Mandatory=$true, position=3)][string]$AppDisplayVersionParam, `
			[Parameter (position=4)][AllowEmptyString()][string]$UsersParam
			)
		
			$UninstallAppsVer = Get-ChildItem -Path $UninstallParam
			$Uninstallx86Ver = Get-ChildItem -Path $Uninstallx86Param
			$UninstallAppsVer += $Uninstallx86Ver

			$Verification = $($UninstallAppsVer | Where-Object -FilterScript { $_.GetValue("DisplayName") -eq $AppNameParam }).Name -eq $null
		
			if($UsersParam -ne ""){
				if($Verification) {
					Write-Host "Success - uninstalled $AppNameParam v. $AppDisplayVersionParam for user: " -Foreground Cyan -NoNewLine
					Write-Host $UsersParam -Foreground Green
				} else {
					Write-Host "Unsuccesful removal from user profile: " -Foreground Red -NoNewLine
					Write-Host $UsersParam -Foreground Magenta
				}
		
			} else{
				if($Verification){            
					Write-Host "Success - Uninstalled $AppNameParam v. $AppDisplayVersionParam from system." -Foreground Cyan
				} else {            
					Write-Host "Unsuccesful removal from system." -Foreground Red
				}			
			}
			
		}
	
#		Credit to "Kris Powell" of PDQ.com for publishing code to find local users in regitry hive.
#		Site URL: "https://www.pdq.com/blog/modify-the-registry-of-another-user/"
#		Get Username, SID, and location of ntuser.dat for all users
		$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
		$ProfileList = gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | 
		Select  @{name="SID";expression={$_.PSChildName}}, 
				@{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
				@{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}

#		Get all user SIDs found in HKEY_USERS (ntuser.dat files that are loaded)
		$LoadedHives = gci Registry::HKEY_USERS | ? {$_.PSChildname -match $PatternSID} | Select @{name="SID";expression={$_.PSChildName}}

#		Get all users that are not currently logged-in.
		$UnloadedHives = Compare-Object $ProfileList.SID $LoadedHives.SID | Select @{name="SID";expression={$_.InputObject}}, UserHive, Username
	
		$CurrentUser = ($(Get-WmiObject -Class Win32_ComputerSystem | Select-Object username).username -split "\\")[1]
		$MachName = $env:ComputerName
		$AppHKLMLocation = ($UninstallApps | Where-Object -FilterScript { $_.GetValue("DisplayName") -eq $AppName }).Name
		
#		Nested loop sequence that starts with values stored in $AppHKLMLocation variable and then compares results with what's stored in individual
#		user profile(s) found on machine thru $ProfileList variable.

		foreach($AppHKLMLocationInstance in $AppHKLMLocation){
			:first
			foreach ($item in $ProfileList){
				if ($item.SID -in $UnloadedHives.SID){reg load HKU\$($Item.SID) $($Item.UserHive) | Out-Null}
		
				$AppHKLMLocationInstanceReFormed = $AppHKLMLocationInstance -replace "HKEY_LOCAL_MACHINE", "HKLM:"
				$AppUninstallVal = 	(Get-ItemProperty -Path $AppHKLMLocationInstanceReFormed).UninstallString
				$AppDisplayVersion = (Get-ItemProperty -Path $AppHKLMLocationInstanceReFormed).DisplayVersion
				$AppInstallLocation = (Get-ItemProperty -Path $AppHKLMLocationInstanceReFormed).InstallLocation
				$LocalUserName = $item.Username
				$AppUninstallMSI = New-UninstallString $AppUninstallVal

		
				if($Search){
					if($ExcludeAppVersion -ne ""){
						if($ExcludeAppVersion -NotMatch '^[\d\.]{1,25}'){
							Write-Host "`nUnable to process request with " -NoNewLine
							Write-Host "incorrect syntax entered" -NoNewLine -Foreground Red
							Write-Host " based on the following '-ExcludeAppVersion' parameter: " -NoNewLine
							Write-Host $ExcludeAppVersion -Foreground Red
							Write-Host "`nPlease enter a valid (version) number, seperated by periods if required."
							break
						} else {				
							if($ExcludeAppVersion -eq $AppDisplayVersion){
								Write-Host "`n$AppName v. $AppDisplayVersion" -NoNewLine -Foreground Yellow
								Write-Host " is" -NoNewLine
								Write-Host " currently installed" -NoNewLine -Foreground Green
								Write-Host " and therefore has been excluded from this search based on the '-ExcludeAppVersion' parameter entered: " -NoNewLine
								Write-Host "$ExcludeAppVersion" -Foreground Magenta
								break :first
							} else {
								Write-Host "`nAnother instance(s) of this application version have been found based on the '-ExcludeAppVersion' parameter entered: " -NoNewLine
								Write-Host "$ExcludeAppVersion" -Foreground Magenta
								Write-AppInfo $AppName $AppDisplayVersion $AppHKLMLocationInstance $AppUninstallVal $AppInstallLocation $LocalUserName
								break :first
							}
						}
					} else {
						Write-AppInfo $AppName $AppDisplayVersion $AppHKLMLocationInstance $AppUninstallVal $AppInstallLocation $LocalUserName
						break :first
					}
			
				} elseif ($ExcludeAppVersion -eq $AppDisplayVersion){
					if (($AppDisplayVersion -eq $ExcludeAppVersion) -And ($AppInstallLocation -Match "C:\\Users\\")){
					Write-Host "`n$AppName v. $ExcludeAppVersion " -NoNewLine -Foreground Yellow
					Write-Host "will " -NoNewLine
					Write-Host "NOT be uninstalled " -NoNewLine -Foreground Yellow
					Write-Host "for user: " -NoNewLine
					Write-Host $LocalUserName -Foreground Green
					break :first
				} else {
					Write-Host "`n$AppName v. $ExcludeAppVersion " -NoNewLine -Foreground Yellow
					Write-Host "will " -NoNewLine
					Write-Host "NOT be uninstalled " -NoNewLine -Foreground Yellow
					Write-Host "from system."
					break :first
				}

#				'Elseif' used to test if the app to be uninstalled is located in a user's local file directory, where if '-Credential' switch is enabled
#				then PowerShell will prompt for user's credentials to remove application.			
				} elseif ($AppInstallLocation -match "C:\\Users\\"){			
					if (!($Credential) -and ($AppInstallLocation -NotMatch "C:\\Users\\$CurrentUser\\")){
						Write-Host "Can NOT uninstall $AppName v. $AppDisplayVersion in user profile: $LocalUserName." -NoNewLine
						Write-Host " Use '-Credential' switch to uninstall." -Foreground Yellow
						break :first
					} elseif(($Credential) -and ($AppInstallLocation -NotMatch "C:\\Users\\$CurrentUser\\")){
						Stop-AppProcess $AppProcess
						Write-Progress -Activity "Uninstalling $AppName v. $AppDisplayVersion"
						Start-Process -FilePath cmd.exe -Credential $LocalUserName -ArgumentList '/c', $AppUninstallMSI -Wait
						Test-Uninstall "Uninstall:" "Uninstallx86:" $AppName $AppDisplayVersion $LocalUserName			
						break :first
					} else {
						Stop-AppProcess	$AppProcess
						Write-Progress -Activity "Uninstalling $AppName v. $AppDisplayVersion"
						Start-Process -FilePath cmd.exe -ArgumentList '/c', $AppUninstallMSI -Wait
						Test-Uninstall "Uninstall:" "Uninstallx86:" $AppName $AppDisplayVersion $CurrentUser		
						break :first
					}
			
				} elseif ($Credential){
					Stop-AppProcess $AppProcess
					$c = Get-Credential
					Write-Progress -Activity "Uninstalling $AppName v. $AppDisplayVersion"
					Start-Process -FilePath cmd.exe -ArgumentList '/c', $AppUninstallMSI -Credential $c -WorkingDirectory 'C:\Windows\System32' -Wait
					Test-Uninstall "Uninstall:" "Uninstallx86:" $AppName $AppDisplayVersion	
					break :first
			
				} else {
					Stop-AppProcess $AppProcess
					Write-Progress -Activity "Uninstalling $AppName v. $AppDisplayVersion"
					Start-Process -FilePath cmd.exe -ArgumentList '/c', $AppUninstallMSI -Wait
					Test-Uninstall "Uninstall:" "Uninstallx86:" $AppName $AppDisplayVersion		
					break :first
				}
			}
		}
	}
		
	if($RemovePSDrive){
		Remove-PSDrive -Name Uninstall
		Remove-PSDrive -Name Uninstallx86
	}
}