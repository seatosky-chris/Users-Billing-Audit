###
# File: \User_Billing_Update.ps1
# Project: Users Billing Audit
# Created Date: Tuesday, August 2nd 2022, 10:36:05 am
# Author: Chris Jantzen
# -----
# Last Modified: Fri Jul 21 2023
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
# 2023-07-21	CJ	Modified customer billing page update to remove any old per-device billing info.
# 2023-03-20	CJ	Fixed bug where we weren't sending O365 unmatched info, and changed to send emails if there are unmatched accounts (AD or O365).
###

#Requires -RunAsAdministrator
param (
	$config = $false,
	[switch]$UserAudit = $false, [switch]$BillingUpdate = $false
)
Set-ExecutionPolicy Unrestricted

#####################################################################
### Load Variables from external file
### Make sure you setup your variables in the User Audit - Constants.ps1 file
. "$PSScriptRoot\User Audit - Constants.ps1"
. "$PSScriptRoot\O365Licenses.ps1"
$CustomOverview_FlexAssetID = 219027
$ScriptsLast_FlexAssetID = 251261
$GitHubVersion = "https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/currentversion.txt"
$UpdateFile = "https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/update.ps1"
#####################################################################
Write-Host "User audit starting..."

### Load Variables from external file
### Make sure you setup your variables in the User Audit - Constants.ps1 file
### Or if this is a central audit for customers that are cloud based, create a Constants folder
### and include a Constants file for each customer to be audited. Then use the $config param to set
### the config file to be used for the current run. Set $config to the full name of the file (without the file extension). e.g. "BCCP-Config"
if (!$config) {
	. "$PSScriptRoot\User Audit - Constants.ps1"
} elseif (Test-Path -Path "$PSScriptRoot\Constants\$config.ps1") {
	. "$PSScriptRoot\Constants\$config.ps1"
} else {
	Write-Error "Config file not found! Exiting..."
	exit
}

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

if (($CheckEmail -and $EmailType -eq "O365") -or ($CheckAD -and $ADType -eq "Azure")) {
	# This module needs to be imported before others so lets do this right away
	If (Get-Module -ListAvailable -Name "MSAL.PS") {
		Import-Module MSAL.PS
	} else {
		Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		Install-Module -Name MSAL.PS
	}
}

# Setup logging
If (Get-Module -ListAvailable -Name "PSFramework") {Import-module PSFramework} Else { install-module PSFramework -Force; import-module PSFramework}
$logFile = Join-Path -path "$PSScriptRoot\ErrorLogs" -ChildPath "log-$(Get-date -f 'yyyyMMddHHmmss').txt";
Set-PSFLoggingProvider -Name logfile -FilePath $logFile -Enabled $true;
Write-PSFMessage -Level Verbose -Message "Starting audit."

# Check for any required updates
$UpdatesAvailable = $false
$CurrentVersion = Get-Content "$PSScriptRoot\currentversion.txt"
Write-PSFMessage -Level Verbose -Message "Current Version: $CurrentVersion"
$NextVersion = $null
try {
	$NextVersion = (New-Object System.Net.WebClient).DownloadString($GitHubVersion).Trim([Environment]::NewLine)
	Write-PSFMessage -Level Verbose -Message "Next Version: $NextVersion"
} catch [System.Exception] {
	Write-Host $_ -ForegroundColor Red
	Write-PSFMessage -Level Warning -Message "Failed to get 'next version' from repo."
}

function FixFilePermissions($Path) {
	$CurUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	$CurUserAccount = New-Object System.Security.Principal.Ntaccount($CurUser)
	$acl = Get-Acl -Path $Path
	$accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($CurUser, 'FullControl', 'Allow')
	$acl.SetOwner($CurUserAccount)
	$acl.SetAccessRule($accessrule)
	Set-Acl -Path $Path -AclObject $acl
}

if ($NextVersion -ne $null -and $CurrentVersion -ne $NextVersion) {
	# An update is most likely available, but make sure
	$curr = $CurrentVersion.Split('.')
	$next = $NextVersion.Split('.')
	for($i=0; $i -le ($curr.Count -1); $i++)
	{
		if ([int]$next[$i] -gt [int]$curr[$i])
		{
			$UpdatesAvailable = $true
			break
		}
	}

	if ($UpdatesAvailable) {
		Write-Host "Updates Found!" -ForegroundColor Yellow
		Write-Host "CURRENT VERSION: $CurrentVersion" -ForegroundColor Yellow
		Write-Host "NEXT VERSION: $NextVersion" -ForegroundColor Yellow
		Write-Host "Updating script..." -ForegroundColor Yellow
		Write-PSFMessage -Level Verbose -Message "Update required."

		$UpdatePath = "$PSScriptRoot\update.ps1"
		(New-Object System.Net.Webclient).DownloadFile($UpdateFile, $UpdatePath)
		FixFilePermissions -Path $UpdatePath
		Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList '-File', $UpdatePath, "User_Billing_Update", $UserAudit, $BillingUpdate -NoNewWindow
		Write-PSFMessage -Level Verbose -Message "Update complete. Restart."
		exit
	}
}
### Update check complete

Import-module ITGlueAPI
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

# Install our custom version of the CosmosDB module (if necessary)
$CosmosDBModule = Get-Module -ListAvailable -Name "CosmosDB"

# If installed and not version 0.0.1 (my custom version), uninstall
if ($CosmosDBModule -and ($CosmosDBModule.Version.Major -ne 0 -or $CosmosDBModule.Version.Minor -ne 0 -or $CosmosDBModule.Version.Build -ne 1)) {
	Write-Output "Removing old version of CosmosDB module..."
	Remove-Module -Name "CosmosDB"
	Uninstall-Module -Name "CosmosDB"
	Remove-Item -LiteralPath "C:\Program Files\WindowsPowerShell\Modules\CosmosDB" -Force -Recurse -ErrorAction Ignore
	$CosmosDBModule = $false
}

if (!$CosmosDBModule) {
	$unzipPath = "C:\temp"
	if (!(test-path $unzipPath)) {
		New-Item -ItemType Directory -Force -Path $unzipPath
	}
	Expand-Archive "$PSScriptRoot\CosmosDB.zip" -DestinationPath $unzipPath
	Move-Item -Path "$($unzipPath)\CosmosDB" -Destination "C:\Program Files\WindowsPowerShell\Modules\" -Force
}
Import-module CosmosDB

Write-Host "Successfully imported required modules and configured the ITGlue API."
Write-PSFMessage -Level Verbose -Message "Configured ITGlue module."

if (($CheckEmail -and $EmailType -eq "O365") -or ($CheckAD -and $ADType -eq "Azure")) {
	Write-Host "Connecting to Azure..."
	$ClientCertificate = Get-Item "Cert:\LocalMachine\My\$($O365UnattendedLogin.CertificateThumbprint)"

	# Create base64 hash of certificate
	$CertificateBase64Hash = [System.Convert]::ToBase64String($ClientCertificate.GetCertHash())

	# Create JWT timestamp for expiration
	$StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
	$JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
	$JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

	# Create JWT validity start timestamp
	$NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
	$NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

	# Create JWT header
	$JWTHeader = @{
		alg = "RS256"
		typ = "JWT"
		# Use the CertificateBase64Hash and replace/strip to match web encoding of base64
		x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
	}

	# Create JWT payload
	$JWTPayLoad = @{
		# What endpoint is allowed to use this JWT
		aud = "https://login.microsoftonline.com/$($O365UnattendedLogin.TenantID)/oauth2/token"

		# Expiration timestamp
		exp = $JWTExpiration

		# Issuer = your application
		iss = $O365UnattendedLogin.AppID

		# JWT ID: random guid
		jti = [guid]::NewGuid()

		# Not to be used before
		nbf = $NotBefore

		# JWT Subject
		sub = $O365UnattendedLogin.AppID
	}

	# Convert header and payload to base64
	$JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
	$EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)

	$JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
	$EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)

	# Join header and Payload with "." to create a valid (unsigned) JWT
	$JWT = $EncodedHeader + "." + $EncodedPayload

	# Get the private key object of your certificate
	$PrivateKey = $ClientCertificate.PrivateKey

	# Define RSA signature and hashing algorithm
	$RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
	$HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256

	# Create a signature of the JWT
	$Signature = [Convert]::ToBase64String(
		$PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
	) -replace '\+','-' -replace '/','_' -replace '='

	# Join the signature to the JWT with "."
	$JWT = $JWT + "." + $Signature

	# Create a hash with body parameters
	$Body = @{
		client_id = $O365UnattendedLogin.AppID
		client_assertion = $JWT
		client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		scope = "https://graph.microsoft.com/.default"
		grant_type = "client_credentials"

	}

	$Url = "https://login.microsoftonline.com/$($O365UnattendedLogin.TenantID)/oauth2/v2.0/token"

	# Use the self-generated JWT as Authorization
	$Header = @{
		Authorization = "Bearer $JWT"
	}

	# Splat the parameters for Invoke-Restmethod for cleaner code
	$PostSplat = @{
		ContentType = 'application/x-www-form-urlencoded'
		Method = 'POST'
		Body = $Body
		Uri = $Url
		Headers = $Header
	}
	$AzGraphAuthToken = Invoke-RestMethod @PostSplat

	$AzGraphHeader = @{
		Authorization = "$($AzGraphAuthToken.token_type) $($AzGraphAuthToken.access_token)"
	}

	If (Get-Module -ListAvailable -Name "AzureAD") {
		Import-Module AzureAD
	} else {
		Install-Module -Name AzureAD
	}
	if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
		Connect-AzureAD -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -ApplicationId $O365UnattendedLogin.AppID -TenantId $O365UnattendedLogin.TenantId
	} else {
		Connect-AzureAD -AccountID $O365LoginUser
	}

	Write-Host "Successfully imported Azure related modules."
}

if ($CheckEmail) {
	# Connect to the mail service (it works better doing this first thing)
	if ($EmailType -eq "O365") {
		Write-Host "Connecting to Office 365..."
		# If using a version under 3, upgrade
		$Version = (Get-Module -ListAvailable -Name "ExchangeOnlineManagement").Version
		if ($Version -and $Version.Count -gt 1) {
			$Version = $Version | Sort-Object -Property Major -Descending | Select-Object -First 1
		}
		if ($Version -and $Version.Major -lt 3) {
			Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
			Update-Module -Name ExchangeOnlineManagement -Force
		}
		If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {
			Import-Module ExchangeOnlineManagement
		} else {
			Install-Module PowerShellGet -Force
			Install-Module -Name ExchangeOnlineManagement -Confirm:$false
		}

		if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
			Connect-ExchangeOnline -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -AppID $O365UnattendedLogin.AppID -Organization $O365UnattendedLogin.Organization -ShowProgress $true -ShowBanner:$false
		} else {
			Connect-ExchangeOnline -UserPrincipalName $O365LoginUser -ShowProgress $true -ShowBanner:$false
		}
		Write-PSFMessage -Level Verbose -Message "Imported O365 related modules."
	} elseif ($EmailType -eq "Exchange") {
		If (Get-Module -ListAvailable -Name "CredentialManager") {
			Import-Module CredentialManager
		} else {
			Install-Module -Name CredentialManager
		}
		if ($ExchangeServerFQDN) {
			Write-Host "Connecting to exchange server..."
			$Credential = Get-StoredCredential -Target 'ExchangeServer'
			if (!$Credential) {
				Write-Error "No Exchange credentials were found. Please run the basic/interactive User Audit and add the credentials when prompted."
			}
			$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServerFQDN/PowerShell/" -Authentication Kerberos -Credential $Credential
			Import-PSSession $Session -DisableNameChecking
			Write-PSFMessage -Level Verbose -Message "Connected to Exchange Server session."
		}
	}
	Write-Host "Successfully imported email related modules."
}

###################################################
##### Get Data and Start the matching process #####
###################################################

# Get the contact list from IT Glue
Write-Host "Querying IT Glue..."
$FullContactList = Get-ITGlueContacts -page_size 1000 -organization_id $OrgID

if ($FullContactList.Error) {
	Write-Host "An error occured when trying to use the IT Glue API!" -ForegroundColor Red
	Write-Host "Error: $($FullContactList.Error)" -ForegroundColor Red
	Write-Host "Please fix the issue then try again."
	Write-PSFMessage -Level Error -Message "Could not get contact list from ITG. Error: $($FullContactList.Error)"
	Read-Host "Press ENTER to close..." 
	exit
} else {
	$FullContactList = $FullContactList.data
}

if ($FullContactList.Count -gt 999) {
	$FullContactList = @()
	$i = 1
	while ($i -le 10 -and ($FullContactList | Measure-Object).Count -eq (($i-1) * 500)) {
		$FullContactList += (Get-ITGlueContacts -page_size 500 -page_number $i -organization_id $OrgID).data
		Write-Host "- Got contact set $i"
		$TotalContacts = ($FullContactList | Measure-Object).Count
		Write-Host "- Total: $TotalContacts"
		$i++
	}
}

$ContactCount = ($FullContactList | Measure-Object).Count
Write-Host "Got the contact data from IT Glue. $ContactCount contacts were found."
Write-PSFMessage -Level Verbose -Message "Got '$($ContactCount)' contacts from IT Glue."

# Get the list of locations for later
$Locations = (Get-ITGlueLocations -org_id $OrgID).data
$Locations.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$Locations | ForEach-Object { $_.attributes.id = $_.id }
$Locations = $Locations.attributes
$HasMultipleLocations = $false
if (($Locations | Measure-Object).Count -gt 1) {
	$HasMultipleLocations = $true
}
Write-PSFMessage -Level Verbose -Message "Got $(($Locations | Measure-Object).Count) locations from IT Glue."

# Get the organizations name
$OrganizationInfo = (Get-ITGlueOrganizations -id $OrgID).data
$OrgFullName = $OrganizationInfo[0].attributes.name
$OrgShortName = $OrganizationInfo[0].attributes."short-name"

# Get the list of contacts that are considered an employee type
$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
$EmployeeContacts = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $EmployeeContactTypes -or !$_."contact-type-name"}

$UserCleanupUpdateRan = $false
$UserBillingUpdateRan = $false
$UserO365ReportUpdated = $false


################
#### Running a User Audit
#### This will check for issues and open a ticket to get them fixed
#### At the end it will update the device audit DB, if applicable
#### Use parameter -UserAudit $true   (default off)
################
if ($UserAudit) {
	Write-PSFMessage -Level Verbose -Message "Starting User Audit."

	# Get the existing matched list from the user audit	
	New-Item -ItemType Directory -Force -Path "C:\billing_audit" | Out-Null
	if (!$config) {
		$auditFilesPath = "C:\billing_audit\contacts.json"
	} else {
		if (!(Test-Path -Path "C:\billing_audit\$($OrgShortName)")) {
			New-Item -Path "C:\billing_audit\$($OrgShortName)" -ItemType Directory | Out-Null
		}
		$auditFilesPath = "C:\billing_audit\$($OrgShortName)\contacts.json"
	}
	if (Test-Path $auditFilesPath) {
		$MatchedContactList = Get-Content -Path $auditFilesPath -Raw | ConvertFrom-Json
		Write-PSFMessage -Level Verbose -Message "Imported existing matched list."
	}

	if ($CheckAD) {
		# Get all AD users
		Write-Host "===================================" -ForegroundColor Blue
		Write-Host "Getting AD users to look for disabled users."
		Write-PSFMessage -Level Verbose -Message "Getting AD users."

		if ($ADType -eq "Azure") {
			## Azure
			$ApiUrl = "https://graph.microsoft.com/beta/users?`$select=id,displayName,givenName,surname,userPrincipalName,accountEnabled,signInActivity,city,department,jobTitle,mail,mailNickname,userType,assignedLicenses&`$top=120"
			$FullADUsers = @()
	
			while ($null -ne $ApiUrl) {
				$Response = Invoke-RestMethod -Uri $ApiUrl -Headers $AzGraphHeader -Method Get -ContentType "application/json"
				if ($Response.value) {
					$FullADUsers += $Response.value
				}
				$ApiUrl = $Response.'@odata.nextlink'
			}
	
			if (!$FullADUsers) {
				Write-PSFMessage -Level Warning -Message "Could not connect to the MS Graph Beta API, falling back to the Get-AzureADUser command."
				$FullADUsers = Get-AzureADUser -All $true
			}
	
			$FullADUsers = $FullADUsers | 
								Select-Object -Property @{Name="Id"; E={if ($_.Id) { $_.Id } else { $_.ObjectId }}}, @{Name="Name"; E={$_.DisplayName}}, GivenName, Surname, @{Name="Username"; E={$_.UserPrincipalName}}, 
									@{Name="EmailAddress"; E={$_.mail}}, @{Name="Enabled"; E={$_.AccountEnabled}}, @{Name="Description"; E={""}}, SignInActivity,
									City, Department, @{Name="Division"; E={""}}, @{Name="Title"; E={$_.JobTitle}}, MailNickname, UserType, AssignedLicenses
			$FullADUsers = $FullADUsers | Where-Object  { $_.UserType -eq "Member" }
	
			Write-Host "Got AD accounts. Getting associated AD group memberships."
			$i = 0
			$ADUserCount = ($FullADUsers | Measure-Object).Count
			$FullADUsers | ForEach-Object {
				$i++
				$_ | Add-Member -MemberType NoteProperty -Name Groups -Value $null
				$_ | Add-Member -MemberType NoteProperty -Name LastLogonDate -Value $null
				$_ | Add-Member -MemberType NoteProperty -Name UsernameStart -Value $null
				$_.Groups = @((Get-AzureADUserMembership -ObjectId $_.Id | Select-Object DisplayName).DisplayName)
				$_.LastLogonDate = if($_.signInActivity.lastSignInDateTime) { [DateTime]$_.signInActivity.lastSignInDateTime } else {$null}
				$pos = $_.Username.IndexOf("@")
				$_.UsernameStart = $_.Username.Substring(0, $pos)
				[int]$PercentComplete = ($i / $ADUserCount * 100)
				Write-Progress -Activity "Getting AD Group Memberships" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%")
			}
			Write-Progress -Activity "Getting AD Group Memberships" -Status "Ready" -Completed
	
			$ADEmployees = $FullADUsers
		} else {
			$FullADUsers = Get-ADUser -Filter * -Properties * | 
								Select-Object -Property Name, GivenName, Surname, @{Name="Username"; E={$_.SamAccountName}}, EmailAddress, Enabled, 
												Description, LastLogonDate, @{Name="PrimaryOU"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)')[0].Groups[2]}}, 
												@{Name="OUs"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)').Value -replace 'OU='}}, 
												@{Name="PrimaryCN"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)')[0].Groups[2]}}, 
												@{Name="CNs"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)').Value -replace 'CN='}}, 
												City, Department, Division, Title
			Write-PSFMessage -Level Verbose -Message "Got $(($FullADUsers | Measure-Object).Count) users from AD."

			# Get groups
			$FullADUsers | ForEach-Object {
				$_ | Add-Member -MemberType NoteProperty -Name Groups -Value $null
				$ADGroups = Get-ADPrincipalGroupMembership $_.Username
				if ($ADGroups -and $EmailOnlyGroupsOUIgnore) {
					foreach ($IgnoreOU in $EmailOnlyGroupsOUIgnore) {
						$ADGroups = $ADGroups | Where-Object { $_.distinguishedName -notlike "OU=$($IgnoreOU)," }
					}
				}
				$_.Groups = @(($ADGroups | Select-Object Name).Name)
			}

			if ($ADIncludeSubFolders) {
				$ADEmployees = @()
				foreach ($User in $FullADUsers) {
					$Intersect = $User.OUs | Where-Object {$ADUserFolders -contains $_}
					if ($Intersect) {
						$ADEmployees += $User
					} else {
						$Intersect = $User.CNs | Where-Object {$ADUserFolders -contains $_}
						if ($Intersect) {
							$ADEmployees += $User
						}
					}
				}
			} else {
				$ADEmployees = $FullADUsers | Where-Object {$_.PrimaryOU -in $ADUserFolders}
				if (($ADEmployees | Measure-Object).Count -lt (($EmployeeContacts | Measure-Object).Count / 2)) {
					$ADEmployees += $FullADUsers | Where-Object {$_.PrimaryCN -in $ADUserFolders}
				}
			}
		}

		$ADMatches = New-Object -TypeName "System.Collections.ArrayList"
		$NoMatch = @()
		$NoMatchButIgnore = @() # For IT Glue contacts without an AD account
		foreach ($User in $EmployeeContacts) {
			$ADMatch = @()
			$Emails = $User."contact-emails"
			$PrimaryEmail = ($Emails | Where-Object { $_.primary }).value
			$FirstName = $User."first-name"
			$LastName = $User."last-name"
			$FullName = $User.Name
			$Type = $User."contact-type-name"
			$Notes = $User.notes

			# Check notes for "# No AD Account", ignore these accounts
			if ((!$EmailOnlyHaveAD -and $Type -eq "Employee - Email Only") -or $Notes -like '*# No AD Account*') {
				$NoMatchButIgnore += $User
				continue
			}

			# Check $MatchedContactList (from the user audit script) for the latest match
			$ExistingMatch = $MatchedContactList | Where-Object { $_.id -eq $User.id }
			if ($ExistingMatch) {
				if ($ExistingMatch."AD-Connected?" -eq $false -or !$ExistingMatch."AD-Username") {
					$NoMatchButIgnore += $User
					continue
				} else {
					$UsernameMatch = $ExistingMatch | Select-Object "AD-Username"
					$ADMatch += $ADEmployees | Where-Object { $_.Username -like $UsernameMatch }
				}
			}
			
			# Look for a match if no match already exists (likely a new contact)
			while (!$ADMatch) {
				# Check notes for a username
				$ADMatch += $ADEmployees | Where-Object { 
					if ($ADType -eq "Azure") {
						$Notes -match ".*(Username: (" + $_.Username + "|" + $_.mailNickname + "|" + $_.UsernameStart + ")(\s|W|$)).*" 
					} else {
						$Notes -match ".*(Username: " + $_.Username + "(\s|W|$)).*" 
					}
				}
				if ($ADMatch) { break; }
				# Primary email search
				if ($PrimaryEmail) {
					$ADMatch += $ADEmployees | Where-Object { $_.EmailAddress -like $PrimaryEmail }
				}
				# First and last name
				$ADMatch += $ADEmployees | Where-Object { $_.GivenName -like $FirstName -and $_.Surname -like $LastName }
				if ($ADMatch) { break; }
				if ($LastName -eq ".") {
					$ADMatch += $ADEmployees | Where-Object { $_.GivenName -like $FirstName -and $_.Surname -like "" }
					if ($ADMatch) { break; }
				}
				# Other emails & first name if more than 1 is found
				foreach ($Email in $Emails) {
					if (!$Email) { continue; }
					if ($Email.primary) { continue; }
					$ITGlueEmailUses = $EmployeeContacts | Where-Object { $_."contact-emails" -contains $Email.value }
					$ADEmailUses = $ADEmployees | Where-Object { $_.EmailAddress -like $Email.value }
					if (($ADEmailUses | Measure-Object).Count -lt 1) { continue; }
					if (($ITGlueEmailUses | Measure-Object).Count -le 1 -and ($ADEmailUses | Measure-Object).Count -le 1) {
						# only 1 match
						$ADMatch = $ADEmployees | Where-Object { $_.EmailAddress -like $Email.value }
						if ($ADMatch) { break; }
					} else {
						# more than 1 match, check first name as well
						$ADMatch = $ADEmployees | Where-Object { $_.EmailAddress -like $Email.value -and $_.Name -like "*" + $FirstName + "*"}
						if ($ADMatch) { break; }
					}
				}
				break;
			}

			# If more than 1 match, narrow down to 1
			$ADMatch = $ADMatch | Sort-Object Username -Unique
			if ($ADMatch -and ($ADMatch | Measure-Object).Count -gt 1) {
				$MostLikelyMatches = $ADMatch | Where-Object { $_.GivenName -like $FirstName -and $_.Surname -like $LastName }
				if (($MostLikelyMatches | Measure-Object).Count -gt 1) {
					$ADMatch = $ADMatch | Select-Object -First 1
				} else {
					$ADMatch = $MostLikelyMatches
				} 
			}

			# Add to the Match or NoMatch array
			if ($ADMatch) {
				# Add the AD email first to help with the O365 match later
				if ($ADMatch.EmailAddress) {
					$ADEmail = [PSCustomObject]@{
						primary = $false
						value = $ADMatch.EmailAddress
						"label-name" = 'AD Email'
					}
					$User."contact-emails" += $ADEmail
					$EmployeeContacts = $EmployeeContacts | Where-Object { $_.ID -ne $User.ID }
					$EmployeeContacts += $User
				}

				$match = [PSCustomObject]@{
					id = $User.ID
					name = $FullName
					type = $Type
					itglue = $User
					ad = $ADMatch
				}
				$ADMatches.Add($match) | Out-Null
			} else {
				if ($Type -ne 'Terminated' -and $Type -ne 'Employee - Email Only' -and $Type -ne 'Employee - On Leave') {
					$NoMatch += $User
				}
			}
		}
		$ADMatchCount = ($ADMatches | Measure-Object).Count
		Write-Host "Finished matching all IT Glue contacts to their AD accounts. $ADMatchCount matches were made."
		Write-PSFMessage -Level Verbose -Message "Matched: all IT Glue contacts to AD accounts. $ADMatchCount matches made."
	}

	if ($CheckAD) {
		# Get the existing unmatched AD list from the user audit	
		if (!$config) {
			$auditFilesPath = "C:\billing_audit\unmatchedAD.json"
		} else {
			$auditFilesPath = "C:\billing_audit\$($OrgShortName)\unmatchedAD.json"
		}
		$OldUnmatchedADUsernames = @()
		if (Test-Path $auditFilesPath) {
			$OldUnmatchedAD = Get-Content -Path $auditFilesPath -Raw | ConvertFrom-Json
			if ($OldUnmatchedAD) {
				$OldUnmatchedADUsernames = $OldUnmatchedAD.Username
			}
		}

		$UnmatchedAD = $ADEmployees | Where-Object { $ADMatches.ad.Username -notcontains $_.Username } | Where-Object { $_.Enabled -eq "True" }
		Write-PSFMessage -Level Verbose -Message "Found $(($UnmatchedAD | Measure-Object).Count) unmatched AD accounts."
		$UnmatchedAD = $UnmatchedAD | Where-Object { $_.Username -notin $OldUnmatchedADUsernames } # filter out accounts that have already been reviewed
		Write-PSFMessage -Level Verbose -Message "Found $(($UnmatchedAD | Measure-Object).Count) new unmatched AD accounts."
	}

	if ($CheckEmail -and (($EmailType -eq "O365" -and $O365UnattendedLogin -and $O365UnattendedLogin.AppId) -or $EmailType -eq "Exchange")) {
		Write-Host "Getting $EmailType Mailboxes. This may take a minute..." -ForegroundColor 'black' -BackgroundColor 'red'
		Write-PSFMessage -Level Verbose -Message "Getting $EmailType Mailboxes."

		if ($EmailType -eq "O365") {
			$O365Mailboxes = Get-EXOMailbox -ResultSize unlimited -PropertySets Minimum, AddressList, Delivery, SoftDelete | 
				Select-Object -Property Name, DisplayName, Alias, PrimarySmtpAddress, EmailAddresses, 
					RecipientTypeDetails, Guid, UserPrincipalName, 
					DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled |
				Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
			Write-PSFMessage -Level Verbose -Message "Got $(($O365Mailboxes | Measure-Object).Count) mailboxes from O365."
			$DisabledAccounts = Get-AzureADUser -Filter "AccountEnabled eq false" | Select-Object -ExpandProperty UserPrincipalName
			$UnlicensedUsers = Get-AzureADUser | Where-Object {
				$licensed = $false
				for ($i = 0; $i -le ($_.AssignedLicenses | Measure-Object).Count ; $i++) { 
					if ([string]::IsNullOrEmpty($_.AssignedLicenses[$i].SkuId) -ne $true) { 
						$licensed = $true 
					} 
				} 
				if ($licensed -eq $false) { 
					return $true
				} else {
					return $false
				}
			} | Select-Object DisplayName, UserPrincipalName, @{N="FirstName"; E={$_."GivenName"}}, @{N="LastName"; E={$_."Surname"}}, @{N="Title"; E={$_."JobTitle"}}
			$UnlicensedUsers | Add-Member -MemberType NoteProperty -Name PrimarySmtpAddress -Value 'no license'
			$UnlicensedUsers | Add-Member -MemberType NoteProperty -Name EmailAddresses -Value @()
			$UnlicensedUsers | Add-Member -MemberType NoteProperty -Name RecipientTypeDetails -Value "None"

			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AccountDisabled -Value $false
			$O365Mailboxes | ForEach-Object { 
				if ($_.UserPrincipalName -in $DisabledAccounts) {
					$_.AccountDisabled = $true
				}
			}

			$LicensePlanList = Get-AzureADSubscribedSku
			$AzureUsers = Get-AzureADUser -All $true | Select-Object ObjectID, UserPrincipalName, AssignedLicenses, GivenName, Surname, JobTitle
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AssignedLicenses -Value @()
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AAD_ObjectID -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name PrimaryLicense -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null

			$O365Mailboxes | ForEach-Object { 
				if ($_.UserPrincipalName -in $AzureUsers.UserPrincipalName) {
					$Mailbox = $_
					$LicenseSkus = ($AzureUsers | Where-Object { $_.UserPrincipalName -eq $Mailbox.UserPrincipalName }).AssignedLicenses | Select-Object SkuId
					$Licenses = @()
					$LicenseSkus | ForEach-Object {
						$sku = $_.SkuId
						foreach ($license in $licensePlanList) {
							if ($sku -eq $license.ObjectId.substring($license.ObjectId.length - 36, 36)) {
								$Licenses += $license.SkuPartNumber
								break
							}
						}
					}
					$_.AssignedLicenses = $Licenses
					$_.PrimaryLicense = "None"

					foreach ($LicenseSku in $O365LicenseTypes.Keys) {
						if ($LicenseSku -in $Licenses) {
							$_.PrimaryLicense = $O365LicenseTypes[$LicenseSku]
							break
						}
					}



					$AzureUser = $AzureUsers | Where-Object { $_.UserPrincipalName -eq $Mailbox.UserPrincipalName }
					$_.AAD_ObjectID = $AzureUser.ObjectID
					$_.FirstName = $AzureUser.GivenName
					$_.LastName = $AzureUser.Surname
					$_.Title = $AzureUser.JobTitle
				}
			}
		} else {
			$O365Mailboxes = Get-Mailbox -ResultSize unlimited | 
				Select-Object -Property Name, DisplayName, Alias, PrimarySmtpAddress, EmailAddresses, SamAccountName, 
					RecipientTypeDetails, AccountDisabled, IsDirSynced, Guid,
					DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled |
				Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
			Write-PSFMessage -Level Verbose -Message "Got $(($O365Mailboxes | Measure-Object).Count) mailboxes from Exchange."
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastUserActionTime -Value $null
			$O365MailboxUsers =  Get-User -ResultSize unlimited | Select-Object Name, FirstName, LastName, Title

			for ($i = 0; $i -lt $O365Mailboxes.Count; $i++) {
				$O365MailboxUser = $O365MailboxUsers | Where-Object { $_.Name -like $O365Mailboxes[$i].Name }
				$O365Mailboxes[$i].FirstName = $O365MailboxUser.FirstName
				$O365Mailboxes[$i].LastName = $O365MailboxUser.LastName
				$O365Mailboxes[$i].Title = $O365MailboxUser.Title
			}
		}

		$MailboxCount = ($O365Mailboxes | Measure-Object).Count
		Write-Host "Got all $MailboxCount mailboxes. Now comparing them with IT Glue accounts."
		Write-PSFMessage -Level Verbose -Message "Got $MailboxCount mailboxes."

		# Cleanup the email list
		for ($i = 0; $i -lt $O365Mailboxes.Count; $i++) {
			$EmailAddresses = $O365Mailboxes[$i].EmailAddresses
			$EmailAddresses = $EmailAddresses | Where-Object { $_ -notmatch '^SPO\:SPO_.+' }
			$EmailAddresses = $EmailAddresses -replace '^SIP:|SMTP:', ''
			$O365Mailboxes[$i].EmailAddresses = $EmailAddresses
		}

		# Make comparisons to IT Glue list
		$O365Matches = New-Object -TypeName "System.Collections.ArrayList"
		$NoO365Match = @()
		$NoO365MatchButIgnore = @() # For IT Glue contacts without an O365 account
		foreach ($User in ($FullContactList.attributes | Where-Object {$_."contact-type-name" -notlike "Vendor Support"})) {
			$O365Match = @()
			$Emails = $User."contact-emails".value
			$PrimaryEmail = ($User."contact-emails" | Where-Object { $_.primary }).value
			if (!$PrimaryEmail -and ($Emails | Measure-Object).Count -gt 0) {
				$PrimaryEmail = $Emails | Select-Object -First 1 
			}
			$FirstName = $User."first-name"
			$LastName = $User."last-name"
			$FullName = $User.Name
			$Type = $User."contact-type-name"
			$Notes = $User.notes

			$HasITGEmails = $false
			if (($Emails | Measure-Object).Count -gt 0) {
				$HasITGEmails = $true
			}

			# Check notes for "# No O365 Account", ignore these accounts
			if ($Notes -like '*# No O365 Account*') {
				$NoO365MatchButIgnore += $User
				continue
			}

			# Check $MatchedContactList (from the user audit script) for the latest match
			$ExistingMatch = $MatchedContactList | Where-Object { $_.id -eq $User.id }
			if ($ExistingMatch) {
				if ($ExistingMatch."O365-Connected?" -eq $false -or !$ExistingMatch."O365-PrimarySmtp") {
					$NoMatchButIgnore += $User
					continue
				} else {
					$PrimaryEmail = $ExistingMatch | Select-Object "O365-PrimarySmtp"
					$O365Match += $O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $PrimaryEmail }
				}
			}

			# Look for a match
			while (!$O365Match) {
				# Check notes for an email
				$O365Match += $O365Mailboxes | Where-Object { $Notes -like "*O365 Email: " + $_.PrimarySmtpAddress + "*" }
				if ($O365Match) { break; }
				# Email search
				if ($HasITGEmails) {
					$O365Match += $O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $PrimaryEmail }
					$O365Match += $O365Mailboxes | Where-Object { $Emails -contains $_.PrimarySmtpAddress }
					$O365Match += $O365Mailboxes | Where-Object { $_.EmailAddresses -contains $PrimaryEmail }
					foreach ($Mailbox in $O365Mailboxes) {
						$Intersect = $Mailbox.EmailAddresses | Where-Object { $Emails -contains $_ }
						if ($Intersect) {
							$O365Match += $Mailbox
							break
						}
					}
				}
				# First and last name
				$O365Match += $O365Mailboxes | Where-Object { $_.FirstName -like $FirstName -and $_.LastName -like $LastName }
				if ($O365Match) { break; }
				$O365Match += $UnlicensedUsers | Where-Object { $_.FirstName -like $FirstName -and $_.LastName -like $LastName }
				if ($O365Match) { break; }
				# Check first name / last name against display name
				$O365Match = $O365Mailboxes | Where-Object { $_.DisplayName -like "*$FirstName*" -and $_.DisplayName -like "*$LastName*" }
				if ($O365Match) { break; }
				$O365Match = $UnlicensedUsers | Where-Object { $_.DisplayName -like "*$FirstName*" -and $_.DisplayName -like "*$LastName*" }
				if ($O365Match) { break; }
				# Get the root of each email address (before @) for the next checks
				if ($HasITGEmails) {
					$PrimaryEmailRoot = $PrimaryEmail.split("@")[0]
					$EmailsRoot = $Emails | ForEach-Object { $_.split("@")[0] }
				}
				$CommonRoots = @($FirstName, $LastName)
				$CommonRoots += $FirstName + $LastName.Substring(0, 1)
				$CommonRoots += $LastName + $FirstName.Substring(0, 1)
				$CommonRoots += $FirstName.Substring(0, 1) + $LastName
				$CommonRoots += $FirstName + "." + $LastName
				$CommonRoots += $FirstName + "_" + $LastName
				$CommonRoots = $CommonRoots -replace '\s', ''
				[array]::Reverse($CommonRoots) # in order of most useful to least
				# Check email roots against PrimarySmtpAddress, EmailsAddresses, Name, Alias
				if ($HasITGEmails) {
					$O365Match = $O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $PrimaryEmailRoot +'@*' }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { (@($_.EmailAddresses) -like $PrimaryEmailRoot +'@*').Count -eq 1 }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { $_.Name -like $PrimaryEmailRoot }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { $_.Alias -like $PrimaryEmailRoot }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { (@($EmailsRoot) -like $_.PrimarySmtpAddress.split("@")[0]).Count -eq 1 }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { (@($EmailsRoot) -like $_.Name).Count -eq 1 }
					if ($O365Match) { break; }
					$O365Match = $O365Mailboxes | Where-Object { (@($EmailsRoot) -like $_.Alias).Count -eq 1 }
					if ($O365Match) { break; }
				}
				$O365Match = $O365Mailboxes | Where-Object { (@($CommonRoots) -like $_.PrimarySmtpAddress.split("@")[0]).Count -eq 1 }
				if ($O365Match) { break; }
				$O365Match = $O365Mailboxes | Where-Object { (@($CommonRoots) -like $_.Name).Count -eq 1 }
				if ($O365Match) { break; }
				$O365Match = $O365Mailboxes | Where-Object { (@($CommonRoots) -like $_.Alias).Count -eq 1 }
				if ($O365Match) { break; }
				if ($HasITGEmails) {
					foreach ($Email in $EmailsRoot) {
						$Intersect = $O365Mailboxes | Where-Object { (@($_.EmailAddresses) -like $Email +'@*').Count -gt 0}
						if (($Intersect | Measure-Object).Count -eq 1) {
							$O365Match = $Intersect
							break
						}
					}
					if ($O365Match) { break; }
				}
				foreach ($Root in $CommonRoots) {
					$Intersect = $O365Mailboxes | Where-Object { (@($_.EmailAddresses) -like $Root +'@*').Count -gt 0}
					if (($Intersect | Measure-Object).Count -eq 1) {
						$O365Match = $Intersect
						break
					}
				}
				break;
			}

			# If more than 1 match, narrow down to 1
			$O365Match = $O365Match | Sort-Object PrimarySmtpAddress -Unique
			if ($O365Match -and ($O365Match | Measure-Object).Count -gt 1) {
				# Try to narrow down by name, and then by account type (prefer user mailbox over shared mailbox)
				$FilteredO365MatchByName = $O365Match | Where-Object { $_.FirstName -like $FirstName -and $_.LastName -like $LastName }
				$FilteredO365MatchByType = $O365Match | Where-Object { $_.RecipientTypeDetails -like 'UserMailbox' }
				if (($FilteredO365MatchByName | Measure-Object).Count -eq 1) {
					$O365Match = $FilteredO365MatchByName
				} elseif (($FilteredO365MatchByType | Measure-Object).Count -eq 1) {
					$O365Match = $FilteredO365MatchByType
				}

				# If still too many, we'll just use the first
				if (($O365Match | Measure-Object).Count -gt 1) {
					$O365Match = $O365Match | Select-Object -First 1
				}
			}

			# Add to the Match or NoMatch array
			if ($O365Match) {
				$match = [PSCustomObject]@{
					id = $User.ID
					name = $FullName
					type = $Type
					itglue = $User
					o365 = $O365Match
				}
				$O365Matches.Add($match) | Out-Null
			} else {
				if ($Type -ne 'Terminated' -and $Type -ne "Employee - On Leave" -and $User.ID -in $EmployeeContacts.id) {
					$NoO365Match += $User
				}
			}
		}
		$O365MatchCount = ($O365Matches | Measure-Object).Count
		Write-Host "Finished matching all IT Glue contacts to their email accounts. $O365MatchCount matches were made."
		Write-PSFMessage -Level Verbose -Message "Matched: all IT Glue contacts to mailboxes. $O365MatchCount matches made."

		# Get the existing unmatched O365 list from the user audit
		if (!$config) {
			$auditFilesPath = "C:\billing_audit\unmatchedO365.json"
		} else {
			$auditFilesPath = "C:\billing_audit\$($OrgShortName)\unmatchedO365.json"
		}
		$OldUnmatchedO365Emails = @()
		if (Test-Path $auditFilesPath) {
			$OldUnmatchedO365 = Get-Content -Path $auditFilesPath -Raw | ConvertFrom-Json
			if ($OldUnmatchedO365) {
				$OldUnmatchedO365Emails = $OldUnmatchedO365.PrimarySmtpAddress
			}
		}

		$UnmatchedO365 = $O365Mailboxes | Where-Object { $O365Matches.o365.PrimarySmtpAddress -notcontains $_.PrimarySmtpAddress } | Where-Object { ($_.AssignedLicenses | Measure-Object).Count -gt 0 } | Where-Object { !$_.AccountDisabled }
		Write-PSFMessage -Level Verbose -Message "Found $(($UnmatchedO365 | Measure-Object).Count) unmatched mailboxes."
		$UnmatchedO365 = $UnmatchedO365 | Where-Object { $_.PrimarySmtpAddress -notin $OldUnmatchedO365Emails } # filter out accounts that have already been reviewed
		Write-PSFMessage -Level Verbose -Message "Found $(($UnmatchedO365 | Measure-Object).Count) new unmatched mailboxes."
	} else {
		$CheckEmail = $false # Set to $false in case it is true and we aren't using unattended login
		Write-PSFMessage -Level Warning -Message "Mailbox check not running."
	}

	function buildMatch {
		param($Contact)

		$MatchToAdd = [pscustomobject]@{
			"id" = $Contact.ID
			"ITG-Name" = $Contact.name
			"Type" = $Contact."contact-type-name"
			"Title" = $Contact.title
			"Location" = $Contact."location-name"
			"ITG-Emails" = $Contact."contact-emails"
		}

		if ($script:CheckAD -and $script:ADMatches) {
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "AD-Connected?" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "AD-Name" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "AD-Username" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "AD-Email" -Value $null
			
			$ADMatch = ($script:ADMatches | Where-Object { $_.id -eq $Contact.ID }).ad
			if ($ADMatch) {
				$MatchToAdd."AD-Connected?" = $true
				$Name = $ADMatch.name
				$OtherName = $ADMatch.GivenName + " " + $ADMatch.Surname
				if ($Name -notlike "*" + $OtherName + "*" -and $OtherName -notlike "*" + $Name + "*") {
					$Name = $Name + " (" + $OtherName + ")"
				}
				$MatchToAdd."AD-Name" = $Name
				$MatchToAdd."AD-Username" = $ADMatch.Username
				$MatchToAdd."AD-Email" = $ADMatch.EmailAddress
			} else {
				$MatchToAdd."AD-Connected?" = $false
			}
		}

		if ($script:CheckEmail -and $script:O365Matches) {
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "O365-Connected?" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "O365-Name" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "O365-PrimarySmtp" -Value $null
			$MatchToAdd | Add-Member -MemberType NoteProperty -Name "O365-Emails" -Value $null
			
			$O365Match = ($script:O365Matches | Where-Object { $_.id -eq $Contact.ID }).o365
			if ($O365Match) {
				$MatchToAdd."O365-Connected?" = $true
				$Name = $O365Match.FirstName + " " + $O365Match.LastName + " (" + $O365Match.name + ")"
				$MatchToAdd."O365-Name" = $Name
				$MatchToAdd."O365-PrimarySmtp" = $O365Match.PrimarySmtpAddress
				$MatchToAdd."O365-Emails" = $O365Match.EmailAddresses
			} else {
				$MatchToAdd."O365-Connected?" = $false
			}
		}

		$MatchToAdd | Add-Member -MemberType NoteProperty -Name "ITG-URL" -Value $null
		$MatchToAdd | Add-Member -MemberType NoteProperty -Name "ITG-Notes" -Value $null
		$MatchToAdd."ITG-URL" = $Contact."resource-url"
		$MatchToAdd."ITG-Notes" = $Contact.notes

		return $MatchToAdd
	}

	$FullMatches = New-Object -TypeName "System.Collections.ArrayList"
	foreach ($Contact in $EmployeeContacts) {
		$MatchToAdd = buildMatch $Contact
		$FullMatches.Add($MatchToAdd) | Out-Null
	}

	Write-Host "All matches between IT Glue and AD have now been made. Audit commencing."
	Write-PSFMessage -Level Verbose -Message "All matches found. Total matches: $(($FullMatches | Measure-Object).Count)"

	# Update the Device Audit DB if applicable and get usage data if applicable
	$UserUsage = @()
	if ($FullMatches -and $Device_DB_APIKey -and $Device_DB_APIEndpoint) {
		If (Get-Module -ListAvailable -Name "Az.Accounts") {Import-module Az.Accounts } Else { install-module Az.Accounts  -Force; import-module Az.Accounts }
		If (Get-Module -ListAvailable -Name "Az.Resources") {Import-module Az.Resources } Else { install-module Az.Resources  -Force; import-module Az.Resources }
		#If (Get-Module -ListAvailable -Name "CosmosDB") {Import-module CosmosDB} Else { install-module CosmosDB -Force; import-module CosmosDB}

		$headers = @{
			'x-api-key' = $Device_DB_APIKey
		}
		$body = @{
			'tokenType' = 'users'
		}
		
		$Token = Invoke-RestMethod -Method Post -Uri $Device_DB_APIEndpoint -Headers $headers -Body ($body | ConvertTo-Json) -ContentType 'application/json'
		if ($Token) {			
			$collectionId = Get-CosmosDbCollectionResourcePath -Database 'DeviceUsage' -Id 'Users'
			$contextToken = New-CosmosDbContextToken `
				-Resource $collectionId `
				-TimeStamp (Get-Date $Token.Timestamp) `
				-TokenExpiry $Token.Life `
				-Token (ConvertTo-SecureString -String $Token.Token -AsPlainText -Force) 

			$DB_Name = 'DeviceUsage'
			$CustomerAcronym = $Device_DB_APIKey.split('.')[0]
			$CosmosDBAccount = "stats-$($CustomerAcronym)".ToLower()
			$resourceContext = New-CosmosDbContext -Account $CosmosDBAccount -Database $DB_Name -Token $contextToken

			if ($resourceContext) {
				$Query = "SELECT * FROM Users u"
				$ExistingUsers = Get-CosmosDbDocument -Context $resourceContext -Database $DB_Name -CollectionId "Users" -Query $Query -PartitionKey 'user'

				if ($ExistingUsers) {
					$Now_UTC = Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y-%m-%dT%H:%M:%S.000Z'
					$UserCount = ($ExistingUsers | Measure-Object).Count
					$i = 0
					foreach ($User in $ExistingUsers) {
						$i++
						$Match = $FullMatches | Where-Object { $_.'AD-Username' -eq $User.Username } | Select-Object -First 1

						[int]$PercentComplete = ($i / $UserCount * 100)
						Write-Progress -Activity "Updating users in Device Audit Database." -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "% (Updating: $($User.Username)")

						if (!$Match) {
							$EscapedUsername = [Regex]::Escape($User.Username)
							$Match = $FullMatches | Where-Object { $_.'ITG-Notes' -match ".*(Username: " + $EscapedUsername + "(\s|W|$)).*" } | Select-Object -First 1

							if (!$Match -and $User.DomainOrLocal -eq "Local") {
								$Match = $FullMatches | Where-Object { $_.'ITG-Notes' -match ".*(Local Account: " + $EscapedUsername + "(\s|W|$)).*" } | Select-Object -First 1
							}

							# Still no match, fall back to email-only search
							if (!$Match) {
								$Match = $FullMatches | Where-Object { $_.'O365-PrimarySmtp' -match "$EscapedUsername\.user@" -or $_.'ITG-Notes' -match ".*(Primary O365 Email: " + $EscapedUsername + "@).*" } | Select-Object -First 1
							}
						}

						$UpdateRequired = $false
						# If changing fields, update in device audit as well
						$UpdatedUser = $User | Select-Object Id, Domain, DomainOrLocal, Username, LastUpdated, type, O365Email, ITG_ID, ADUsername

						if ($Match) {
							if ($Match.'AD-Username' -and $User.ADUsername -ne $Match.'AD-Username') {
								$UpdatedUser.ADUsername = $Match.'AD-Username'
								$User.ADUsername = $Match.'AD-Username'
								$UpdateRequired = $true
							}
							if ($Match.'O365-PrimarySmtp' -and $User.O365Email -ne $Match.'O365-PrimarySmtp') {
								$UpdatedUser.O365Email = $Match.'O365-PrimarySmtp'
								$User.O365Email = $Match.'O365-PrimarySmtp'
								$UpdateRequired = $true
							}
							if ($Match.id -and $User.ITG_ID -ne $Match.id) {
								$UpdatedUser.ITG_ID = $Match.id
								$User.ITG_ID = $Match.id
								$UpdateRequired = $true
							}
						}

						$UserID = $User.Id
						if ($UpdateRequired) {
							$UpdatedUser.LastUpdated = $Now_UTC
							$User.LastUpdated = $Now_UTC
							Set-CosmosDbDocument -Context $resourceContext -Database $DB_Name -CollectionId "Users" -Id $UserID -DocumentBody ($UpdatedUser | ConvertTo-Json) -PartitionKey 'user' | Out-Null
						}
					}
					Write-Progress -Activity "Updating users in Device Audit Database." -Status "Ready" -Completed
				}
			}

			# Get user usage info from Device Audit DB if configured to look for part time employees
			if ($PartTimeEmployeesByUsage -and $ExistingUsers) {
				$body = @{
					'tokenType' = 'userusage'
				}
				$Token2 = Invoke-RestMethod -Method Post -Uri $Device_DB_APIEndpoint -Headers $headers -Body ($body | ConvertTo-Json) -ContentType 'application/json'

				if ($Token2) {
					$collectionId2 = Get-CosmosDbCollectionResourcePath -Database 'DeviceUsage' -Id 'UserUsage'
					$contextToken2 = New-CosmosDbContextToken `
						-Resource $collectionId2 `
						-TimeStamp (Get-Date $Token2.Timestamp) `
						-TokenExpiry $Token2.Life `
						-Token (ConvertTo-SecureString -String $Token2.Token -AsPlainText -Force) 
					$resourceContext2 = New-CosmosDbContext -Account $CosmosDBAccount -Database $DB_Name -Token $contextToken2

					if ($resourceContext2) {
						$Query2 = "SELECT * FROM UserUsage AS uu"
						$UserUsage = Get-CosmosDbDocument -Context $resourceContext2 -Database $DB_Name -CollectionId "UserUsage" -Query $Query2 -QueryEnableCrossPartition $true

						if ($UserUsage) {
							foreach ($Usage in $UserUsage) {
								$ExistingUser = $ExistingUsers | Where-Object { $_.Id -eq $Usage.Id }
								$Usage | Add-Member -MemberType NoteProperty -Name User -Value $null
								if ($ExistingUser) {
									$Usage.User = $ExistingUser
								}
							}
						}
					}
				}
			}
		}
	}

	if (!$UserUsage -or ($UserUsage | Measure-Object).Count -le 0) {
		$PartTimeEmployeesByUsage = $false
	}

	#############################################
	##### Matches Made. Find Discrepancies. #####
	#############################################

	if ($FullMatches) {
		Write-PSFMessage -Level Verbose -Message "Searching for discrepancies."
		$WarnContacts = New-Object -TypeName "System.Collections.Generic.List[Object]"

		foreach ($Match in $FullMatches) {
			$MatchID = $Match.id
			$Contact = $EmployeeContacts | Where-Object { $_.ID -eq $MatchID }
			$ContactType = $Contact."contact-type-name"

			if ($Contact.notes -like "*# Ignore Warnings*") {
				continue;
			}

			$IgnoreWarnings = @()
			if ($Contact.notes -match '\# Ignore ([\w\[\]]+) Warnings') {
				$IgnoreTypes = ([regex]::Matches($Contact.notes, '\# Ignore ([\w\[\]]+) Warnings').Groups | Where-Object { "Groups" -notin $_.PSObject.Properties.Name }).Value
				$IgnoreWarnings += $IgnoreTypes
			}

			$PartTimeUsage = $false
			$NoRecentUsage = $false
			$UsageStats = $false
			if ($PartTimeEmployeesByUsage) {
				$UsageStats = $UserUsage | Where-Object { $_.User.ITG_ID -eq $MatchID }
				if ($UsageStats) {
					$LastMonthDate = Get-Date (Get-Date).AddMonths(-1) -Format "yyyy-MM"
					$TwoMonthsAgoDate = Get-Date (Get-Date).AddMonths(-2) -Format "yyyy-MM"
					$LastMonthUsage = $UsageStats.DaysActive.HistoryPercent.$LastMonthDate
					$TwoMonthsAgoUsage = $UsageStats.DaysActive.HistoryPercent.$TwoMonthsAgoDate

					if ($LastMonthUsage -and $LastMonthUsage -lt $PartTimePercentage -and $LastMonthUsage -gt 0 -and (!$TwoMonthsAgoUsage -or $TwoMonthsAgoUsage -lt $PartTimePercentage)) {
						$PartTimeUsage = $true
					} elseif ($LastMonthUsage -and $ContactType -like "*Part Time*" -and $LastMonthUsage -lt $PartTimePercentage) {
						$PartTimeUsage = $true
					} elseif (!$LastMonthUsage -and $TwoMonthsAgoUsage -and $TwoMonthsAgoUsage -lt $PartTimePercentage) {
						$PartTimeUsage = $true
					} elseif (!$LastMonthUsage -and !$TwoMonthsAgoUsage) {
						$PartTimeUsage = $true
						$NoRecentUsage = $true
					}
				} else {					
					$NoRecentUsage = $true
				}
			}

			###########
			# AD Checks
			if ($CheckAD) {
				$ADMatch = ($ADMatches | Where-Object { $_.ID -eq $MatchID }).ad

				$HasEmail = $false
				$EmailEnabled = $false
				if ($CheckEmail) {
					$O365Match = ($O365Matches | Where-Object { $_.ID -eq $MatchID })
					if ($O365Match) {
						$HasEmail = $true
						$EmailEnabled = ($O365Match.o365.AccountDisabled -eq $false)
					}
				}

				if ($ADMatch) {
					$WarnObj = @{
						id = $MatchID
						category = 'AD'
						type = $false
						reason = $false
						name = $Contact.name
					}

					# If email only accounts might have an associated AD account, lets check if the groups make this look like an email only user
					$EmailOnly = $false
					$EmailOnlyDetails = ""
					if ($EmailOnlyHaveAD -and $HasEmail -and $EmailEnabled -and $O365Match.o365.RecipientTypeDetails -like 'UserMailbox' -and $ADMatch.PSObject.Properties.Name -contains "Groups") {
						$EmployeeGroups = @()
						foreach ($Group in $ADMatch.Groups) {
							if (($EmailOnlyGroupsIgnore | ForEach-Object{$Group -like $_}) -notcontains $true ) {
								$EmployeeGroups += $Group
							}
						}
						if (($EmployeeGroups | Measure-Object).Count -eq 0) {
							$EmailOnlyDetails = "Not in any employee AD groups."
							$EmailOnly = $true
						}

						# If it looks email-only from the AD groups, and this is O365, lets double check if there are any office actived devices or intune devices (if so, it's not email only)
						if ($EmailType -eq "O365" -and $EmailOnly -eq $true -and ($O365Match.o365.AssignedLicenses | Measure-Object).Count -gt 0) {
							$O365Licenses_NotEmailOnly = $O365Match.o365.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }
			
							if (($O365Licenses_NotEmailOnly | Measure-Object).Count -gt 0) {
								$O365Devices = Get-AzureADUserRegisteredDevice -ObjectId $O365Match.o365.AAD_ObjectID
								if (($O365Devices | Measure-Object).Count -gt 0) {
									$EmailOnlyDetails = "Has the following O365 Activated Devices: " + ($O365Devices.DisplayName -join ", ")
									$EmailOnly = $false
								} else {
									$IntuneDevices = Get-AzureADUserOwnedDevice -ObjectId $O365Match.o365.AAD_ObjectID
									if (($IntuneDevices | Measure-Object).Count -gt 0) {
										$EmailOnlyDetails = "Has the following assigned InTune Devices: " + ($IntuneDevices.DisplayName -join ", ")
										$EmailOnly = $false
									}
								}
							}
						}
						
						# If this looks like an email only user, get the related items for this user from ITG to see if they have a computer assigned
						if ($EmailOnly) {
							$ITGUserDetails = Get-ITGlueContacts -id $MatchID -include 'related_items'
							$Existing_RelatedItems = $false
							if ($ITGUserDetails.included) {
								$Existing_RelatedItems = $ITGUserDetails.included
							}
							if ($Existing_RelatedItems) {
								$AssignedDevices = $Existing_RelatedItems | Where-Object { $_.attributes.'asset-type' -eq 'configuration' -and $_.attributes.notes -like "*User*" -and !$_.attributes.archived }

								if ($AssignedDevices -and ($AssignedDevices | Measure-Object).count -gt 0) {
									$EmailOnlyDetails = "Has the following devices assigned in ITG: " + ($AssignedDevices.attributes.name -join ", ")
									$EmailOnly = $false
								}
							}
						}
					} elseif ($O365Match.o365.RecipientTypeDetails -notlike 'UserMailbox') {
						$EmailOnlyDetails = "Mailbox is not a UserMailbox"
					}

					if (($ADMatch.Enabled -eq $false -or $ADMatch.OU -like '*Disabled*') -and 'ToTerminated' -notin $IgnoreWarnings) {
						# ToTerminated
						if ($ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave') {
							$WarnObj.type = "ToTerminated"
							$WarnObj.reason = "AD Account Disabled. Delete IT Glue contact or change type to 'Terminated'."
						}
					} elseif (($ADMatch.Name -like '*Disabled*' -or $ADMatch.Description -like '*Disabled*') -and 'ImproperlyTerminated' -notin $IgnoreWarnings) {
						# ImproperlyTerminated
						$WarnObj.type = "ImproperlyTerminated"
						$WarnObj.reason = "AD Account Improperly Disabled. Please review and fix. (Description lists Disabled but account is not disabled.)"
					} elseif ((!$ADMatch.LastLogonDate -or $ADMatch.LastLogonDate -lt (Get-Date).AddDays(-150)) -and (!$EmailOnlyHaveAD -or ($ContactType -notlike "Employee - Email Only" -and !$EmailOnly)) -and $ContactType -ne "Employee - On Leave" -and $ContactType -ne "Terminated" -and 'MaybeTerminate' -notin $IgnoreWarnings -and !$InactivityO365Preference) {
						# MaybeTerminate
						$WarnObj.type = "MaybeTerminate"
						$WarnObj.reason = "AD Account Unused. Maybe disable it? Please review. (Last login > 150 days ago.)"
						if ($ADMatch.LastLogonDate) {
							$LastLoginDaysAgo = (New-TimeSpan -Start $ADMatch.LastLogonDate -End (Get-Date)).Days
							if ($ADMatch.LastLogonDate -lt (Get-Date).AddDays(-150)) { $WarnObj.reason += " (Last Login: $($LastLoginDaysAgo) days ago)" }
						} else {
							$WarnObj.reason += " (Last Login: Never)"
						}
						# If $InactivityO365Preference is $true, this gets skipped and will only be checked in the O365 section if the O365 account is inactive
					} elseif ($NoRecentUsage -and (!$ADMatch.LastLogonDate -or $ADMatch.LastLogonDate -lt (Get-Date).AddDays(-60)) -and (!$EmailOnlyHaveAD -or ($ContactType -notlike "Employee - Email Only" -and !$EmailOnly)) -and 
							$ContactType -ne "Employee - On Leave" -and $ContactType -ne "Terminated" -and 'MaybeTerminate' -notin $IgnoreWarnings -and !$InactivityO365Preference) {
						# MaybeTerminate[NoRecentDeviceUsage]
						$WarnObj.type = "MaybeTerminate[NoRecentDeviceUsage]"
						$WarnObj.reason = "AD Account Unused. Maybe disable it? Please review."
						if (!$UsageStats) {
							$WarnObj.reason += " (No device usage found ever)"
						} else {
							$LastUse = $UsageStats.DaysActive.History.PSObject.Properties.Name | Sort-Object -Descending | Select-Object -First 1
							$WarnObj.reason += " (No device usage over the past 2 months, last used: $LastUse)"
						}
					} elseif ($ContactType -eq 'Terminated' -and 'ToEnabled' -notin $IgnoreWarnings) {
						# ToEnabled
						$WarnObj.type = "ToEnabled"
						$WarnObj.reason = "AD Account Enabled. IT Glue Contact should not be 'Terminated'."
					} elseif ($ContactType -notlike "Employee - Part Time" -and $ContactType -notlike "Shared Account" -and $ContactType -notlike "Employee - Multi User" -and 
								!$NoRecentUsage -and $PartTimeUsage -and !$EmailOnly -and 'ToEmployeePartTime' -notin $IgnoreWarnings) {
						# ToEmployeePartTime
						$WarnObj.type = "ToEmployeePartTime"
						$WarnObj.reason = "AD account appears to be part time. Consider changing the IT Glue Contact type to 'Employee - Part Time'."
						$WarnObj.reason += " (Last Months Usage: $($LastMonthUsage)% [$($UsageStats.DaysActive.LastMonth) days])"
					} elseif ($ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "Employee - Part Time" -and $ContactType -notlike "Contractor" -and $ContactType -notlike "Vendor" -and $EmailOnly -and 'ToEmailOnly' -notin $IgnoreWarnings) {
						#ToEmailOnly
						$WarnObj.type = "ToEmailOnly"
						$WarnObj.reason = "AD account has no groups but an email account is setup. Consider changing the IT Glue Contact type to 'Employee - Email Only'."
						if ($EmailOnlyDetails) {
							$WarnObj.reason += "(Reason: $EmailOnlyDetails)"
						}
					} elseif ($ContactType -like "Employee - Email Only" -and $ContactType -notlike "Employee - Part Time" -and $ContactType -notlike "Shared Account" -and $ContactType -notlike "Employee - Multi User" -and 
								$ContactType -notlike "Contractor" -and !$EmailOnly -and $EmailOnlyDetails -notlike "Mailbox is not a UserMailbox" -and 'ToEmployee' -notin $IgnoreWarnings -and 'ToEmployee[FromEmailOnly]' -notin $IgnoreWarnings) {
						#ToEmployee[FromEmailOnly]
						$WarnObj.type = "ToEmployee[FromEmailOnly]"
						$WarnObj.reason = "AD account appears to be a full employee but is currently set to email only. Consider changing the IT Glue Contact type to 'Employee'."
						if ($EmailOnlyDetails) {
							$WarnObj.reason += "(Reason: $EmailOnlyDetails)"
						}
					} elseif ($ContactType -like "Employee - Part Time" -and $ContactType -notlike "Employee - Email Only" -notlike "Shared Account" -and $ContactType -notlike "Employee - Multi User" -and 
								$ContactType -notlike "Contractor" -and !$EmailOnly -and !$PartTimeUsage -and !$NoRecentUsage -and $PartTimeEmployeesByUsage -and 'ToEmployee' -notin $IgnoreWarnings -and 'ToEmployee[FromPartTime]' -notin $IgnoreWarnings) {
						#ToEmployee[FromPartTime]
						$WarnObj.type = "ToEmployee[FromPartTime]"
						$WarnObj.reason = "AD account appears to be a full employee but is currently set to part time. Consider changing the IT Glue Contact type to 'Employee'."
						$WarnObj.reason += " (Last Months Usage: $($LastMonthUsage)% [$($UsageStats.DaysActive.LastMonth) days])"
					} elseif (!$ContactType) {
						#NoContactType
						$WarnObj.type = "NoContactType"
						$WarnObj.reason = "ITG has no contact type set for this contact but an AD account exists. Please audit this account."
					}

					if ($WarnObj.type) {
						$WarnContacts.Add($WarnObj) | Out-Null
					}
				}
			}

			#############
			# O365 Checks
			if ($CheckEmail) {
				$O365Match = ($O365Matches | Where-Object { $_.ID -eq $MatchID }).o365

				$HasAD = $false
				$ADEnabled = $false
				if ($CheckAD) {
					$ADMatch = $ADMatches | Where-Object { $_.ID -eq $MatchID }
					if ($ADMatch) {
						$HasAD = $true
						$ADEnabled = $ADMatch.ad.Enabled
					}
				}

				if (!$O365Match) { 
					# If no O365 account or AD account:
					# ToTerminated
					if (((!$HasAD -and $CheckAD) -or !$CheckAD) -and $ContactType -ne 'Terminated') {
						$WarnObj = @{
							id = $MatchID
							category = 'None'
							type = "ToTerminated"
							reason = "No O365 or AD account. Delete IT Glue contact or change type to 'Terminated'. Alternatively, this may be a Vendor Support account."
							name = $Contact.name
						}
						$WarnContacts.Add($WarnObj) | Out-Null
						continue;
					} else {
						# If no O365 account, just continue onto the next contact
						continue;
					}
				}

				# If email only accounts might have an associated AD account, lets check if the groups make this look like an email only user
				$EmailOnly = $false
				$EmailOnlyDetails = ""
				if ($EmailOnlyHaveAD -and $HasAD -and $ADEnabled -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and $ADMatch.ad.PSObject.Properties.Name -contains "Groups") {
					$EmployeeGroups = @()
					foreach ($Group in $ADMatch.ad.Groups) {
						if (($EmailOnlyGroupsIgnore | ForEach-Object{$Group -like $_}) -notcontains $true ) {
							$EmployeeGroups += $Group
						}
					}
					if (($EmployeeGroups | Measure-Object).Count -eq 0) {
						$EmailOnlyDetails = "Not in any employee AD groups."
						$EmailOnly = $true
					} else {
						$EmailOnlyDetails = "In the Employee AD groups: " + ($EmployeeGroups -join ", ")
					}
				} elseif ($O365Match.RecipientTypeDetails -notlike 'UserMailbox') {
					$EmailOnlyDetails = "Mailbox is not a UserMailbox"
				}

				# If not doing an AD check, lets use the O365 licenses and any devices assigned in O365 to device if this is an email only user
				if (!$CheckAD -and $EmailType -eq "O365" -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and ($O365Match.AssignedLicenses | Measure-Object).Count -gt 0) {
					$O365Licenses_NotEmailOnly = $O365Match.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }

					if (($O365Licenses_NotEmailOnly | Measure-Object).Count -eq 0) {
						$O365Devices = Get-AzureADUserRegisteredDevice -ObjectId $O365Match.AAD_ObjectID
						if (($O365Devices | Measure-Object).Count -eq 0) {
							$IntuneDevices = Get-AzureADUserOwnedDevice -ObjectId $O365Match.AAD_ObjectID
							if (($IntuneDevices | Measure-Object).Count -eq 0) {
								$EmailOnlyDetails = "No devices activated in O365 or assigned in InTune."
								$EmailOnly = $true
							}
						}
					}
				# If we did do an AD check and the user appears to be EmailOnly due to their AD groups, lets verify if they have any devices connected in O365 (if so, then they are not email-only)
				} elseif ($CheckAD -and $EmailType -eq "O365" -and $EmailOnly -eq $true -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and ($O365Match.AssignedLicenses | Measure-Object).Count -gt 0) {
					$O365Licenses_NotEmailOnly = $O365Match.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }
	
					if (($O365Licenses_NotEmailOnly | Measure-Object).Count -gt 0) {
						$O365Devices = Get-AzureADUserRegisteredDevice -ObjectId $O365Match.AAD_ObjectID
						if (($O365Devices | Measure-Object).Count -gt 0) {
							$EmailOnlyDetails = "Has the following O365 Activated Devices: " + ($O365Devices.DisplayName -join ", ")
							$EmailOnly = $false
						} else {
							$IntuneDevices = Get-AzureADUserOwnedDevice -ObjectId $O365Match.AAD_ObjectID
							if (($IntuneDevices | Measure-Object).Count -gt 0) {
								$EmailOnlyDetails = "Has the following assigned InTune Devices: " + ($IntuneDevices.DisplayName -join ", ")
								$EmailOnly = $false
							}
						}
					}
				}

				# If this user appears to be email only, verify against assigned devices in ITG (if they are assigned a device, then they are not email-only)
				if ($EmailOnly) {
					$ITGUserDetails = Get-ITGlueContacts -id $MatchID -include 'related_items'
					$Existing_RelatedItems = $false
					if ($ITGUserDetails.included) {
						$Existing_RelatedItems = $ITGUserDetails.included
					}
					if ($Existing_RelatedItems) {
						$AssignedDevices = $Existing_RelatedItems | Where-Object { $_.attributes.'asset-type' -eq 'configuration' -and $_.attributes.notes -like "*User*" -and !$_.attributes.archived }

						if ($AssignedDevices -and ($AssignedDevices | Measure-Object).count -gt 0) {
							$EmailOnlyDetails = "Has the following devices assigned in ITG: " + ($AssignedDevices.attributes.name -join ", ")
							$EmailOnly = $false
						}
					}
				}

				$WarnObj = @{
					id = $MatchID
					category = 'O365'
					type = $false
					reason = $false
					name = $Contact.name
				}

				if ($O365Match.AccountDisabled -eq $true -and $O365Match.RecipientTypeDetails -like 'UserMailbox') {
					if (!$HasAD -and 'ToTerminated' -notin $IgnoreWarnings) {
						# ToTerminated
						if ($ContactType -ne 'Terminated' -and $ContactType -ne "Employee - On Leave") {
							$WarnObj.type = "ToTerminated"
							$WarnObj.reason = "$EmailType Account Disabled. Delete IT Glue contact or change type to 'Terminated'."
						}
					} elseif ($HasAD -and $ADEnabled -and 'ImproperlyTerminated' -notin $IgnoreWarnings) {
						# ImproperlyTerminated
						$WarnObj.type = "ImproperlyTerminated"
						$WarnObj.reason = "$EmailType Account Disabled Discrepancy. Please review and fix. (O365 Account Disabled but AD Account is Enabled.)"
					}
				} elseif ($O365Match.DisplayName -like '*Disabled*' -and $ContactType -ne 'Terminated' -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and 'ImproperlyTerminated' -notin $IgnoreWarnings) {
					# ImproperlyTerminated
					$WarnObj.type = "ImproperlyTerminated"
					$WarnObj.reason = "$EmailType Account Improperly Disabled. Please review and fix. (DisplayName lists Disabled but account is not disabled.)"
				} elseif ($EmailType -eq 'O365' -and ($O365Match.PrimarySmtpAddress -like "no license" -or ($O365Match.AssignedLicenses | Measure-Object).count -eq 0 -or $O365Match.RecipientTypeDetails -like "None") -and $ContactType -ne 'Terminated' -and !$HasAD -and 'MaybeTerminate' -notin $IgnoreWarnings) {
					# MaybeTerminate
					$WarnObj.type = "MaybeTerminate"
					$WarnObj.reason = "$EmailType Account is Unlicensed and no AD account is associated with this contact. Should this account be terminated? Consider changing the IT Glue type to 'Terminated'."
				} elseif ($O365Match.RecipientTypeDetails -like 'SharedMailbox' -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and $O365Match.DisplayName -like "*" + $Contact."last-name" + "*" -and 'MaybeTerminate' -notin $IgnoreWarnings) {
					# MaybeTerminate
					$WarnObj.type = "MaybeTerminate"
					$WarnObj.reason = "$EmailType Account is a Shared Mailbox and appears to be a terminated account. Consider changing the IT Glue type to 'Terminated'."
				} elseif ($O365Match.DeliverToMailboxAndForward -eq $false -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and ($O365Match.ForwardingSmtpAddress -or $O365Match.ForwardingAddress) -and 'MaybeTerminate' -notin $IgnoreWarnings -and 'MaybeTerminate[Forwarding]' -notin $IgnoreWarnings) {
					# MaybeTerminate
					$WarnObj.type = "MaybeTerminate[Forwarding]"
					$WarnObj.reason = "$EmailType Account has forwarding setup and appears to be a terminated account. Consider changing the IT Glue type to 'Terminated', or if temporary, to 'Employee - On Leave'."
				} elseif ($O365Match.HiddenFromAddressListsEnabled -eq $true -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and 'MaybeTerminate' -notin $IgnoreWarnings -and 'MaybeTerminate[GAL]' -notin $IgnoreWarnings) {
					# MaybeTerminate
					$WarnObj.type = "MaybeTerminate[GAL]"
					$WarnObj.reason = "$EmailType Account is hidden from GAL and appears to be a terminated account. Consider changing the IT Glue type to 'Terminated'."
				} elseif ($ContactType -eq 'Terminated' -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and (!$HasAD -or (!$ADEnabled -and $EmailType -ne 'Exchange')) -and ($EmailType -ne 'O365' -or ($O365Match.AssignedLicenses | Measure-Object) -eq 0) -and 'ToEnabled' -notin $IgnoreWarnings) {
					# ToEnabled
					$WarnObj.type = "ToEnabled"
					$WarnObj.reason = "$EmailType Account Enabled. IT Glue Contact should not be 'Terminated'."
				} elseif ($ContactType -notlike "Internal / Shared Mailbox" -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and $O365Match.RecipientTypeDetails -notlike 'UserMailbox' -and $O365Match.RecipientTypeDetails -notlike 'None' -and 'ToSharedMailbox' -notin $IgnoreWarnings) {
					# ToSharedMailbox
					$WarnObj.type = "ToSharedMailbox"
					$WarnObj.reason = "$EmailType account appears to be a shared mailbox. Consider changing the IT Glue Contact type to 'Internal / Shared Mailbox'."
				} elseif ($CheckAD -and $ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "External User" -and $ContactType -notlike "Internal / Shared Mailbox" -and (!$HasAD -or $EmailOnly) -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and 'ToEmailOnly' -notin $IgnoreWarnings) {
					# ToEmailOnly (with AD)
					$WarnObj.type = "ToEmailOnly"
					if ($EmailOnly) {
						$WarnObj.reason = "$EmailType account has an associated AD account but it appears to be email-only. Consider changing the IT Glue Contact type to 'Employee - Email Only'. Alternatively: 'External User' or 'Internal / Shared Mailbox'."
						if ($EmailOnlyDetails) {
							$WarnObj.reason += "(Reason: $EmailOnlyDetails)"
						}
					} else {	
						$WarnObj.reason = "$EmailType account has no associated AD account. Consider changing the IT Glue Contact type to 'Employee - Email Only'. Alternatively: 'External User' or 'Internal / Shared Mailbox'."
					}
				} elseif (!$CheckAD -and $ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "External User" -and $ContactType -notlike "Internal / Shared Mailbox" -and $EmailOnly -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and 'ToEmailOnly' -notin $IgnoreWarnings) {
					# ToEmailOnly (without AD)
					$WarnObj.type = "ToEmailOnly"
					$WarnObj.reason = "$EmailType account appears to be email-only based on O365 licenses and assigned devices. Consider changing the IT Glue Contact type to 'Employee - Email Only'. Alternatively: 'External User' or 'Internal / Shared Mailbox'."
					if ($EmailOnlyDetails) {
						$WarnObj.reason += "(Reason: $EmailOnlyDetails)"
					}
				} elseif (!$CheckAD -and $ContactType -notlike "Employee - Part Time" -and $ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "Shared Account" -and $ContactType -notlike "Employee - Multi User" -and 
							!$NoRecentUsage -and $PartTimeUsage -and 'ToEmployeePartTime' -notin $IgnoreWarnings) {
					# ToEmployeePartTime
					$WarnObj.type = "ToEmployeePartTime"
					$WarnObj.reason = "$EmailType account appears to be part time. Consider changing the IT Glue Contact type to 'Employee - Part Time'."
					$WarnObj.reason += " (Last Months Usage: $($LastMonthUsage)% [$($UsageStats.DaysActive.LastMonth) days])"
				} elseif (!$CheckAD -and $ContactType -like "Employee - Part Time" -and $ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "Shared Account" -and $ContactType -notlike "Employee - Multi User" -and 
							$ContactType -notlike "Contractor" -and !$PartTimeUsage -and $PartTimeEmployeesByUsage -and 'ToEmployee' -notin $IgnoreWarnings) {
					#ToEmployee[FromPartTime]
					$WarnObj.type = "ToEmployee[FromPartTime]"
					$WarnObj.reason = "AD account appears to be a full employee but is currently set to part time. Consider changing the IT Glue Contact type to 'Employee'."
				} elseif (!$ContactType -and !$HasAD) {
					#NoContactType
					$WarnObj.type = "NoContactType"
					$WarnObj.reason = "ITG has no contact type set for this contact but an $EmailType account exists. Please audit this account."
				}

				if ($WarnObj.type) {
					$Existing = $WarnContacts | Where-Object { $_.id -eq $MatchID }
					if (!$Existing -or ($Existing -and ($Existing.type -replace "\[|\]", "") -notlike ($WarnObj.type -replace "\[|\]", ""))) {
						if ($Existing -and ($WarnObj.type -eq 'MaybeTerminate' -or $WarnObj.type -eq 'ToTerminated')) {
							if ($WarnObj.type -eq 'ToTerminated' -and $Existing.type -eq 'MaybeTerminate') {
								$WarnContacts = [System.Collections.ArrayList] ($WarnContacts | Where-Object { $_.id -ne $MatchID })
								$WarnContacts.Add($WarnObj) | Out-Null
							} elseif ($WarnObj.type -ne 'MaybeTerminate' -or ($WarnObj.type -eq 'MaybeTerminate' -and $Existing.type -ne 'ToTerminated')) {
								$WarnContacts.Add($WarnObj) | Out-Null
							}
						} else {
							$WarnContacts.Add($WarnObj) | Out-Null
						}
					}
				}
			}

			############
			# IT Glue Note Checks
			if ((($WarnContacts | Where-Object { $_.id -eq $MatchID }) | Measure-Object).Count -le 0) {
				$WarnObj = @{
					id = $MatchID
					category = 'ITG'
					type = $false
					reason = $false
					name = $Contact.name
				}

				if ($ContactType -ne 'Terminated' -and $ContactType -ne "Employee - On Leave" -and ($Contact.notes -like '*Disabled*' -or $Contact.title -like '*Disabled*') -and 'ImproperlyTerminated' -notin $IgnoreWarnings) {
					# ImproperlyTerminated
					$WarnObj.type = "ImproperlyTerminated"
					$WarnObj.reason = "ITG contact notes list 'Disabled', yet this account is not terminated. Please review and fix."
				} elseif (!$ContactType) {
					#ToUnknown
					$WarnObj.type = "NoContactType"
					$WarnObj.reason = "ITG account has no contact type but no suggestion could be made. Please fix the type manually."
				}

				if ($WarnObj.type){
					$WarnContacts.Add($WarnObj) | Out-Null
				}
			}
		}

		$WarnCount = ($WarnContacts | Measure-Object).Count
		Write-Host "Audit complete. $($WarnCount) issues have been found."
		Write-PSFMessage -Level Verbose -Message "Audit complete. Issues found: $($WarnCount)"
		$UserCleanupUpdateRan = $true

		if ($WarnCount -gt 0) {
			$WarnContacts = $WarnContacts | Sort-Object @{Expression={$_.type}}, @{Expression={$_.category}}, @{Expression={$_.name}}
			$WarnContacts = [Collections.Generic.List[Object]]@($WarnContacts)

			# See what inactive accounts we warned on in the past and remove the related warnings
			if (!$config) {
				$auditFilesPath = "C:\billing_audit\contact_warnings.json"
			} else {
				$auditFilesPath = "C:\billing_audit\$($OrgShortName)\contact_warnings.json"
			}
			$OldContactWarnings = @()
			if (Test-Path $auditFilesPath) {
				$OldContactWarnings = Get-Content -Path $auditFilesPath -Raw | ConvertFrom-Json
			}

			$OldContactWarnings | Where-Object { $_.type -eq "MaybeTerminate" } | ForEach-Object {
				$NewIndex = $WarnContacts.FindIndex( { $args[0].id -eq $_.id -and $args[0].type -eq $_.type -and $args[0].category -eq $_.category } )
				if ($NewIndex -ge 0) {
					[void]$WarnContacts.RemoveAt($NewIndex)
				}
			}

			# Export a full list of what we just warned on and what we warned on in the past
			$AllContactWarnings = @(($WarnContacts | ConvertTo-Json | ConvertFrom-Json)) + $OldContactWarnings
			$ContactWarningsJson = $AllContactWarnings | ConvertTo-Json
			if (!$config) {
				$auditFilesPath = "C:\billing_audit\contact_warnings.json"
			} else {
				$auditFilesPath = "C:\billing_audit\$($OrgShortName)\contact_warnings.json"
			}
			$ContactWarningsJson | Out-File -FilePath $auditFilesPath
			Write-Host "Exported contact warnings to a json file."
		}

		$WarnCount = ($WarnContacts | Measure-Object).Count
		if ($WarnCount -gt 0 -or ($UnmatchedAD -and ($UnmatchedAD | Measure-Object).Count -gt 0) -or ($UnmatchedO365 -and ($UnmatchedO365 | Measure-Object).Count -gt 0)) {
			if ($EmailFrom.Email -and $EmailTo_Audit[0] -and $EmailTo_Audit[0].Email) {
				# Lets add info on any duplicate contacts (only if other warnings exist)
				$UniqueContacts = $FullContactList.attributes."name" | Select-Object -Unique
				$DuplicateContacts = @()
				if ($UniqueContacts) {
					$DuplicateContacts = Compare-Object -ReferenceObject $UniqueContacts -DifferenceObject $FullContactList.attributes."name"
				}
				$DuplicateIDs = @()

				foreach ($Contact in $DuplicateContacts.InputObject) {
					$DuplicateIDs += ($FullContactList | Where-Object { $_.attributes.name -like $Contact }).id
				}

				# Create some html for an email based on the $WarnContacts
				$DueDate = $(get-date).AddDays(5).ToString("dddd, MMMM d")
				$HTMLBody = ""

				if ($WarnContacts) {
					$WarnContacts | ForEach-Object {
						$FullMatchID = $_.id
						$Contact = $EmployeeContacts | Where-Object { $_.ID -eq $FullMatchID }

						$HTMLBody += '
									<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
										<strong>Contact:</strong> {0}<br />
										<strong>Issue Type:</strong> {1} (from {2} check)<br />
										<strong>Issue:</strong> {3}<br />
										<strong>ITG Link:</strong> <a href="{4}">{4}</a>
									</p><br />' -f $_.name, $_.type, $_.category, $_.reason, $Contact."resource-url"
					}
					# Now lets add a table to the end
					$HTMLBody += "<br /><br />"
					$HTMLBody += '
									<table class="desktop_only_table" cellpadding="0" cellspacing="0" style="border-collapse: collapse; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: auto;">
										<tbody>
										<tr>
											<th>Contact</th>
											<th>Current Type</th>
											<th>AD Username</th>
											<th>O365 Email</th>
											<th>Issue Type</th>
											<th>From Check</th>
											<th>Issue</th>
											<th>ITG Link</th>
										</tr>'
					$WarnContacts | ForEach-Object {
						$FullMatchID = $_.id
						$Contact = $EmployeeContacts | Where-Object { $_.ID -eq $FullMatchID }
						$ContactID = $Contact.id
						if ($CheckEmail) {
							$O365Match = ($O365Matches | Where-Object { $_.ID -eq $ContactID }).o365
						}
						if ($CheckAD) {
							$ADMatch = ($ADMatches | Where-Object { $_.ID -eq $ContactID }).ad
						}

						$ADUsername = 'N/A'
						$O365Email = 'N/A'
						if ($CheckAD -and $ADMatch) {
							$ADUsername = $ADMatch.Username
						}
						if ($CheckEmail -and $O365Match) {
							$O365Email = $O365Match.PrimarySmtpAddress
						}

						$HTMLBody += '
										<tr>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{0}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{1}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{2}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{3}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{4}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{5}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;">{6}</td>
											<td style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 5px; border: 1px solid #000000;"><a href="{7}">{7}</a></td>
										</tr>' -f $_.name, $Contact."contact-type-name", $ADUsername, $O365Email, $_.type, $_.category, $_.reason, $Contact."resource-url"
					}
					$HTMLBody += '
										</tbody>
									</table>
									<div class="mobile_table_fallback" style="display: none;">
										Table version hidden. You can view a tabular version of the above data on a desktop.
									</div><br />'
				}

				# If there were unmatched AD accounts, lets output those as well
				if ($CheckAD -and $UnmatchedAD -and ($UnmatchedAD | Measure-Object).Count -gt 0) {
					$HTMLBody += '<br />
							<p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>Unmatched AD Accounts Found</strong></p>
							<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								The following AD accounts do not appear to have an associated contact in ITG. Please review and add an ITG contact if necessary.
								The next time this report runs these unmatched accounts will be ignored.
							</p>
							<ul>
					'
					foreach ($ADAccount in $UnmatchedAD) {
						$HTMLBody += "<li><u>$($ADAccount.Name)</u> ($($ADAccount.EmailAddress)) (Last Logon: $($ADAccount.LastLogonDate)) ($($ADAccount.Description))</li>"
					}
					$HTMLBody += '</ul><br />'
				}

				# If there were unmatched O365 accounts, output those
				if ($CheckEmail -and $UnmatchedO365 -and ($UnmatchedO365 | Measure-Object).Count -gt 0) {
					$HTMLBody += '<br />
							<p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>Unmatched Email Accounts Found</strong></p>
							<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								The following Email accounts do not appear to have an associated contact in ITG. Please review and add an ITG contact if necessary.
								The next time this report runs these unmatched accounts will be ignored.
							</p>
							<ul>
					'
					foreach ($O365Account in $UnmatchedO365) {
						$HTMLBody += "<li><u>$($O365Account.DisplayName)</u> ($($O365Account.PrimarySmtpAddress)) (Primary License: $($O365Account.PrimaryLicense))</li>"
					}
					$HTMLBody += '</ul><br />'
				}

				if (($DuplicateIDs | Measure-Object).Count -gt 0) {
					$HTMLBody += '<br />
							<p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>Possible Duplicate ITG Contacts Found</strong></p>
							<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								The following ITG Contacts may be duplicates. Please review and remove/combine any contacts where necessary.
							</p>
							<ul>
					'

					foreach ($ID in $DuplicateIDs) {
						$Contact = $FullContactList | Where-Object { $_.id -eq $ID }
						$PrimaryEmail = ($Contact.attributes."contact-emails" | Where-Object {$_.primary -eq $true}).value
						$HTMLBody += "<li><u>$($Contact.attributes.Name)</u> ($($Contact.attributes.'contact-type-name')) (Location: $($Contact.attributes.'location-name')) (Email: $($PrimaryEmail)) (URL: $($Contact.attributes.'resource-url'))</li>"
					}
					$HTMLBody += '</ul><br />'
				}

				$EmailIntro = "Contact discrepancies were found at <strong>$OrgFullName</strong>. These will affect billing. Please review each and fix. A tabular summary is at the end of this email.
							<br /><br />Please correct these issues before <strong>$DueDate</strong>, at that time billing will be updated based on the ITG contact list. 
							Note that any issues you ignore now will not be reported on next month."							

				$HTMLEmail = $EmailTemplate -f `
								$EmailIntro, 
								"Contact Issues Found:", 
								$HTMLBody, 
								""
				$EmailSubject = "Contact Issues Found @ $OrgFullName"

				# Send email
				$mailbody = @{
					"From" = $EmailFrom
					"To" = $EmailTo_Audit
					"Subject" = $EmailSubject
					"HTMLContent" = $HTMLEmail
				} | ConvertTo-Json -Depth 6

				$headers = @{
					'x-api-key' = $Email_APIKey
				}
				
				Invoke-RestMethod -Method Post -Uri $Email_APIEndpoint -Body $mailbody -Headers $headers -ContentType application/json
				Write-Host "Sent Email" -ForegroundColor Green
			}
		}
	}

	Write-Host "User Audit Complete!" -ForegroundColor Black -BackgroundColor Green
	Write-PSFMessage -Level Verbose -Message "User Audit Complete."
}
# END device audit


################
#### Running a Billing Update
#### This will get the contact list from ITG and update the billing document
#### If there were changes from last month it will send an email to accounting
#### Use parameter -BillingUpdate $true   (default off)
####
#### Note: This code is almost directly pulled from the User Audit powershell script
####		The only difference is a small amount of code to check for changes and send an email at the end if changes were found
####		Search "Custom Code" to find this bit of code
####
#### TODO: Move this code into an external function that both this script and the User Audit script can use instead of copying the code
################
if ($BillingUpdate) {
	Write-PSFMessage -Level Verbose -Message "Starting Billing Update."

	$Version = (Get-Module -ListAvailable -Name "ImportExcel").Version
	if ($Version.Major -lt 7 -or $Version.Minor -lt 8 -or $Version.Build -lt 4) {
		Remove-Module ImportExcel
		Uninstall-Module ImportExcel
		Install-Module -Name ImportExcel
		Import-Module ImportExcel -Force
	}

	If (Get-Module -ListAvailable -Name "ImportExcel") {Import-module ImportExcel} Else { install-module ImportExcel -Force; import-module ImportExcel}
	
	# Get a fresh list of contacts from IT Glue
	$FullContactList = @()
	$i = 1
	while ($i -le 10 -and ($FullContactList | Measure-Object).Count -eq (($i-1) * 500)) {
		$FullContactList += (Get-ITGlueContacts -page_size 500 -page_number $i -organization_id $OrgID).data
		Write-Host "- Got contact set $i"
		$TotalContacts = ($FullContactList | Measure-Object).Count
		Write-Host "- Total: $TotalContacts"
		$i++
	}
	$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
	$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
	Write-PSFMessage -Level Verbose -Message "Got $(($FullContactList | Measure-Object).Count) contacts from IT Glue."

	# Export a csv into the billing history folder (overwrite if same month)
	New-Item -ItemType Directory -Force -Path "C:\billing_history" | Out-Null
	$Month = Get-Date -Format "MM"
	$Year = Get-Date -Format "yyyy"
	$historyContacts = $FullContactList | ConvertTo-Json
	if (!$config) {
		$historyPath = "C:\billing_history\contacts_$($Month)_$($Year).json"
	} else {
		if (!(Test-Path -Path "C:\billing_history\$($OrgShortName)")) {
			New-Item -Path "C:\billing_history\$($OrgShortName)" -ItemType Directory | Out-Null
		}
		$historyPath = "C:\billing_history\$($OrgShortName)\contacts_$($Month)_$($Year).json"
	}
	$historyContacts | Out-File -FilePath $historyPath
	Write-Host "Exported a billing history file."
	Write-PSFMessage -Level Verbose -Message "Exported billing history file: $historyPath"

	# Export billing user list to CSV
	Write-Host "Generating billing report..."
	Write-PSFMessage -Level Verbose -Message "Generating Billing Report."

	# First get the history file if it exists to perform a diff
	$Month = Get-Date -Format "MM"
	$Year = Get-Date -Format "yyyy"
	$LastMonth = '{0:d2}' -f ([int]$Month - 1)
	$LastYear = $Year
	if ([int]$Month -eq 1) {
		$LastMonth = "12"
		$LastYear = $Year - 1
	}
	$CheckChanges = $false
	if (!$config) {
		$historyPath = "C:\billing_history\contacts_$($LastMonth)_$($LastYear).json"
	} else {
		$historyPath = "C:\billing_history\$($OrgShortName)\contacts_$($LastMonth)_$($LastYear).json"
	}
	if (Test-Path $historyPath) {
		$CheckChanges = $true
		$HistoryContactList = Get-Content -Path $historyPath -Raw | ConvertFrom-Json
	}

	if ($CheckChanges) {
		$HistoryContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
		$HistoryContactList | ForEach-Object { $_.attributes.id = $_.id }
		$HistoryContactList = $HistoryContactList.attributes
		$HistoryChanges = Compare-Object $HistoryContactList $FullContactList.attributes -Property id, name, contact-type-name
	}
	$BilledEmployees = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $BilledContactTypes}
	$UnbilledEmployees = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $UnbilledContactTypes -or !$_."contact-type-name"}
	$NonEmployees = $FullContactList.attributes | Where-Object {$_."contact-type-name" -notin $BilledContactTypes -and $_."contact-type-name" -notin $UnbilledContactTypes -and $_."contact-type-name" -notlike "Terminated"}

	# Put together the object lists for the billed and unbilled users
	$billedCsvTable = @()
	$movedToBilledUser = @()
	$fixedUser = @()
	foreach ($User in $BilledEmployees) {

		$Type = $User."contact-type-name"
		if ($Type -in $ConvertToEmployeeTypes) {
			$Type = "Employee"
		}

		$properties = [ordered]@{
			"Name" = $User.name
			"Type" = $Type
			"Title" = $User.title
		}
		if ($HasMultipleLocations) {
			$properties.Location = $User."location-name"
		}

		if ($CheckChanges) {
			$properties."New?" = ""
			if ($User.id -notin $HistoryContactList.id) {
				$properties."New?" = "Yes"
			}
			if ($User.id -in $HistoryContactList.id) { 
				$HistoryType = ($HistoryContactList | Where-Object { $_.id -eq $User.id })."contact-type-name"
				if ($HistoryType -and $HistoryType -in $UnbilledContactTypes) {
					$properties.Type = $HistoryType
					$movedToBilledUser += New-Object PSObject -Property $properties
					$properties.Type = $Type
					$properties."New?" = "Yes (was unbilled)"				
				} elseif ($HistoryType -eq "Terminated") {
					$properties."New?" = "Yes (was terminated)"
				} elseif ($HistoryType -and $HistoryType -notin $BilledContactTypes) {
					$properties."New?" = "Yes (was $($HistoryType))"
				} elseif (!$HistoryType) {
					$properties."New?" = "Yes (was unknown)"
					$fixedUser += New-Object PSObject -Property $properties
				}
			}
		}

		$csvRow = New-Object PSObject -Property $properties
		$billedCsvTable += $csvRow
	}

	$unbilledCsvTable = @()
	$movedToUnbilledUser = @()
	foreach ($User in $UnbilledEmployees) {

		$Type = $User."contact-type-name"
		if (!$Type) {
			$Type = "Unknown"
		}

		$properties = [ordered]@{
			"Name" = $User.name
			"Type" = $Type
			"Title" = $User.title
		}
		if ($HasMultipleLocations) {
			$properties.Location = $User."location-name"
		}

		if ($CheckChanges) {
			$properties."New?" = ""
			if ($User.id -notin $HistoryContactList.id) {
				$properties."New?" = "Yes"
			}
			if ($User.id -in $HistoryContactList.id) {
				$HistoryType = ($HistoryContactList | Where-Object { $_.id -eq $User.id })."contact-type-name"
				if ($HistoryType -and $HistoryType -in $BilledContactTypes) {
					$properties.Type = $HistoryType
					$movedToUnbilledUser += New-Object PSObject -Property $properties
					$properties.Type = $Type
					$properties."New?" = "Yes (was billed)"
				} elseif ($HistoryType -eq "Terminated") {
					$properties."New?" = "Yes (was terminated)"
				} elseif ($HistoryType -and $HistoryType -notin $UnbilledContactTypes) {
					$properties."New?" = "Yes (was $($HistoryType))"
				} elseif (!$HistoryType) {
					$properties."New?" = "Yes (was unknown)"
					$fixedUser += New-Object PSObject -Property $properties
				}
			}
		}

		$csvRow = New-Object PSObject -Property $properties
		$unbilledCsvTable += $csvRow
	}

	$movedToNonEmployee = @()
	if ($CheckChanges -and $NonEmployees) {
		foreach ($User in $NonEmployees) {

			$Type = $User."contact-type-name"
			$properties = [ordered]@{
				"Name" = $User.name
				"Type" = $Type
				"Title" = $User.title
			}
			if ($HasMultipleLocations) {
				$properties.Location = $User."location-name"
			}

			if ($User.id -in $HistoryContactList.id) {
				$HistoryType = ($HistoryContactList | Where-Object { $_.id -eq $User.id })."contact-type-name"
				if ($HistoryType -in $BilledContactTypes -or $HistoryType -in $UnbilledContactTypes) {
					$properties.Type = $HistoryType
					if (!$HistoryType) {
						$properties.Type = "Unknown"
						$fixedUser += New-Object PSObject -Property $properties
					} else {
						$movedToNonEmployee += New-Object PSObject -Property $properties
					}
				}
			}
		}
	}

	$unbilledToTerminated = @()
	$billedToTerminated = @()
	if ($CheckChanges -and $HistoryChanges) {
		# get the tables of terminated users
		$BecameTerminated = @()
		$BecameTerminated += $HistoryChanges | Where-Object { $_."contact-type-name" -like "Terminated" -and $_.SideIndicator -eq "=>" }
		$UniqueAccounts = $HistoryChanges.id | Group-Object | Where-Object { $_.Count -eq 1 } | Select-Object -ExpandProperty Group
		$BecameTerminated += $HistoryChanges | Where-Object { $_.id -in $UniqueAccounts -and $_.SideIndicator -eq "<=" -and $_."contact-type-name" -notlike "Terminated" }

		foreach ($User in $BecameTerminated) {
			$HistoryUser = $HistoryContactList | Where-Object { $_.id -eq $User.id }

			$Type = $HistoryUser."contact-type-name"
			if ($Type -in $ConvertToEmployeeTypes) {
				$Type = "Employee"
			} elseif (!$Type) {
				$Type = "Unknown"
			}

			$properties = [ordered]@{
				"Name" = $HistoryUser.name
				"Past Type" = $Type
			}
			if ($HasMultipleLocations) {
				$properties.Location = $HistoryUser."location-name"
			}
			$csvRow = New-Object PSObject -Property $properties

			if ($HistoryUser."contact-type-name" -in $BilledContactTypes) {
				$billedToTerminated += $csvRow
			} else {
				$unbilledToTerminated += $csvRow
			}
		}
	}

	# get totals for totals table
	$Totals = @()
	$TotalTypes = Compare-Object -ReferenceObject $BilledContactTypes -DifferenceObject $ConvertToEmployeeTypes -PassThru
	$TotalTypes += $UnbilledContactTypes

	foreach ($Type in $TotalTypes) {
		if (!$Type) { continue; }
		if ($Type -in $BilledContactTypes) {
			$Totals += [PSCustomObject]@{
				Type = $Type
				Billed = ($billedCsvTable | Where-Object { $_.Type -eq $Type } | Measure-Object).Count
				Unbilled = $null
			}
		} else {
			$Totals += [PSCustomObject]@{
				Type = $Type
				Billed = $null
				Unbilled = ($unbilledCsvTable | Where-Object { $_.Type -eq $Type } | Measure-Object).Count
			}
		}
	}
	$Totals += [PSCustomObject]@{
		Type = "Unknown"
		Billed = $null
		Unbilled = ($unbilledCsvTable | Where-Object { !$_.Type -or $_.Type -eq "Unknown" } | Measure-Object).Count
	}


	# calculate total changes
	if ($CheckChanges) {
		$TotalChanges = @()
		$TotalChanges += [PSCustomObject]@{
			Month = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName([int]$LastMonth)
			"Billed FT" = ($HistoryContactList | Where-Object { $_."contact-type-name" -in $BilledContactTypes -and $_."contact-type-name" -notlike "*Part Time*" } | Measure-Object).Count
			"Billed PT" = ($HistoryContactList | Where-Object { $_."contact-type-name" -in $BilledContactTypes -and $_."contact-type-name" -like "*Part Time*" } | Measure-Object).Count
			Unbilled = ($HistoryContactList | Where-Object { $_."contact-type-name" -in $UnbilledContactTypes -or !$_."contact-type-name" } | Measure-Object).Count
		}
		$TotalChanges += [PSCustomObject]@{
			Month = (Get-Culture).DateTimeFormat.GetAbbreviatedMonthName([int]$Month)
			"Billed FT" = ($FullContactList.attributes | Where-Object { $_."contact-type-name" -in $BilledContactTypes -and $_."contact-type-name" -notlike "*Part Time*" } | Measure-Object).Count
			"Billed PT" = ($FullContactList.attributes | Where-Object { $_."contact-type-name" -in $BilledContactTypes -and $_."contact-type-name" -like "*Part Time*" } | Measure-Object).Count
			Unbilled = ($FullContactList.attributes | Where-Object { $_."contact-type-name" -in $UnbilledContactTypes -or !$_."contact-type-name" } | Measure-Object).Count
		}
		$TotalChanges += [PSCustomObject]@{
			Month = "Total"
			"Billed FT" = $TotalChanges[1]."Billed FT" - $TotalChanges[0]."Billed FT"
			"Billed PT" = $TotalChanges[1]."Billed PT" - $TotalChanges[0]."Billed PT"
			Unbilled = $TotalChanges[1].Unbilled - $TotalChanges[0].Unbilled
		}
	}

	# Create the excel document
	$MonthName = (Get-Culture).DateTimeFormat.GetMonthName([int](Get-Date -Format MM))
	$Year = Get-Date -Format yyyy
	$FileName = "$($OrgShortName)--Billed_User_List--$($MonthName)_$Year.xlsx"
	$Path = $PSScriptRoot + "\$FileName"
	Remove-Item $Path -ErrorAction SilentlyContinue

	$excel = $Totals | Export-Excel -Path $Path -WorksheetName "Billed Employees" -AutoSize -StartRow 4 -PassThru
	$ws = $excel.Workbook.Worksheets['Billed Employees']

	$xlParams = @{WorkSheet=$ws; Bold=$true; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#44546A"); FontSize=20; HorizontalAlignment="Center"; Merge=$true}
	Set-ExcelRange -Range "A1:H1" -Value "$($OrgFullName) - Billed User List ($($MonthName))" @xlParams 
	$totalsTblLastRow = (($TotalTypes | Measure-Object).Count + 5)

	# totals title
	$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#548235"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#375623"); FontSize=15; HorizontalAlignment="Center"; Merge=$true}
	Set-ExcelRange -Range "A3:C3" -Value "Totals" @xlParams

	# totals table
	Add-ExcelTable -PassThru -Range $ws.Cells["A4:C$($totalsTblLastRow)"] -TableName Totals -TableStyle "Light21" -ShowFilter:$false -ShowTotal -ShowFirstColumn -TableTotalSettings @{"Billed" = "Sum"; "Unbilled" = "Sum"} | Out-Null
	$totalsTblLastRow += 1
	$xlParams = @{WorkSheet=$ws; BackgroundColor=[System.Drawing.ColorTranslator]::FromHtml("#A9D08E")}
	Set-ExcelRange -Range "B$($totalsTblLastRow):C$($totalsTblLastRow)" @xlParams

	# totals by location table
	if ($TotalsByLocation -and $HasMultipleLocations) {
		$TotalsByLoc = @()

		foreach ($Location in $Locations) {
			$BilledCount = ($billedCsvTable | Where-Object { $_.Location -eq $Location.name } | Measure-Object).Count
			$UnbilledCount = ($unbilledCsvTable | Where-Object { $_.Location -eq $Location.name } | Measure-Object).Count
			if (!$BilledCount -and !$UnbilledCount) { continue; }
			$TotalsByLoc += [PSCustomObject]@{
				Location = $Location.name
				Billed = $BilledCount
				Unbilled = $UnbilledCount
			}
		}
		$NoLocBilledCount = ($billedCsvTable | Where-Object { !$_.Location } | Measure-Object).Count
		$NoLocUnbilledCount = ($unbilledCsvTable | Where-Object { !$_.Location } | Measure-Object).Count
		if ($NoLocBilledCount -or $NoLocUnbilledCount) {
			$TotalsByLoc += [PSCustomObject]@{
				Type = "Unknown"
				Billed = $NoLocBilledCount
				Unbilled = $NoLocUnbilledCount
			}
		}

		$totalsByLocFirstRow = $totalsTblLastRow + 4
		$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#548235"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#375623"); FontSize=15; HorizontalAlignment="Center"; Merge=$true}
		Set-ExcelRange -Range "A$($totalsByLocFirstRow):C$($totalsByLocFirstRow)" -Value "Totals by Location" @xlParams
		$totalsByLocFirstRow += 1

		$totalsTblLastRow = $totalsByLocFirstRow + ($TotalsByLoc | Measure-Object).Count
		$excel = $TotalsByLoc | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $totalsByLocFirstRow
		Add-ExcelTable -PassThru -Range $ws.Cells["A$($totalsByLocFirstRow):C$($totalsTblLastRow)"] -TableName TotalsByLoc -TableStyle "Light21" -ShowFilter:$false -ShowTotal -ShowFirstColumn -TableTotalSettings @{"Billed" = "Sum"; "Unbilled" = "Sum"} | Out-Null
		$totalsTblLastRow += 1
		$xlParams = @{WorkSheet=$ws; BackgroundColor=[System.Drawing.ColorTranslator]::FromHtml("#A9D08E")}
		Set-ExcelRange -Range "B$($totalsTblLastRow):C$($totalsTblLastRow)" @xlParams
	}

	if ($CheckChanges) {
		# total changes title
		$ChangesTitle = "Changes (" + $TotalChanges[0].Month + " to " + $TotalChanges[1].Month + ")"
		$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#548235"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#375623"); FontSize=15; HorizontalAlignment="Center"; Merge=$true}
		Set-ExcelRange -Range "F3:H3" -Value $ChangesTitle @xlParams

		# total changes table
		$excel = $TotalChanges | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow 4 -StartColumn 6
		Add-ExcelTable -PassThru -Range $ws.Cells["F4:I7"] -TableName TotalChanges -TableStyle "Light21" -ShowFilter:$false -ShowFirstColumn | Out-Null
		$xlParams = @{WorkSheet=$ws; Bold=$true; BackgroundColor=[System.Drawing.ColorTranslator]::FromHtml("#A9D08E"); BorderTop="Double"; BorderBottom="Hair"; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#70AD47")}
		Set-ExcelRange -Range "F7:I7" @xlParams
		Set-ExcelRange -Range "G7:I7" -Worksheet $ws -NumberFormat "+0;-0;0"

		$ctGt = New-ConditionalText -Range "G7:I7" -ConditionalType "GreaterThan" -Text "0"
		$ctColors = @{BackgroundColor=[System.Drawing.ColorTranslator]::FromHtml("#FFEB9C"); ConditionalTextColor=[System.Drawing.ColorTranslator]::FromHtml("#9C5700")}
		$ctLt = New-ConditionalText -Range "G7:I7" -ConditionalType "LessThan" -Text "0" @ctColors
		$excel = Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -ConditionalText $ctGt, $ctLt

		$SmallTableLastCol = "B"
		if ($HasMultipleLocations) {
			$SmallTableLastCol = "C"
		}
	}

	# billed employees title and table
	$TableLastCol = "C"
	if ($HasMultipleLocations -and $CheckChanges) {
		$TableLastCol = "E"
	} elseif ($HasMultipleLocations -or (!$HasMultipleLocations -and $CheckChanges)) {
		$TableLastCol = "D"
	}
	$billedEmployeesTblFirstRow = $totalsTblLastRow + 4
	$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#4472C4"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#44546A"); FontSize=15; HorizontalAlignment="Center"; Merge=$true}
	Set-ExcelRange -Range "A$($billedEmployeesTblFirstRow):$($TableLastCol)$($billedEmployeesTblFirstRow)" -Value "Billed Employees" @xlParams
	$billedEmployeesTblFirstRow += 2

	$billedEmployeesTable = $billedCsvTable | Sort-Object Type, @{Expression="New?";Descending=$true}, Name
	$billedEmployeesTblLastRow = $billedEmployeesTblFirstRow + ($billedEmployeesTable | Measure-Object).Count
	$tableName = "BilledEmployees"
	$excel = $billedEmployeesTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $billedEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium2"
	
	if ($CheckChanges) {
		$ctColors = @{ForegroundColor=[System.Drawing.ColorTranslator]::FromHtml("#548235")}
		$ctFormula = '=ISNUMBER(SEARCH("Yes",$' + $TableLastCol + '' + ($billedEmployeesTblFirstRow+1) + '))'
		Add-ConditionalFormatting -Address "A$($billedEmployeesTblFirstRow+1):$($TableLastCol)$($billedEmployeesTblLastRow)" -Worksheet $ws -RuleType Expression -ConditionValue $ctFormula -Bold @ctColors
		$billedEmployeesTblFirstRow = $billedEmployeesTblLastRow + 2
	}

	if ($CheckChanges) {
		$LastMonthName = (Get-Culture).DateTimeFormat.GetMonthName([int]$LastMonth)
		$MonthName = (Get-Culture).DateTimeFormat.GetMonthName([int]$Month)
		if ($billedToTerminated) {
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#C65911"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#C00000"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($billedEmployeesTblFirstRow):$($SmallTableLastCol)$($billedEmployeesTblFirstRow)" -Value "Terminated Employees*" @xlParams
			$billedEmployeesTblFirstRow += 1

			$terminatedTable = $billedToTerminated | Select-Object Name, "Past Type", Location
			if (!$HasMultipleLocations) {
				$terminatedTable = $terminatedTable | Select-Object Name, "Past Type"
			}
			$billedEmployeesTblLastRow = $billedEmployeesTblFirstRow + ($terminatedTable | Measure-Object).Count
			$tableName = "BilledTerminatedEmployees"
			$excel = $terminatedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $billedEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium3"
			$xlColors = @{FontColor=[System.Drawing.ColorTranslator]::FromHtml("#C00000")}
			Set-ExcelRange -Range "A$($billedEmployeesTblFirstRow+1):$($SmallTableLastCol)$($billedEmployeesTblLastRow)" -Worksheet $ws -Bold @xlColors
			$billedEmployeesTblLastRow += 1

			Set-ExcelRange -Range "A$($billedEmployeesTblLastRow)" -Worksheet $ws -Value "* These employees are no longer billed and were terminated between $($LastMonthName) and $($MonthName)."
			$billedEmployeesTblFirstRow = $billedEmployeesTblLastRow + 2
		}	

		if ($movedToUnbilledUser) {
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#BF8F00"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#806000"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($billedEmployeesTblFirstRow):$($SmallTableLastCol)$($billedEmployeesTblFirstRow)" -Value "Moved to Unbilled Employees" @xlParams
			$billedEmployeesTblFirstRow += 1

			$movedTable = $movedToUnbilledUser | Add-Member -MemberType AliasProperty -Name "Past Type" -Value Type -PassThru | Select-Object Name, "Past Type", Location
			if (!$HasMultipleLocations) {
				$movedTable = $movedTable | Select-Object Name, "Past Type"
			}
			$billedEmployeesTblLastRow = $billedEmployeesTblFirstRow + ($movedTable | Measure-Object).Count
			$tableName = "BilledMovedToUnbilled"
			$excel = $movedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $billedEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium5"
			$billedEmployeesTblFirstRow = $billedEmployeesTblLastRow + 2
		}
	}

	# unbilled employees title and table
	if ($unbilledCsvTable) {
		$unbilledEmployeesTblFirstRow = $billedEmployeesTblLastRow + 4
		$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#4472C4"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#44546A"); FontSize=15; HorizontalAlignment="Center"; Merge=$true}
		Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow):$($TableLastCol)$($unbilledEmployeesTblFirstRow)" -Value "Unbilled Employees" @xlParams
		$unbilledEmployeesTblFirstRow += 2

		$unbilledEmployeesTable = $unbilledCsvTable | Sort-Object Type, @{Expression="New?";Descending=$true}, Name
		$unbilledEmployeesTblLastRow = $unbilledEmployeesTblFirstRow + ($unbilledEmployeesTable | Measure-Object).Count
		$tableName = "UnbilledEmployees"
		$excel = $unbilledEmployeesTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $unbilledEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium2"
		$ctColors = @{ForegroundColor=[System.Drawing.ColorTranslator]::FromHtml("#548235")}
		$ctFormula = '=ISNUMBER(SEARCH("Yes",$' + $TableLastCol + '' + ($unbilledEmployeesTblFirstRow+1) + '))'
		Add-ConditionalFormatting -Address "A$($unbilledEmployeesTblFirstRow+1):$($TableLastCol)$($unbilledEmployeesTblLastRow)" -Worksheet $ws -RuleType Expression -ConditionValue $ctFormula -Bold @ctColors
		$unbilledEmployeesTblFirstRow = $unbilledEmployeesTblLastRow + 2
	} else {
		$unbilledEmployeesTblFirstRow = $billedEmployeesTblLastRow + 4
	}
	
	if ($CheckChanges) {
		if ($unbilledToTerminated) {
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#C65911"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#C00000"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow):$($SmallTableLastCol)$($unbilledEmployeesTblFirstRow)" -Value "Terminated Accounts*" @xlParams
			$unbilledEmployeesTblFirstRow += 1
			
			$terminatedTable = $unbilledToTerminated | Select-Object Name, "Past Type", Location
			if (!$HasMultipleLocations) {
				$terminatedTable = $terminatedTable | Select-Object Name, "Past Type"
			}
			$unbilledEmployeesTblLastRow = $unbilledEmployeesTblFirstRow + ($terminatedTable | Measure-Object).Count
			$tableName = "UnbilledTerminatedEmployees"
			$excel = $terminatedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $unbilledEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium3"
			$xlColors = @{FontColor=[System.Drawing.ColorTranslator]::FromHtml("#C00000")}
			Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow+1):$($SmallTableLastCol)$($unbilledEmployeesTblLastRow)" -Worksheet $ws -Bold @xlColors
			$unbilledEmployeesTblLastRow += 1

			Set-ExcelRange -Range "A$($unbilledEmployeesTblLastRow)" -Worksheet $ws -Value "* These unbilled employee accounts were removed between $($LastMonthName) and $($MonthName)."
			$unbilledEmployeesTblFirstRow = $unbilledEmployeesTblLastRow + 2
		}	

		if ($movedToBilledUser) {
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#BF8F00"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#806000"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow):$($SmallTableLastCol)$($unbilledEmployeesTblFirstRow)" -Value "Moved to Billed Employees" @xlParams
			$unbilledEmployeesTblFirstRow += 1

			$movedTable = $movedToBilledUser | Add-Member -MemberType AliasProperty -Name "Past Type" -Value Type -PassThru | Select-Object Name, "Past Type", Location
			if (!$HasMultipleLocations) {
				$movedTable = $movedTable | Select-Object Name, "Past Type"
			}
			$unbilledEmployeesTblLastRow = $unbilledEmployeesTblFirstRow + ($movedTable | Measure-Object).Count
			$tableName = "UnbilledMovedToBilled"
			$excel = $movedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $unbilledEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium5"
			$unbilledEmployeesTblFirstRow = $unbilledEmployeesTblLastRow + 2
		}

		if ($movedToNonEmployee) {
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#BF8F00"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#806000"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow):$($SmallTableLastCol)$($unbilledEmployeesTblFirstRow)" -Value "Moved to Non-Employee" @xlParams
			$unbilledEmployeesTblFirstRow += 1

			$movedTable = $movedToNonEmployee | Add-Member -MemberType AliasProperty -Name "Past Type" -Value Type -PassThru | Select-Object Name, "Past Type", Location
			if (!$HasMultipleLocations) {
				$movedTable = $movedTable | Select-Object Name, "Past Type"
			}
			$unbilledEmployeesTblLastRow = $unbilledEmployeesTblFirstRow + ($movedTable | Measure-Object).Count
			$tableName = "UnbilledMovedToNonEmployee"
			$excel = $movedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $unbilledEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium5"
			$unbilledEmployeesTblFirstRow = $unbilledEmployeesTblLastRow + 2
		}

		if ($fixedUser) {
			$FixedTableLastCol = "A"
			if ($HasMultipleLocations) {
				$FixedTableLastCol = "B"
			}
			$xlParams = @{WorkSheet=$ws; Bold=$true; BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#A2B8E1"); BorderBottom="Thick"; FontColor=[System.Drawing.ColorTranslator]::FromHtml("#44546A"); FontSize=13; HorizontalAlignment="Center"; Merge=$true}
			Set-ExcelRange -Range "A$($unbilledEmployeesTblFirstRow):$($FixedTableLastCol)$($unbilledEmployeesTblFirstRow)" -Value "Fixed Accounts*" @xlParams
			$unbilledEmployeesTblFirstRow += 1

			$fixedTable = $fixedUser | Select-Object Name, Location
			if (!$HasMultipleLocations) {
				$fixedTable = $fixedTable | Select-Object Name
			}
			$unbilledEmployeesTblLastRow = $unbilledEmployeesTblFirstRow + ($fixedTable | Measure-Object).Count
			$tableName = "FixedAccounts"
			$excel = $fixedTable | Export-Excel -PassThru -ExcelPackage $excel -WorksheetName $ws -AutoSize -StartRow $unbilledEmployeesTblFirstRow -TableName $tableName -TableStyle "Medium4"
			$unbilledEmployeesTblLastRow += 1

			Set-ExcelRange -Range "A$($unbilledEmployeesTblLastRow)" -Worksheet $ws -Value "* These accounts were marked as 'Unknown' last month but have since been fixed."
			$unbilledEmployeesTblFirstRow = $unbilledEmployeesTblLastRow + 2
		}
	}

	Close-ExcelPackage $excel
	Write-Host "Excel Report Exported." -ForegroundColor Green
	Write-PSFMessage -Level Verbose -Message "Excel Report Exported."

	#######
	### Upload billing report to ITG
	########

	# Get the info for the fields
	$TotalBilled = 0
	$TotalUnbilled = 0
	$Totals.Billed | ForEach-Object { $TotalBilled += $_ }
	$Totals.Unbilled | ForEach-Object { $TotalUnbilled += $_ }
	
	$UserBreakdownTable = "
		<table class='table table-striped'>
			<thead>
				<tr>
				<th>Type</th>
				<th>Billed</th>
				<th>Unbilled</th>
				</tr>
			</thead>
			<tbody>"

	foreach ($BillingType in $Totals) {
		$UserBreakdownTable += "
			<tr>
				<th>$($BillingType.Type)</th>
				<td>$($BillingType.Billed)</td>
				<td>$($BillingType.Unbilled)</td>
			</tr>"
	}
	$UserBreakdownTable += "
			<tr style='background-color: #e9e9e9'>
				<th style='background-color: #e9e9e9'><u>Totals</u></th>
				<td><strong><u>$TotalBilled</u></strong></td>
				<td><strong><u>$TotalUnbilled</u><strong></td>
			</tr>"
	$UserBreakdownTable += "
			</tbody>
		</table>"

	if ($TotalsByLocation -and $HasMultipleLocations) {
		$UserBreakdownTable += "
		<br />
		<h2>Totals by Location</h2>
		<table>
			<thead>
				<tr>
				<th>Location</th>
				<th>Billed</th>
				<th>Unbilled</th>
				</tr>
			</thead>
			<tbody>"

		$TotalsByLoc | Foreach-Object {
			$UserBreakdownTable += "
				<tr>
					<td>$($_.Location)</td>
					<td>$($_.Billed)</td>
					<td>$($_.Unbilled)</td>
				</tr>"
		}
		$UserBreakdownTable += "
			</tbody>
		</table>"
	}

	$ReportEncoded = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))

	# Get the existing info if it exists (anything that isn't updated will just get deleted, not left alone)
	$FlexAssetName = "Customer Billing"
	$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
	if ($FilterID) {
		$FlexAssetBody 	= 
		@{
			type 		= 'flexible-assets'
			attributes	= @{
				traits	= @{

				}
			}
		}
		
		$ExistingFlexAsset = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $OrgID -include attachments
		$ExistingFlexAsset.data = $ExistingFlexAsset.data | Select-Object -First 1

		if ($ExistingFlexAsset -and $ExistingFlexAsset.data.attributes.traits) {
			$ExistingFlexAsset.data.attributes.traits.PSObject.Properties | ForEach-Object {
				if ($_.name -eq "billing-report-user-list" -or $_.name -eq "billing-report-device-list") {
					return
				}
				$property = $_.name
				$FlexAssetBody.attributes.traits.$property = $_.value
			}
		}

		# Add the new data to be uploaded
		$FlexAssetBody.attributes.traits."billed-by" = "User"
		$FlexAssetBody.attributes.traits."number-of-billed-users" = $TotalBilled
		$FlexAssetBody.attributes.traits."user-breakdown" = $UserBreakdownTable
		$FlexAssetBody.attributes.traits.Remove("number-of-billed-computers")
		$FlexAssetBody.attributes.traits.Remove("number-of-billed-servers")
		$FlexAssetBody.attributes.traits.Remove("device-breakdown")
		$FlexAssetBody.attributes.traits."billing-report-user-list" = @{
			content 	= $ReportEncoded
			file_name 	= $FileName
		}

		# If billing report is already an attachment, delete so we can replace it
		if ($ExistingFlexAsset -and $ExistingFlexAsset.data.id -and $ExistingFlexAsset.included) {
			$Attachments = $ExistingFlexAsset.included | Where-Object {$_.type -eq 'attachments'}
			if ($Attachments -and ($Attachments | Measure-Object).Count -gt 0 -and $Attachments.attributes) {
				$MonthsAttachment = $Attachments.attributes | Where-Object { $_.name -like $FileName + '*' -or $_."attachment-file-name" -like $FileName + '*' }
				if ($MonthsAttachment) {
					$data = @{ 
						'type' = 'attachments'
						'attributes' = @{
							'id' = $MonthsAttachment.id
						}
					}
					Remove-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingFlexAsset.data.id -data $data | Out-Null
				}
			}
		}

		# Upload
		if ($ExistingFlexAsset -and $ExistingFlexAsset.data.id) {
			Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.data.id -data $FlexAssetBody | Out-Null
			Write-Host "Updated existing $FlexAssetName asset."
			Write-PSFMessage -Level Verbose -Message "Updated existing: $FlexAssetName asset"
		} else {
			$FlexAssetBody.attributes."organization-id" = $OrgID
			$FlexAssetBody.attributes."flexible-asset-type-id" = $FilterID.id
			$FlexAssetBody.attributes.traits."billed-by" = "User"
			$ExistingFlexAsset = New-ITGlueFlexibleAssets -data $FlexAssetBody
			Write-Host "Uploaded a new $FlexAssetName asset."
			Write-PSFMessage -Level Verbose -Message "Uploaded new: $FlexAssetName asset"
		}

		if ($ExistingFlexAsset -and $ExistingFlexAsset.data.id) {
			$data = @{ 
				'type' = 'attachments'
				'attributes' = @{
					'attachment' = @{
						'content' = $ReportEncoded
						'file_name'	= $FileName
					}
				}
			}
			New-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingFlexAsset.data.id -data $data | Out-Null
			Write-Host "Billing report uploaded and attached." -ForegroundColor Green
			Write-PSFMessage -Level Verbose -Message "Uploaded: Billing report"
		}

		# If there were changes to the amount of billed users, send an email to account (or if no billing history and this is a new setup)
		# Custom Code
		if ($EmailFrom.Email -and $EmailTo_BillingUpdate[0] -and $EmailTo_BillingUpdate[0].Email -and 
			(!(Test-Path variable:HistoryContactList) -or 
			($CheckChanges -and $TotalChanges -and (($TotalChanges | Select-Object -Last 1)."Billed FT" -ne 0 -or ($TotalChanges | Select-Object -Last 1)."Billed PT" -ne 0)))) 
		{

			# No past billing history
			if (!(Test-Path variable:HistoryContactList) -or !$CheckChanges) {
				$EmailSubject = "Bill May Need Updating for $OrgFullName - No history found"
				$EmailIntro = "The User Audit for $OrgFullName was updated but no billing history could be found. Please verify this organization's bill is correct. Next month an email will only be sent if changes were made."
				$BilledUsersFTTotal = (($Totals | Where-Object { $_.Type -notlike "*Part Time*" }).Billed | Measure-Object -Sum).Sum
				$BilledUsersPTTotal = (($Totals | Where-Object { $_.Type -like "*Part Time*" }).Billed | Measure-Object -Sum).Sum
				$EmailTitle = "New Totals"
				$HTMLBody = '<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								<strong>Full Time Employees:</strong> ' + $BilledUsersFTTotal + '<br />
								<strong>Part Time Employees:</strong> ' + $BilledUsersPTTotal + '
							</p>';
			} else {
				$EmailSubject = "Bill Needs Updating for $OrgFullName"
				$EmailIntro = "The User Audit for $OrgFullName was updated and changes were found. Please update this organizations contract."
				$BilledUsersFTChange = ($TotalChanges | Select-Object -Last 1)."Billed FT"
				$BilledUsersPTChange = ($TotalChanges | Select-Object -Last 1)."Billed PT"
				$BilledUsersFTTotal = (($Totals | Where-Object { $_.Type -notlike "*Part Time*" }).Billed | Measure-Object -Sum).Sum
				$BilledUsersPTTotal = (($Totals | Where-Object { $_.Type -like "*Part Time*" }).Billed | Measure-Object -Sum).Sum
				$EmailTitle = "Changes"
				$HTMLBody = '<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								<strong>Full Time Employees Change:</strong> ' + $BilledUsersFTChange.ToString("+#;-#;0") + '<br />
								<strong>Part Time Employees Change:</strong> ' + $BilledUsersPTChange.ToString("+#;-#;0") + '
							</p><br />'
				$HTMLBody += '<p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>New Totals</strong></p>'
				$HTMLBody += '<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">
								<strong>New Full Time Employees Total:</strong> ' + $BilledUsersFTTotal + '<br />
								<strong>New Part Time Employees Total:</strong> ' + $BilledUsersPTTotal + '
							</p>'
			}
			
			if ($TotalsByLocation -and $HasMultipleLocations) {
				$HTMLBody += "<br />"
				$HTMLBody += '<p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>Totals by Location</strong></p>'
				$HTMLBody += '<p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">'
		
				$TotalsByLoc | Foreach-Object {
					$HTMLBody += "<strong>$($_.Location):</strong> $($_.Billed) <br />"
				}
				$HTMLBody += "</p>"
			}

			$HTMLEmail = $EmailTemplate -f `
							$EmailIntro, 
							$EmailTitle, 
							$HTMLBody, 
							"Attached is the full user audit for this organization."

			# Get this months user audit report that was generated earlier in this script to attach to the email
			$MonthName = (Get-Culture).DateTimeFormat.GetMonthName([int](Get-Date -Format MM))
			$Year = Get-Date -Format yyyy
			$FileName = "$($OrgShortName)--Billed_User_List--$($MonthName)_$Year.xlsx"
			$Path = $PSScriptRoot + "\$FileName"
			$ReportEncoded = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))

			# Send email
			$mailbody = @{
				"From" = $EmailFrom
				"To" = $EmailTo_BillingUpdate
				"Subject" = $EmailSubject
				"HTMLContent" = $HTMLEmail
				"Attachments" = @(
					@{
						Base64Content = $ReportEncoded
						Filename = $FileName
						ContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
					}
				)
			} | ConvertTo-Json -Depth 6

			$headers = @{
				'x-api-key' = $Email_APIKey
			}
			
			Invoke-RestMethod -Method Post -Uri $Email_APIEndpoint -Body $mailbody -Headers $headers -ContentType application/json
			Write-Host "Email Sent" -ForegroundColor Green
			Write-PSFMessage -Level Verbose -Message "Billing update email sent. Subject: $Subject"
			$UserBillingUpdateRan = $true
		} else {
			$UserBillingUpdateRan = $true
		}
		
	} else {
		Write-Host "Something went wrong when trying to find the $FlexAssetName asset type. Could not update IT Glue." -ForegroundColor Red
		Write-PSFMessage -Level Warning -Message "Error. Could not get ID of asset type: $FlexAssetName"
	}

	Write-Host "Billing Update Complete!" -ForegroundColor Black -BackgroundColor Green
	Write-PSFMessage -Level Verbose -Message "Billing Update Complete."
}

#  Export an Office 365 license report
if ($CheckEmail -and $EmailType -eq "O365") {
	Write-Host "Exporting Office 365 license report..."
	Write-PSFMessage -Level Verbose -Message "Exporting Office 365 License Report."
	$LicensePlanList = Get-AzureADSubscribedSku
	$AzureUsers = Get-AzureADUser -All $true | Select-Object UserPrincipalName, AssignedLicenses, DisplayName, GivenName, Surname

	$LicenseList = @()
	$AzureUsers | ForEach-Object {
		$LicenseSkus = $_.AssignedLicenses | Select-Object SkuId
		$Licenses = @()
		$LicenseSkus | ForEach-Object {
			$sku = $_.SkuId
			foreach ($license in $licensePlanList) {
				if ($sku -eq $license.ObjectId.substring($license.ObjectId.length - 36, 36)) {
					$Licenses += $license.SkuPartNumber
					break
				}
			}
		}

		$UserInfo = [pscustomobject]@{
			Name = $_.DisplayName
			Email = $_.UserPrincipalName
			PrimaryLicense = ""
			AssignedLicenses = $Licenses | ForEach-Object { if ($_ -in $O365LicenseTypes.Keys) { $O365LicenseTypes[$_] } else { $_ }  }
		}

		foreach ($LicenseSku in $O365LicenseTypes.Keys) {
			if ($LicenseSku -in $Licenses) {
				$UserInfo.PrimaryLicense = $O365LicenseTypes[$LicenseSku]
				break
			}
		}

		$LicenseList += $UserInfo
	}

	# Create a custom overview document (or update it)
	$LicenseList_FlexAssetBody =
	@{
		type       = 'flexible-assets'
		attributes = @{
			traits = @{
				'name' = "Office 365 License Overview"
				'overview' = ""
			}
		}
	}

	$LicenseListHTML = ($LicenseList | Where-Object { $_.PrimaryLicense } | Select-Object -Property Name, Email, PrimaryLicense -First 600 | convertto-html -Fragment | Out-String)
	if (($LicenseList | Where-Object { $_.PrimaryLicense } | Measure-Object).Count -gt 600) {
		$LicenseList_FlexAssetBody.attributes.traits.overview = "<p>This list has been truncated due to its size. Please see the attached excel document for the full list.</p>"
	} else {
		$LicenseList_FlexAssetBody.attributes.traits.overview = "<p>This list only includes primary licenses. Please see the attached excel document for the full list.</p>"
	}
	$LicenseList_FlexAssetBody.attributes.traits.overview += $LicenseListHTML

	$ExistingLicenseOverview = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $CustomOverview_FlexAssetID -filter_organization_id $orgID -include attachments
	$ExistingLicenseOverview.data = $ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview" }  | Select-Object -First 1

	if (!$ExistingLicenseOverview.data) {
		$LicenseList_FlexAssetBody.attributes.add('organization-id', $orgID)
		$LicenseList_FlexAssetBody.attributes.add('flexible-asset-type-id', $CustomOverview_FlexAssetID)
		$ExistingLicenseOverview = New-ITGlueFlexibleAssets -data $LicenseList_FlexAssetBody
		Write-Host "Created a new O365 License Overview."

		# relate to the billing overview page
		if ($ExistingFlexAsset) {
			$RelatedItems = @{
				type = 'related_items'
				attributes = @{
					destination_id = $ExistingFlexAsset.data.id
					destination_type = "Flexible Asset"
				}
			}
			New-ITGlueRelatedItems -resource_type flexible_assets -resource_id $ExistingLicenseOverview.data.id -data $RelatedItems | Out-Null
		}

		# and email Office 365 page too if it exists
		$EmailFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name "Email").data
		$EmailOverview = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $EmailFilterID.id -filter_organization_id $orgID
		$EmailOverview.data = $EmailOverview.data | Where-Object { $_.attributes.name -eq "Office 365" }  | Select-Object -First 1
		if ($EmailOverview) {
			$RelatedItems = @{
				type = 'related_items'
				attributes = @{
					destination_id = $EmailOverview.data.id
					destination_type = "Flexible Asset"
				}
			}
			New-ITGlueRelatedItems -resource_type flexible_assets -resource_id $ExistingLicenseOverview.data.id -data $RelatedItems | Out-Null
		}
	} else {
		Set-ITGlueFlexibleAssets -id $ExistingLicenseOverview.data.id -data $LicenseList_FlexAssetBody | Out-Null
		Write-Host "Updated the O365 License Overview."
	}

	# Create the excel document
	$MonthName = (Get-Culture).DateTimeFormat.GetMonthName([int](Get-Date -Format MM))
	$Year = Get-Date -Format yyyy
	$FileName = "$($OrgShortName)--O365_License_Overview--$($MonthName)_$Year.xlsx"
	New-Item -ItemType Directory -Force -Path ($PSScriptRoot + "\O365LicenseOverview") | Out-Null
	$Path = $PSScriptRoot + "\O365LicenseOverview\$FileName"
	Remove-Item $Path -ErrorAction SilentlyContinue

	$LicenseList | Where-Object { $_.AssignedLicenses } | Select-Object -Property Name, Email, PrimaryLicense, @{Name="AssignedLicenses"; E={$_.AssignedLicenses -join ", "}} | Export-Excel $Path -AutoFilter -AutoSize -AutoNameRange -TableStyle "Medium2"
	$ReportEncoded = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))

	# Attach the excel doc to the custom overview (delete first if necessary)
	if ($ExistingLicenseOverview -and $ExistingLicenseOverview.data.id -and $ExistingLicenseOverview.included) {
		$Attachments = $ExistingLicenseOverview.included | Where-Object {$_.type -eq 'attachments'}
		if ($Attachments -and ($Attachments | Measure-Object).Count -gt 0 -and $Attachments.attributes) {
			$MonthsAttachment = $Attachments.attributes | Where-Object { $_.name -like $FileName + '*' -or $_."attachment-file-name" -like $FileName + '*' }
			if ($MonthsAttachment) {
				$data = @{ 
					'type' = 'attachments'
					'attributes' = @{
						'id' = $MonthsAttachment.id
					}
				}
				Remove-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingLicenseOverview.data.id -data $data | Out-Null
			}
		}
	}

	if ($ExistingLicenseOverview -and $ExistingLicenseOverview.data.id) {
		$data = @{ 
			'type' = 'attachments'
			'attributes' = @{
				'attachment' = @{
					'content' = $ReportEncoded
					'file_name'	= $FileName
				}
			}
		}
		New-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingLicenseOverview.data.id -data $data | Out-Null
		Write-Host "O365 license overview xls uploaded and attached." -ForegroundColor Green
		Write-PSFMessage -Level Verbose -Message "Office 365 License Report Export Complete."
		$UserO365ReportUpdated = $true
	}
}

# Update / Create the "Scripts - Last Run" ITG page which shows when the user audit (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID) {
	if ($ScriptsLast_FlexAssetID) {
		$LastUpdatedPage = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $ScriptsLast_FlexAssetID -filter_organization_id $orgID
		if (!$LastUpdatedPage -or !$LastUpdatedPage.data) {
			# Upload new to ITG
			$FlexAssetBody = 
			@{
				type = 'flexible-assets'
				attributes = @{
					'organization-id' = $orgID
					'flexible-asset-type-id' = $ScriptsLast_FlexAssetID
					traits = @{
						"name" = "Scripts - Last Run"
						"current-version" = "N/A"
					}
				}
			}
			$LastUpdatedPage = New-ITGlueFlexibleAssets -data $FlexAssetBody
			Write-Host "Created a new 'Scripts - Last Run' page."
		}
	}

	# Update asset with last run times for the user audit
	$Headers = @{
        "x-api-key" = $APIKEy
    }
    $Body = @{
        "apiurl" = $APIEndpoint
        "itgOrgID" = $orgID
        "HostDevice" = $env:computername
		"current-version" = "$($CurrentVersion | Out-String)"
    }
	if ($UserCleanupUpdateRan) {
		$Body.Add("contact-audit", (Get-Date).ToString("yyyy-MM-dd"))
	}
	if ($UserBillingUpdateRan) {
		$Body.Add("billing-update-ua", (Get-Date).ToString("yyyy-MM-dd"))
	}
	if ($UserO365ReportUpdated) {
		$Body.Add("o365-license-report", (Get-Date).ToString("yyyy-MM-dd"))
	}

    $Params = @{
        Method = "Post"
        Uri = $LastUpdatedUpdater_APIURL
        Headers = $Headers
        Body = ($Body | ConvertTo-Json)
        ContentType = "application/json"
    }			
    Invoke-RestMethod @Params 
}


# Close email sessions
if ($EmailType -eq "O365") {
	Disconnect-ExchangeOnline -Confirm:$false
	Write-PSFMessage -Level Verbose -Message "Disconnected from O365."
} elseif ($ExchangeServerFQDN) {
	Remove-PSSession $Session
}

Write-Host "Script Completed."
Write-PSFMessage -Level Verbose -Message "Script Complete."