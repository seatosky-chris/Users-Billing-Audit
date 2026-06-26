###
# File: \Initial User Import.ps1
# Project: Users Billing Audit
# Created Date: Tuesday, March 3rd 2026, 9:49:37 am
# Author: Chris Jantzen
# -----
# Last Modified: Thu Mar 12 2026
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2026 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
###

#Requires -RunAsAdministrator
param($config = $false)
Set-ExecutionPolicy Unrestricted
#####################################################################
# Choose what methods you want to use for mapping users to ITG locations.
# You can choose multiple, order them by preference. If a field is not set, it will fall back to the next preference.
# 1 = AD OU, 2 = AD/Azure Department field, 3 = AD/Azure Office field
$MapITGLocationsPreference = @(3, 2, 1)

$Municipality = $true # Set to true if we should watch for Councillors

$IgnoreLastLogonDate = $false # Set to true if you want to ignore the last login date when determining if a contact is email only. This useful when a customer has Exchange as it updates this even when a user isn't logging into a device.

# Map each contact type to either the Contact Type Name from ITG or the Contact Type ID (no quotes if this is an ID)
$ContactTypeMapping = @{
	"ToTerminated" = 72304
	"ToEmailOnly" = 117960
	"ToContractor" = 115246
	"ToTemporary" = 118828
	"ToVendor" = 113769
	"ToEmployee" = 31990
	"ToSharedMailbox" = 117553
	"ToServiceAccount" = 121780
	"ToSharedAccount" = 121868
}

. "$PSScriptRoot\O365Licenses.ps1"
#####################################################################
Write-Host "Starting user import..."

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

If (Get-Module -ListAvailable -Name "ITGlueAPI") {
	Import-module ITGlueAPI
} Else { 
	try {
		Install-Module -Name ITGlueAPI
	} catch {
		[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
		Import-Module PowerShellGet 
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
		Register-PSRepository -Default
		Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		Install-Module -Name ITGlueAPI
	}
	import-module ITGlueAPI
}

# Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy
Export-ITGlueModuleSettings

# This line allows popup boxes to work
Add-Type -AssemblyName PresentationFramework

Write-Host "Successfully imported required modules and configured the ITGlue API."

if (($CheckEmail -and $EmailType -eq "O365") -or ($CheckAD -and $ADType -eq "Azure")) {
	Write-Host "Connecting to Microsoft Graph (Azure)..."
	
	$Version = (Get-Module -ListAvailable -Name "Microsoft.Graph.Users" | Sort-Object Version -Descending | Select-Object -First 1).Version
	if ($Version.Major -lt 2 -or $Version.Minor -lt 8) {
		Remove-Module Microsoft.Graph.Users
		Uninstall-Module Microsoft.Graph.Users
		Install-Module -Name Microsoft.Graph.Users
		Import-Module Microsoft.Graph.Users -Force
	}

	$GraphModules = (Get-Module -ListAvailable).Name | Where-Object { $_ -like "Microsoft.Graph*" }
	If ("Microsoft.Graph" -in $GraphModules -or ("Microsoft.Graph.Users" -in $GraphModules -and "Microsoft.Graph.Identity.SignIns" -in $GraphModules -and "Microsoft.Graph.Identity.DirectoryManagement" -in $GraphModules)) {
		Import-Module Microsoft.Graph.Users
		Import-Module Microsoft.Graph.Identity.DirectoryManagement
	} else {
		Install-Module -Name Microsoft.Graph.Authentication
		Install-Module -Name Microsoft.Graph.Users
		Install-Module Microsoft.Graph.Identity.DirectoryManagement
	}

	# Connect to Microsoft Graph (for Azure)
	if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
		Connect-MgGraph -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -ClientID $O365UnattendedLogin.AppID -TenantId $O365UnattendedLogin.TenantId -NoWelcome
	} else {
		Connect-MgGraph
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
	} else {
		If (Get-Module -ListAvailable -Name "CredentialManager") {
			Import-Module CredentialManager
		} else {
			Install-Module -Name CredentialManager
		}
		if ($ExchangeServerFQDN) {
			Write-Host "Connecting to exchange server..."
			$Credential = Get-StoredCredential -Target 'ExchangeServer'
			if (!$Credential) {
				New-StoredCredential -Comment 'Exchange Server Login (for User Audit)' -Persist LOCALMACHINE -Credentials $(Get-Credential -Message "Enter the exchange server login details:") -Target 'ExchangeServer' | Out-Null
				$Credential = Get-StoredCredential -Target 'ExchangeServer'
				Write-Host "Password stored for next time!" -ForegroundColor Green
			}
			$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeServerFQDN/PowerShell/" -Authentication Kerberos -Credential $Credential
			Import-PSSession $Session -DisableNameChecking
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
	Read-Host "Press ENTER to close..." 
	exit
} else {
	$FullContactList = $FullContactList.data
}

# Get the contact types list from IT Glue for later
$FullContactTypes = (Get-ITGlueContactTypes -sort "name").data
$ContactTypes = @()
foreach ($Contact in $FullContactTypes) {
	$ContactTypes += @{
		'id' = $Contact.id
		'name' = $Contact.attributes.name
	}
}

# Get the list of locations for later
$Locations = (Get-ITGlueLocations -org_id $OrgID).data
$Locations.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$Locations | ForEach-Object { $_.attributes.id = $_.id }
$Locations = $Locations.attributes
$HasMultipleLocations = $false
if (($Locations | Measure-Object).Count -gt 1) {
	$HasMultipleLocations = $true
}

$ContactCount = ($FullContactList | Measure-Object).Count
Write-Host "Got the contact data from IT Glue. $ContactCount existing contacts were found."

# Get the list of contacts that are considered an employee type
$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
$EmployeeContacts = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $EmployeeContactTypes -or !$_."contact-type-name"}

# Duplicate Locations check
Write-Host "Checking for duplicate locations."
$UniqueAddresses = $Locations."address-1" | Select-Object -Unique
$DuplicateAddresses = @()
if ($UniqueAddresses) {
	$DuplicateAddresses = Compare-Object -ReferenceObject $UniqueAddresses -DifferenceObject $Locations."address-1"
}
$DuplicateIDs = @()

foreach ($Address in $DuplicateAddresses.InputObject) {
	# These all have the same address, but lets verify the other fields are the same as well
	$AddressesToCheck = $Locations | Where-Object { $_."address-1" -like $Address }
	foreach ($CheckAddress in $AddressesToCheck) {
		foreach ($CheckAddressCompare in $AddressesToCheck) {
			if ($CheckAddress.id -eq $CheckAddressCompare.id -or $CheckAddress.id -in $DuplicateIDs -or $CheckAddressCompare.id -in $DuplicateIDs) {
				continue
			}
			$C1Att = $CheckAddress
			$C2Att = $CheckAddressCompare
			
			if ($C1Att."address-2" -like $C2Att."address-2" -and $C1Att."city" -like $C2Att."city" -and $C1Att."region-name" -like $C2Att."region-name" -and $C1Att."country-name" -like $C2Att."country-name") {
				$DuplicateIDs += $CheckAddress.id
				$DuplicateIDs += $CheckAddressCompare.id
			}
		}
	}
}
if ($DuplicateIDs) {
	$ShowDuplicates = $false
	$ShowDuplicates = [System.Windows.MessageBox]::Show('Duplicate locations were found in the pre-cleanup check. Would you like to see these duplicates?', 'Duplicate Locations Found', 'YesNo')

	if ($ShowDuplicates -eq 'Yes') {
		$DupeLocationsTable = @()
		foreach ($ID in $DuplicateIDs) {
			$DupeLocationsTable += ($Locations | Where-Object { $_.id -eq $ID }) | 
				Select-Object Name, primary, "address-1", "city", @{Name="Link"; Expression={"https://seatosky.itglue.com/$orgID/locations/$ID"}}, 
					@{Name="Contacts using Location"; E={($FullContactList.attributes | Where-Object {$_."location-id" -eq $ID} | Measure-Object).Count}}
		}
		$DupeLocationsTable | Out-GridView -PassThru -Title "Duplicate Locations"

		# Update locations
		$Locations = (Get-ITGlueLocations -org_id $OrgID).data
		$Locations.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
		$Locations | ForEach-Object { $_.attributes.id = $_.id }
		$Locations = $Locations.attributes
		$HasMultipleLocations = $false
		if (($Locations | Measure-Object).Count -gt 1) {
			$HasMultipleLocations = $true
		}
	}
}

### Build the Multiple Matches Found form
# Generates a form to allow a user to choose a match when multiple are found
# @param str $Type 'O365' or 'AD'
# @param obj $Contact the IT Glue contact object
# @param arr $FoundMatches an array of found matches (either $ITGADMatches or $ITGO365Matches)
# @return arr an array with a single match (the one chosen in the form)
function MultipleMatchesForm {
	param(
		[string]$Type, 
		[psObject]$Contact, 
		[array]$FoundMatches
	)

	if (@('AD', 'O365') -notcontains $Type) {
		Write-Host 'The wrong $Type was fed to the MultipleMatchesForm function. Type: ' + $Type
		return
	}

	$NewMatch = @()

	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.Application]::EnableVisualStyles()

	$MultipleChoiceForm              = New-Object system.Windows.Forms.Form
	$MultipleChoiceForm.ClientSize   = New-Object System.Drawing.Point(800,404)
	$MultipleChoiceForm.text         = "Multiple Matches Found"
	$MultipleChoiceForm.TopMost      = $false

	$Label1                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'AD') {
		$Label1.text                     = "Multiple AD matches were found for this user:"
	} else {
		$Label1.text                     = "Multiple O365 matches were found for this user:"
	}
	$Label1.AutoSize                 = $true
	$Label1.width                    = 25
	$Label1.height                   = 10
	$Label1.location                 = New-Object System.Drawing.Point(6,10)
	$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label2                          = New-Object system.Windows.Forms.Label
	$Label2.text                     = "User:"
	$Label2.AutoSize                 = $true
	$Label2.width                    = 25
	$Label2.height                   = 10
	$Label2.location                 = New-Object System.Drawing.Point(11,32)
	$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

	$userNameLbl                     = New-Object system.Windows.Forms.Label
	$userNameLbl.text                = ""
	$userNameLbl.AutoSize            = $true
	$userNameLbl.width               = 25
	$userNameLbl.height              = 10
	$userNameLbl.location            = New-Object System.Drawing.Point(52,32)
	$userNameLbl.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
	$userNameLbl.ForeColor           = [System.Drawing.ColorTranslator]::FromHtml("#ff0000")

	$Label7                          = New-Object system.Windows.Forms.Label
	$Label7.text                     = "Title/Loc:"
	$Label7.AutoSize                 = $true
	$Label7.width                    = 25
	$Label7.height                   = 10
	$Label7.location                 = New-Object System.Drawing.Point(223,32)
	$Label7.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

	$userTitleLocLbl                 = New-Object system.Windows.Forms.Label
	$userTitleLocLbl.text            = ""
	$userTitleLocLbl.AutoSize        = $true
	$userTitleLocLbl.width           = 25
	$userTitleLocLbl.height          = 10
	$userTitleLocLbl.location        = New-Object System.Drawing.Point(286,32)
	$userTitleLocLbl.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label4                          = New-Object system.Windows.Forms.Label
	$Label4.text                     = "Type:"
	$Label4.AutoSize                 = $true
	$Label4.width                    = 25
	$Label4.height                   = 10
	$Label4.location                 = New-Object System.Drawing.Point(11,54)
	$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

	$userTypeLbl                     = New-Object system.Windows.Forms.Label
	$userTypeLbl.text                = ""
	$userTypeLbl.AutoSize            = $true
	$userTypeLbl.width               = 25
	$userTypeLbl.height              = 10
	$userTypeLbl.location            = New-Object System.Drawing.Point(52,54)
	$userTypeLbl.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label3                          = New-Object system.Windows.Forms.Label
	$Label3.text                     = "Primary Email: "
	$Label3.AutoSize                 = $true
	$Label3.width                    = 25
	$Label3.height                   = 10
	$Label3.location                 = New-Object System.Drawing.Point(223,54)
	$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

	$userPrimEmailLbl                = New-Object system.Windows.Forms.Label
	$userPrimEmailLbl.text           = ""
	$userPrimEmailLbl.AutoSize       = $true
	$userPrimEmailLbl.width          = 25
	$userPrimEmailLbl.height         = 10
	$userPrimEmailLbl.location       = New-Object System.Drawing.Point(320,54)
	$userPrimEmailLbl.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label5                          = New-Object system.Windows.Forms.Label
	$Label5.text                     = "Other Emails:"
	$Label5.AutoSize                 = $true
	$Label5.width                    = 25
	$Label5.height                   = 10
	$Label5.location                 = New-Object System.Drawing.Point(11,76)
	$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

	$userEmailsLbl                   = New-Object system.Windows.Forms.TextBox
	$userEmailsLbl.multiline         = $false
	$userEmailsLbl.text              = ""
	$userEmailsLbl.width             = 556
	$userEmailsLbl.height            = 20
	$userEmailsLbl.location          = New-Object System.Drawing.Point(102,74)
	$userEmailsLbl.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label6                          = New-Object system.Windows.Forms.Label
	$Label6.text                     = "Please choose the primary email account:"
	$Label6.AutoSize                 = $true
	$Label6.width                    = 25
	$Label6.height                   = 10
	$Label6.location                 = New-Object System.Drawing.Point(7,104)
	$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$MatchesGrid                     = New-Object system.Windows.Forms.DataGridView
	$MatchesGrid.width               = 773
	$MatchesGrid.height              = 196
	$MatchesGrid.SelectionMode 		 = 'FullRowSelect'
	$MatchesGrid.Anchor              = 'top,right,bottom,left'
	$MatchesGrid.location            = New-Object System.Drawing.Point(9,149)

	$ignoreContact                   = New-Object system.Windows.Forms.Button
	$ignoreContact.text              = "Ignore Contact. No Match."
	$ignoreContact.width             = 180
	$ignoreContact.height            = 30
	$ignoreContact.location          = New-Object System.Drawing.Point(442,6)
	$ignoreContact.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$setPrimary                      = New-Object system.Windows.Forms.Button
	if ($Type -eq 'AD') {
		$setPrimary.text                 = "Set Primary Account."
	} else {
		$setPrimary.text                 = "Set Primary Email."
	}
	$setPrimary.width                = 145
	$setPrimary.height               = 30
	$setPrimary.location             = New-Object System.Drawing.Point(630,6)
	$setPrimary.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$itGlueUserGroupbox              = New-Object system.Windows.Forms.Groupbox
	$itGlueUserGroupbox.height       = 129
	$itGlueUserGroupbox.width        = 775
	$itGlueUserGroupbox.location     = New-Object System.Drawing.Point(8,9)

	$buttonsGroupbox                 = New-Object system.Windows.Forms.Groupbox
	$buttonsGroupbox.height          = 44
	$buttonsGroupbox.width           = 782
	$buttonsGroupbox.Anchor          = 'right,bottom'
	$buttonsGroupbox.location        = New-Object System.Drawing.Point(10,352)

	$itGlueUserGroupbox.controls.AddRange(@($Label1,$Label2,$userNameLbl,$Label4,$userTypeLbl,$Label3,$userPrimEmailLbl,$Label5,$userEmailsLbl,$Label6,$userTitleLocLbl,$Label7))
	$MultipleChoiceForm.controls.AddRange(@($MatchesGrid,$itGlueUserGroupbox,$buttonsGroupbox))
	$buttonsGroupbox.controls.AddRange(@($ignoreContact,$setPrimary))

	# Fill in IT Glue user information
	$userNameLbl.text = $Contact.Name
	$TitleLoc = ''
	if ($Contact.title) {
		$TitleLoc += $Contact.title + " / "
	}
	if ($Contact."location-name") {
		$TitleLoc += $Contact."location-name"
	}
	$userTitleLocLbl.text = $TitleLoc
	$userTypeLbl.text = $Contact."contact-type-name"
	$userPrimEmailLbl.text = ($Contact."contact-emails" | Where-Object { $_.primary }).value
	$userEmailsLbl.text = ($Contact."contact-emails" | Where-Object { !$_.primary }).value -join ', '

	# Fill in the Matches Grid with each found match
	if ($Type -eq 'AD') {
		# AD
		$MatchesGrid.ColumnCount = 7
		$MatchesGrid.ColumnHeadersVisible = $true
		$MatchesGrid.Columns[0].Name = "ID"
		$MatchesGrid.Columns[0].Visible = $false
		$MatchesGrid.Columns[1].Name = "Name"
		$MatchesGrid.Columns[2].Name = "Username"
		$MatchesGrid.Columns[3].Name = "Email"
		$MatchesGrid.Columns[4].Name = "OU"
		$MatchesGrid.Columns[5].Name = "Enabled?"
		$MatchesGrid.Columns[6].Name = "Description"

		$i = 0
		foreach ($Match in $FoundMatches) {
			$Row = @('', '', '', '', '', '', '')
			$PrimaryOUCN = $Match.PrimaryOU
			if (!$PrimaryOUCN) {
				$PrimaryOUCN = $Match.PrimaryCN
			}
			$Row[0] = $i
			$Row[1] = $Match.Name
			$Row[2] = $Match.Username
			$Row[3] = $Match.EmailAddress
			$Row[4] = $PrimaryOUCN
			$Row[5] = !$Match.AccountDisabled
			$Row[6] = $Match.Description
			$MatchesGrid.Rows.Add($Row) | Out-Null
			$i += 1
		}
	} else {
		# O365
		$MatchesGrid.ColumnCount = 7
		$MatchesGrid.ColumnHeadersVisible = $true
		$MatchesGrid.Columns[0].Name = "ID"
		$MatchesGrid.Columns[0].Visible = $false
		$MatchesGrid.Columns[1].Name = "Display Name"
		$MatchesGrid.Columns[2].Name = "First / Last Name"
		$MatchesGrid.Columns[3].Name = "Primary Email"
		$MatchesGrid.Columns[4].Name = "Emails"
		$MatchesGrid.Columns[5].Name = "Account Type"
		$MatchesGrid.Columns[6].Name = "Enabled?"

		$i = 0
		foreach ($Match in $FoundMatches) {
			$Row = @('', '', '', '', '', '', '')
			$Row[0] = $i
			$Row[1] = $Match.DisplayName
			$Row[2] = $Match.FirstName + " " + $Match.LastName
			$Row[3] = $Match.PrimarySmtpAddress
			$Row[4] = $Match.EmailAddresses -join ", "
			$Row[5] = $Match.RecipientTypeDetails
			$Row[6] = !$Match.AccountDisabled
			$MatchesGrid.Rows.Add($Row) | Out-Null
			$i += 1
		}
	}

	# ON ignore button
	$ignoreContact.Add_Click({
		Set-Variable -scope 1 -Name "NewMatch" -Value @()
		[void]$MultipleChoiceForm.Close()
	})

	# ON set primary button
	$setPrimary.Add_Click({
		$SelectedID = $false
		if ($MatchesGrid.CurrentRow) {
			$SelectedID = $MatchesGrid.CurrentRow.Cells['ID'].Value
		}
		if ($SelectedID -is [int] -and $SelectedID -ge 0) {
			Set-Variable -scope 1 -Name "NewMatch" -Value $FoundMatches[$SelectedID]
			[void]$MultipleChoiceForm.Close()
		} else {
			[System.Windows.MessageBox]::Show('Something went wrong trying to save the match.')
		}
	})

	# Show form
	[void]$MultipleChoiceForm.ShowDialog()

	# Return the new match
	$NewMatch
	return
}

# Get AD/Azure users
if ($CheckAD) {
	# Get all AD users
	Write-Host "===================================" -ForegroundColor Blue
	Write-Host "Getting AD users for comparison."

	if ($ADType -eq "Azure") {
		## Azure
		$FullADUsers = Get-MgUser -All -Property Id, DisplayName, GivenName, Surname, UserPrincipalName, AccountEnabled, CreatedDateTime, SignInActivity, City, Department, OfficeLocation, JobTitle, Mail, MailNickname, UserType, AssignedLicenses, BusinessPhones, MobilePhone, FaxNumber | Select-Object Id, DisplayName, GivenName, Surname, UserPrincipalName, AccountEnabled, CreatedDateTime, SignInActivity, City, Department, OfficeLocation, JobTitle, Mail, MailNickname, UserType, AssignedLicenses, BusinessPhones, MobilePhone, FaxNumber

		$FullADUsers = $FullADUsers | 
							Select-Object -Property Id, DisplayName, @{Name="Name"; E={$_.DisplayName}}, GivenName, Surname, UserPrincipalName, @{Name="Username"; E={$_.UserPrincipalName}}, 
								@{Name="EmailAddress"; E={$_.mail}}, @{Name="Enabled"; E={$_.AccountEnabled}}, @{Name="Created"; E={$_.CreatedDateTime}}, @{Name="Description"; E={""}}, SignInActivity,
								City, Department, @{Name="Office"; E={$_.OfficeLocation}}, @{Name="Division"; E={""}}, @{Name="Title"; E={$_.JobTitle}}, MailNickname, UserType, AssignedLicenses, BusinessPhones, MobilePhone, @{Name="Fax"; E={$_.FaxNumber}}
		$FullADUsers = $FullADUsers | Where-Object  { $_.UserType -eq "Member" }

		Write-Host "Got AD accounts. Getting associated AD group memberships."
		$i = 0
		$ADUserCount = ($FullADUsers | Measure-Object).Count
		$FullADUsers | ForEach-Object {
			$i++
			$_ | Add-Member -MemberType NoteProperty -Name Groups -Value $null
			$_ | Add-Member -MemberType NoteProperty -Name LastLogonDate -Value $null
			$_ | Add-Member -MemberType NoteProperty -Name UsernameStart -Value $null
			$_.Groups = @((Get-MgUserMemberOf -UserId $_.Id -All).AdditionalProperties.displayName)
			$_.LastLogonDate = if($_.signInActivity.lastSuccessfulSignInDateTime) { [DateTime]$_.signInActivity.lastSuccessfulSignInDateTime } elseif ($_.signInActivity.lastSignInDateTime) { [DateTime]$_.signInActivity.lastSignInDateTime } else {$null}
			$pos = $_.Username.IndexOf("@")
			$_.UsernameStart = $_.Username.Substring(0, $pos)
			[int]$PercentComplete = ($i / $ADUserCount * 100)
			Write-Progress -Activity "Getting AD Group Memberships" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%")
		}
		Write-Progress -Activity "Getting AD Group Memberships" -Status "Ready" -Completed

		$ADEmployees = $FullADUsers
	} else {
		## On-Premise AD
		$FullADUsers = Get-ADUser -Filter * -Properties * | 
							Select-Object -Property Name, DisplayName, GivenName, Surname, UserPrincipalName, @{Name="Username"; E={$_.SamAccountName}}, EmailAddress, Enabled, 
											Description, LastLogonDate, Created, @{Name="PrimaryOU"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)')[0].Groups[2]}}, 
											@{Name="OUs"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)').Value -replace 'OU='}}, 
											@{Name="PrimaryCN"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)')[0].Groups[2]}}, 
											@{Name="CNs"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)').Value -replace 'CN='}}, 
											City, Department, Office, Division, Title, ObjectGUID, OfficePhone, MobilePhone, HomePhone, ipPhone, Fax, DistinguishedName
		Write-Host "Got AD accounts. Getting associated AD group memberships."
		$i = 0
		$ADUserCount = ($FullADUsers | Measure-Object).Count
		$FullADUsers | ForEach-Object {
			$i++
			$_ | Add-Member -MemberType NoteProperty -Name Groups -Value $null
			$ADGroups = Get-ADPrincipalGroupMembership $_.Username
			$ADGroups = $ADGroups | Where-Object { $_.GroupCategory -ne "Distribution"}
			if ($ADGroups -and $EmailOnlyGroupsOUIgnore) {
				foreach ($IgnoreOU in $EmailOnlyGroupsOUIgnore) {
					$ADGroups = $ADGroups | Where-Object { $_.distinguishedName -notlike "*OU=$($IgnoreOU),*" }
				}
			}
			$_.Groups = @(($ADGroups | Select-Object Name).Name)
			[int]$PercentComplete = ($i / $ADUserCount * 100)
			Write-Progress -Activity "Getting AD Group Memberships" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%")
		}
		Write-Progress -Activity "Getting AD Group Memberships" -Status "Ready" -Completed
		
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


	$ITGADMatches = New-Object -TypeName "System.Collections.ArrayList"
	$ITGADNoMatch = @()
	$ITGADNoMatchButIgnore = @() # For IT Glue contacts without an AD account
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
			$ITGADNoMatchButIgnore += $User
			continue
		}
		
		# Look for a match
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
				$ADMatch = MultipleMatchesForm 'AD' $User $ADMatch
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
			$ITGADMatches.Add($match) | Out-Null
		} else {
			if ($Type -ne 'Terminated' -and $Type -ne 'Employee - Email Only' -and $Type -ne 'Employee - On Leave') {
				$ITGADNoMatch += $User
			}
		}
	}
	$ADMatchCount = ($ITGADMatches | Measure-Object).Count
	Write-Host "Finished matching all existing IT Glue contacts to their AD accounts. $ADMatchCount matches were made."

	$UnmatchedAD = $ADEmployees | Where-Object { $ITGADMatches.ad.Username -notcontains $_.Username } | Where-Object { $_.Enabled -eq "True" } | Sort-Object -Property @{ Expression = "LastLogonDate"; Descending = $true }, @{ Expression = "Name" }
	Write-Host "$(($UnmatchedAD | Measure-Object).Count) AD accounts found without a match."
}

# Generates a form to allow matching of displayed contacts that a match couldn't be found for
# @param str $Type 'O365', 'AD' or, 'ChangeMatches'
# Accesses outside variables directly rather than passing them in and out
function NoMatchForm {
	param([string]$Type)

	if (@('AD', 'O365', 'ChangeMatches') -notcontains $Type) {
		Write-Host 'The wrong $Type was fed to the NoMatchForm function. Type: ' + $Type
		return
	}

	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.Application]::EnableVisualStyles()

	$ShortName = ''
	$LongName = ''
	if ($Type -eq 'AD') {
		$ShortName = 'AD'
		$LongName = 'Active Directory'
	} else {
		$ShortName = 'O365'
		$LongName = "Office 365"
	}

	# Function to show the updated label
	# You must provide the label as a parameter
	function showUpdatedLabel {
		param ($Label)
		$UpdatedLbl.Visible = $true
		if ($null -ne $global:timer) {
			$global:timer.Stop()
			$global:timer = $null
		}
		$global:timer = New-Object System.Windows.Forms.Timer
		$global:timer.Interval = 1000 # milliseconds
		$global:timer.add_Tick({
			$UpdatedLbl.Visible = $false
			$global:timer.Stop()
			$global:timer = $null
		})
		$global:timer.Start()
	}

	$NoMatchForm                     = New-Object system.Windows.Forms.Form
	if ($Type -ne 'ChangeMatches') {
		$NoMatchForm.ClientSize          = New-Object System.Drawing.Point(800,600)
		$NoMatchForm.text			 	 = "Some $ShortName Matches Not Found"
	} else {
		$NoMatchForm.ClientSize          = New-Object System.Drawing.Point(800,650)
		$NoMatchForm.text			 	 = "Manually fix these found matches"
	}
	$NoMatchForm.TopMost             = $false

	$Label1                          = New-Object system.Windows.Forms.Label
	if ($Type -ne 'ChangeMatches') {
		$Label1.text                     = "No $LongName matches were found for the following contacts:"
	} else {
		$Label1.text                     = "Manually fix the following matched contacts:"
	}
	$Label1.AutoSize                 = $true
	$Label1.width                    = 25
	$Label1.height                   = 10
	$Label1.location                 = New-Object System.Drawing.Point(22,23)
	$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label3                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'AD' -or $Type -eq 'ChangeMatches') {
		$Label3.text                     = "- If not a billed employee, change the contact type to 1 of these: "
	} else {
		$Label3.text                     = "- If the contact has an associated email, add it to the IT Glue contact. (preferred)"
	}
	$Label3.AutoSize                 = $true
	$Label3.width                    = 25
	$Label3.height                   = 10
	$Label3.location                 = New-Object System.Drawing.Point(18,22)
	$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$contactTypesList              	 = New-Object system.Windows.Forms.ListBox
	$contactTypesList.text         	 = "listBox"
	$contactTypesList.width        	 = 140
	$contactTypesList.height       	 = 40
	$contactTypesList.location     	 = New-Object System.Drawing.Point(420,16)
	foreach ($CType in $script:ContactTypes) {
		if ($script:EmployeeContactTypes -contains $CType.name -and $CType.name -notlike 'Email Only') { continue }
		$contactTypesList.Items.Add($CType.name) | Out-Null
	}

	$Label4                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'AD') {
		$Label4.text                     = "- If is a billed employee, add a note to the contact in IT Glue like `"Username: AD Username here`"."
	} elseif ($Type -eq 'O365') {
		$Label4.text                     = "- Use the 'Quick Fix' form to associate the contact with a specific O365 email account. This only modifies the contact notes."
	} else {
		$Label4.text                     = "- To change the AD match, use the form to associate the contact with a different AD username."
	}
	$Label4.AutoSize                 = $true
	$Label4.width                    = 25
	$Label4.height                   = 10
	$Label4.location                 = New-Object System.Drawing.Point(18,48)
	$Label4.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label42                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'AD') {
		$Label42.text                     = "- For the second, select a row then use the below 'Quick Fix' form to easily make these changes."
	} elseif ($Type -eq 'O365') {
		$Label42.text                     = "- If this contact has no associated O365 email, click the 'No O365 Account. Ignore.' button."
	} else {
		$Label42.text                     = "- To change the O365 match, use the form to associate the contact with a different O365 email account."
	}
	$Label42.AutoSize                 = $true
	$Label42.width                    = 25
	$Label42.height                   = 10
	$Label42.location                 = New-Object System.Drawing.Point(18,74)
	$Label42.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Groupbox1                       = New-Object system.Windows.Forms.Groupbox
	$Groupbox1.height                = 100
	$Groupbox1.width                 = 768
	$Groupbox1.text                  = "To fix these contacts, either:"
	$Groupbox1.location              = New-Object System.Drawing.Point(18,52)

	$NoMatchesGrid                 = New-Object system.Windows.Forms.DataGridView
	$NoMatchesGrid.width           = 743
	$NoMatchesGrid.height          = 290
	$NoMatchesGrid.AllowUserToAddRows = $false
	$NoMatchesGrid.AllowUserToDeleteRows = $false
	$NoMatchesGrid.AllowUserToOrderColumns = $true
	$NoMatchesGrid.ReadOnly = $true
	$NoMatchesGrid.MultiSelect = $false
	$NoMatchesGrid.ColumnCount = 8
	$NoMatchesGrid.ColumnHeadersVisible = $true
	$NoMatchesGrid.Columns[0].Name = "ID"
	$NoMatchesGrid.Columns[0].Visible = $false
	$NoMatchesGrid.Columns[1].Name = "Name"
	$NoMatchesGrid.Columns[2].Name = "Title"
	$NoMatchesGrid.Columns[3].Name = "Type"
	$NoMatchesGrid.Columns[4].Name = "Location"
	$NoMatchesGrid.Columns[5].Name = "Emails"
	$NoMatchesGrid.Columns[6].Name = "ITGlue URL"
	$NoMatchesGrid.Columns[7].Name = "Notes"

	if ($Type -eq 'AD') {
		$Rows = $script:NoMatch
	} elseif ($Type -eq 'O365') {
		$Rows = $script:NoO365Match
	} else {
		$Rows = $script:ChangeMatches
	}

	foreach ($User in $Rows) {
		$Emails = @()
		foreach ($Email in $User."contact-emails") {
			$Emails += $Email."label-name" + ": " + $Email.value
		}
		$Row = @('', '', '', '', '', '', '', '')
		$Row[0] = $User.ID
		$Row[1] = $User.Name
		$Row[2] = $User.Title
		$Row[3] = $User."contact-type-name"
		$Row[4] = $User."location-name"
		$Row[5] = $Emails -join ','
		$Row[6] = $User."resource-url"
		$Row[7] = $User.notes
		$NoMatchesGrid.Rows.Add($Row) | Out-Null
	}
	$NoMatchesGrid.Anchor          = 'top,right,bottom,left'
	$NoMatchesGrid.location        = New-Object System.Drawing.Point(17,160)

	$FixGroupbox                     = New-Object system.Windows.Forms.Groupbox
	$FixGroupbox.height              = 205
	$FixGroupbox.width               = 750
	$FixGroupbox.Anchor              = 'bottom,left'
	$FixGroupbox.location            = New-Object System.Drawing.Point(17,440)

	$Label5                          = New-Object system.Windows.Forms.Label
	$Label5.text                     = "Quick Fix:"
	$Label5.AutoSize                 = $true
	$Label5.width                    = 25
	$Label5.height                   = 10
	$Label5.location                 = New-Object System.Drawing.Point(17,20)
	$Label5.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Underline))

	$Label52                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'O365') {
		$Label52.text                     = "- It is generally better if you edit the contact directly and add the email rather than use this form"
	} else {
		$Label52.text                     = "- For the O365 match, it is better if you edit the contact directly to add the email rather than use this form"
	}
	$Label52.AutoSize                 = $true
	$Label52.width                    = 25
	$Label52.height                   = 10
	$Label52.location                 = New-Object System.Drawing.Point(95,20)
	$Label52.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label6                          = New-Object system.Windows.Forms.Label
	if ($Type -eq 'AD' -or $Type -eq 'ChangeMatches') {
		$Label6.text                     = "AD Username (to match):"
	} else {
		$Label6.text                     = "O365 Email (to match):"
	}
	$Label6.AutoSize                 = $true
	$Label6.width                    = 25
	$Label6.height                   = 10
	$Label6.location                 = New-Object System.Drawing.Point(17,50)
	$Label6.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label62                          = New-Object system.Windows.Forms.Label
	$Label62.text                     = "O365 Email (to match):"
	$Label62.AutoSize                 = $true
	$Label62.width                    = 25
	$Label62.height                   = 10
	$Label62.location                 = New-Object System.Drawing.Point(17,120)
	$Label62.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$setMatchTxt                 	= New-Object system.Windows.Forms.TextBox
	$setMatchTxt.multiline       	= $false
	$setMatchTxt.width           	= 200
	$setMatchTxt.height          	= 20
	$setMatchTxt.location        	= New-Object System.Drawing.Point(17,75)
	$setMatchTxt.Font            	= New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$setMatchTxt2                 	= New-Object system.Windows.Forms.TextBox
	$setMatchTxt2.multiline       	= $false
	$setMatchTxt2.width           	= 200
	$setMatchTxt2.height          	= 20
	$setMatchTxt2.location        	= New-Object System.Drawing.Point(17,145)
	$setMatchTxt2.Font            	= New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label10                          = New-Object system.Windows.Forms.Label
	$Label10.text                     = "Currently: "
	$Label10.AutoSize                 = $true
	$Label10.width                    = 25
	$Label10.height                   = 10
	$Label10.location                 = New-Object System.Drawing.Point(17,100)
	$Label10.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

	$Label11                          = New-Object system.Windows.Forms.Label
	$Label11.text                     = "Currently: "
	$Label11.AutoSize                 = $true
	$Label11.width                    = 25
	$Label11.height                   = 10
	$Label11.location                 = New-Object System.Drawing.Point(17,170)
	$Label11.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

	$currentADUsername                = New-Object system.Windows.Forms.Label
	$currentADUsername.text           = ""
	$currentADUsername.AutoSize       = $true
	$currentADUsername.width          = 25
	$currentADUsername.height         = 10
	$currentADUsername.location       = New-Object System.Drawing.Point(70,100)
	$currentADUsername.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',8,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))

	$currentO365Email                 = New-Object system.Windows.Forms.Label
	$currentO365Email.text            = ""
	$currentO365Email.AutoSize        = $true
	$currentO365Email.width           = 25
	$currentO365Email.height          = 10
	$currentO365Email.location        = New-Object System.Drawing.Point(70,170)
	$currentO365Email.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',8,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))

	$saveMatchChanges              = New-Object system.Windows.Forms.Button
	$saveMatchChanges.text         = "Save Changes"
	$saveMatchChanges.width        = 106
	$saveMatchChanges.height       = 30
	if ($Type -ne 'ChangeMatches') {
		$saveMatchChanges.location     = New-Object System.Drawing.Point(240,72)
	} else {
		$saveMatchChanges.location     = New-Object System.Drawing.Point(240,140)
	}
	$saveMatchChanges.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$Label9                          = New-Object system.Windows.Forms.Label
	$Label9.text                     = "Currently Editing: "
	$Label9.AutoSize                 = $true
	$Label9.width                    = 25
	$Label9.height                   = 10
	$Label9.location                 = New-Object System.Drawing.Point(17,188)
	$Label9.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

	$currentlyEditingLbl             = New-Object system.Windows.Forms.Label
	$currentlyEditingLbl.text        = ""
	$currentlyEditingLbl.AutoSize    = $true
	$currentlyEditingLbl.width       = 25
	$currentlyEditingLbl.height      = 10
	$currentlyEditingLbl.location    = New-Object System.Drawing.Point(135,188)
	$currentlyEditingLbl.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
	$currentlyEditingLbl.ForeColor   = [System.Drawing.ColorTranslator]::FromHtml("#ff0000")

	$UpdatedLbl                      = New-Object system.Windows.Forms.Label
	$UpdatedLbl.text                 = "Updated!"
	$UpdatedLbl.AutoSize             = $true
	$UpdatedLbl.width                = 25
	$UpdatedLbl.height               = 10
	$UpdatedLbl.location             = New-Object System.Drawing.Point(236,45)
	$UpdatedLbl.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold -bor [System.Drawing.FontStyle]::Italic))
	$UpdatedLbl.ForeColor            = [System.Drawing.ColorTranslator]::FromHtml("#4a90e2")
	$UpdatedLbl.Visible				 = $false

	$updateContactType               = New-Object system.Windows.Forms.Button
	if ($Type -eq 'AD') {
		$updateContactType.text          = "Contact Type Changed. Update."
	} else {
		$updateContactType.text          = "Contact Manually Changed. Update."
	}
	$updateContactType.width         = 209
	$updateContactType.height        = 40
	$updateContactType.location      = New-Object System.Drawing.Point(517,56)
	$updateContactType.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$ignoreContact                   = New-Object system.Windows.Forms.Button
	if ($Type -ne 'ChangeMatches') {
		$ignoreContact.text              = "No $ShortName Account. Ignore."
		$ignoreContact.width             = 159
		$ignoreContact.height            = 40
		$ignoreContact.location          = New-Object System.Drawing.Point(546,103)
	} else {
		$ignoreContact.text              = "No AD Account."
		$ignoreContact.width             = 120
		$ignoreContact.height            = 30
		$ignoreContact.location          = New-Object System.Drawing.Point(497,103)
	}
	$ignoreContact.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$ignoreContact2                   = New-Object system.Windows.Forms.Button
	$ignoreContact2.text              = "No O365 Account."
	$ignoreContact2.width             = 125
	$ignoreContact2.height            = 30
	$ignoreContact2.location          = New-Object System.Drawing.Point(617,103)
	$ignoreContact2.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$doneFixingMatches                   = New-Object system.Windows.Forms.Button
	$doneFixingMatches.text              = "Done Fixing Matches. Continue."
	$doneFixingMatches.width             = 180
	$doneFixingMatches.height            = 40
	$doneFixingMatches.location          = New-Object System.Drawing.Point(532,140)
	$doneFixingMatches.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$NoMatchForm.controls.AddRange(@($Label1,$Groupbox1,$NoMatchesGrid,$FixGroupbox))
	if ($Type -eq 'AD' -or $Type -eq 'ChangeMatches') {
		$Groupbox1.controls.AddRange(@($Label3,$contactTypesList,$Label4,$Label42))
	} else {
		$Groupbox1.controls.AddRange(@($Label3,$Label4,$Label42))
	}
	if ($Type -eq 'AD') {
		$FixGroupbox.controls.AddRange(@($Label5,$Label6,$setMatchTxt,$saveMatchChanges,$Label9,$currentlyEditingLbl,$UpdatedLbl,$updateContactType,$ignoreContact))
	} elseif ($Type -eq 'O365') {
		$FixGroupbox.controls.AddRange(@($Label5,$Label52,$Label6,$setMatchTxt,$saveMatchChanges,$Label9,$currentlyEditingLbl,$UpdatedLbl,$updateContactType,$ignoreContact))
	} else {
		$FixGroupbox.controls.AddRange(@($Label5,$Label52,$Label6,$Label62,$setMatchTxt,$setMatchTxt2,$Label10,$Label11,$currentADUsername,$currentO365Email,$saveMatchChanges,$Label9,$currentlyEditingLbl,$UpdatedLbl,$updateContactType,$ignoreContact,$ignoreContact2,$doneFixingMatches))
	}

	# Row or cell selected, change user being modified and clear form
	$NoMatchesGrid.Add_SelectionChanged({ 
		if ($NoMatchesGrid.CurrentRow) {
			$SelectedName = $NoMatchesGrid.CurrentRow.Cells['Name'].Value
			$SelectedID = $NoMatchesGrid.CurrentRow.Cells['ID'].Value
			$currentlyEditingLbl.text = $SelectedName
		} else {
			$currentlyEditingLbl.text = ''
		}
		$setMatchTxt.Text = ''

		if ($SelectedID -and $Type -eq 'ChangeMatches') {
			$CurUsername = ($script:FullMatches | Where-Object { $_.ID -eq $SelectedID })."AD-Username"
			$CurO365 = ($script:FullMatches | Where-Object { $_.ID -eq $SelectedID })."O365-PrimarySmtp"
			$currentADUsername.text = $CurUsername
			$currentO365Email.text = $CurO365
		}

		# When empty, auto close
		if ($null -eq $NoMatchesGrid -or $NoMatchesGrid.Rows.Count -eq 0) {
			if ($null -ne $global:timer) {
				$global:timer.Stop()
				$global:timer = $null
			}
			[void]$NoMatchForm.Close()
		}
	})

	# Allow url links to be clickable
	$NoMatchesGrid.Add_CellMouseDoubleClick({
		$ColumnIndex = $NoMatchesGrid.CurrentCell.ColumnIndex
		$ColumnValue = $NoMatchesGrid.CurrentCell.Value

		# verify they clicked on a URL, if so, launch it
		if ($ColumnIndex -eq 6 -and ($ColumnValue -as [System.URI]).AbsoluteURI -ne $null) {
			Start-Process $ColumnValue
		}
	})

	# On quick fix save button
	$saveMatchChanges.Add_Click({  
		$SelectedID = 0
		if ($NoMatchesGrid.CurrentRow) {
			$SelectedID = $NoMatchesGrid.CurrentRow.Cells['ID'].Value
		}
		if ($SelectedID -and $SelectedID -ge 0) {
			$SelectedRowID = $NoMatchesGrid.CurrentCell.RowIndex

			# AD 
			if ($Type -eq 'AD') {
				$NewUsername = $setMatchTxt.Text

				if ($NewUsername) {
					if (($script:ADEmployees | Where-Object { $_.Username -like $NewUsername } | Measure-Object).Count -eq 1) {
						# Username was found in AD, update IT Glue notes and move from $ITGADNoMatch to $ITGADMatches
						$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
						$CurrentNotes = $CurrentNotes.TrimEnd()
						$UserUpdate = 
							@{
								type = "contacts"
								attributes = @{
									notes = $CurrentNotes + "`nUsername: " + $NewUsername
								}	
							}
						Set-ITGlueContacts -id $SelectedID -data $UserUpdate

						$ADMatch = $script:ADEmployees | Where-Object { $_.Username -like $NewUsername }
						$ITGlueUser = $script:EmployeeContacts | Where-Object { $_.ID -like $SelectedID }
						$match = [PSCustomObject]@{
							id = $SelectedID
							name = $ITGlueUser.Name
							type = $ITGlueUser."contact-type-name"
							itglue = $ITGlueUser
							ad = $ADMatch
						}
						$script:ADMatches.Add($match) | Out-Null

						$script:NoMatch = $script:NoMatch | Where-Object { $_.ID -ne $SelectedID }

						# Remove from datagridview table
						$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)

						# Show the updated message
						showUpdatedLabel($UpdatedLbl)
					} else {
						# Username was not found in AD
						[System.Windows.MessageBox]::Show('That username was not found in AD. If it was created after this script was ran, you will need to re-run the script.')
						#TODO: Maybe modify this to ask a user if the AD account is new and if so query AD directly then add to the ADUsers array
					}
				} else {
					# Nothing was set to save...
					[System.Windows.MessageBox]::Show('Please enter a username before clicking save.')
				}

			# O365
			} elseif ($Type -eq 'O365') {
				$NewEmailMatch = $setMatchTxt.Text

				if ($NewEmailMatch) {
					if (($script:O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $NewEmailMatch } | Measure-Object).Count -eq 1) {
						# Email was found in O365, update IT Glue notes and move from $NoITGO365Match to $ITGO365Matches
						$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
						$CurrentNotes = $CurrentNotes.TrimEnd()
						$UserUpdate = 
							@{
								type = "contacts"
								attributes = @{
									notes = $CurrentNotes + "`nO365 Email: " + $NewEmailMatch
								}	
							}
						Set-ITGlueContacts -id $SelectedID -data $UserUpdate

						$O365Match = $script:O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $NewEmailMatch }
						$ITGlueUser = $script:EmployeeContacts | Where-Object { $_.ID -like $SelectedID }
						$match = [PSCustomObject]@{
							id = $SelectedID
							name = $ITGlueUser.Name
							type = $ITGlueUser."contact-type-name"
							itglue = $ITGlueUser
							o365 = $O365Match
						}
						$script:O365Matches.Add($match) | Out-Null

						$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $SelectedID }

						# Remove from datagridview table
						$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)

						# Show the updated message
						showUpdatedLabel($UpdatedLbl)
					} else {
						# Username was not found in O365
						[System.Windows.MessageBox]::Show('That email was not found in O365. Please make sure you are using the primary email address of the account. If it was created after this script was ran, you will need to re-run the script.')
						#TODO: Maybe modify this to ask a user if the O365 account is new and if so query O365 directly then add to the NewMatches array
					}
				} else {
					# Nothing was set to save...
					[System.Windows.MessageBox]::Show('Please enter an email before clicking save.')
				}
			
			# ChangeMatches
			} else {
				$NewUsername = $setMatchTxt.Text
				$NewO365Email = $setMatchTxt2.Text

				if ($NewUsername) {
					if (($script:ADEmployees | Where-Object { $_.Username -like $NewUsername } | Measure-Object).Count -eq 1) {
						# Username was found in AD, update IT Glue notes and update $FullMatches
						$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
						$CurrentNotes = $CurrentNotes -replace "Username\: \S+"
						$CurrentNotes = $CurrentNotes.TrimEnd()
						$UserUpdate = 
							@{
								type = "contacts"
								attributes = @{
									notes = $CurrentNotes + "`nUsername: " + $NewUsername
								}	
							}
						Set-ITGlueContacts -id $SelectedID -data $UserUpdate

						$ADMatch = $script:ADEmployees | Where-Object { $_.Username -like $NewUsername }
						$ITGlueUser = $script:EmployeeContacts | Where-Object { $_.ID -like $SelectedID }

						$script:ADMatches = [System.Collections.ArrayList] ($script:ADMatches | Where-Object { $_.ID -ne $SelectedID })
						$match = [PSCustomObject]@{
							id = $SelectedID
							name = $ITGlueUser.Name
							type = $ITGlueUser."contact-type-name"
							itglue = $ITGlueUser
							ad = $ADMatch
						}
						$script:ADMatches.Add($match) | Out-Null

						$MatchUpdated = buildITGMatch $ITGlueUser
						$script:FullMatches = [System.Collections.ArrayList] ($script:FullMatches | Where-Object { $_.ID -ne $SelectedID })
						$script:FullMatches.Add($MatchUpdated) | Out-Null

						# Show the updated message
						$currentADUsername.text = $NewUsername
						showUpdatedLabel($UpdatedLbl)
					} else {
						# Username was not found in AD
						[System.Windows.MessageBox]::Show('That username was not found in AD. If it was created after this script was ran, you will need to re-run the script.')
						#TODO: Maybe modify this to ask a user if the AD account is new and if so query AD directly then add to the ADUsers array
					}
				}

				if ($NewO365Email) {
					if (($script:O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $NewEmailMatch } | Measure-Object).Count -eq 1) {
						# Email was found in O365, update IT Glue notes and update $FullMatches
						$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
						$CurrentNotes = $CurrentNotes -replace "O365 Email\: \S+"
						$CurrentNotes = $CurrentNotes.TrimEnd()
						$UserUpdate = 
							@{
								type = "contacts"
								attributes = @{
									notes = $CurrentNotes + "`nO365 Email: " + $NewEmailMatch
								}	
							}
						Set-ITGlueContacts -id $SelectedID -data $UserUpdate

						$O365Match = $script:O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $NewEmailMatch }
						$ITGlueUser = $script:EmployeeContacts | Where-Object { $_.ID -like $SelectedID }

						$script:O365Matches = [System.Collections.ArrayList] ($script:O365Matches | Where-Object { $_.ID -ne $SelectedID })
						$match = [PSCustomObject]@{
							id = $SelectedID
							name = $ITGlueUser.Name
							type = $ITGlueUser."contact-type-name"
							itglue = $ITGlueUser
							o365 = $O365Match
						}
						$script:O365Matches.Add($match) | Out-Null

						$MatchUpdated = buildITGMatch $ITGlueUser
						$script:FullMatches = [System.Collections.ArrayList] ($script:FullMatches | Where-Object { $_.ID -ne $SelectedID })
						$script:FullMatches.Add($MatchUpdated) | Out-Null

						# Remove from datagridview table
						$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)

						# Show the updated message
						$currentO365Email.text = $NewO365Email
						showUpdatedLabel($UpdatedLbl)
					} else {
						# Username was not found in O365
						[System.Windows.MessageBox]::Show('That email was not found in O365. Please make sure you are using the primary email address of the account. If it was created after this script was ran, you will need to re-run the script.')
						#TODO: Maybe modify this to ask a user if the O365 account is new and if so query O365 directly then add to the NewMatches array
					}
				}
				
				if (!$NewUsername -and !$NewO365Email) {
					# Nothing was set to save...
					[System.Windows.MessageBox]::Show('Please enter a username before clicking save.')
				}
			}
		}
	})

	# On Contact Type Changed / Manually updated, update button.
	$updateContactType.Add_Click({
		$SelectedID = 0
		if ($NoMatchesGrid.CurrentRow) {
			$SelectedID = $NoMatchesGrid.CurrentRow.Cells['ID'].Value
		}
		if ($SelectedID -and $SelectedID -ge 0) {
			$SelectedRowID = $NoMatchesGrid.CurrentCell.RowIndex
			$NewContact = (Get-ITGlueContacts -id $SelectedID).data.attributes

			if ($NewContact -and $NewContact.name) {
				$NewContact | Add-Member -MemberType NoteProperty -Name ID -Value $null
				$NewContact.id = $SelectedID
				# Update $EmployeeContacts and $NoMatch/ADMatch/FullMatches
				$script:EmployeeContacts = $script:EmployeeContacts | Where-Object { $_.ID -ne $SelectedID }
				$script:EmployeeContacts += $NewContact

				if ($Type -eq 'AD') {
					$script:NoMatch = $script:NoMatch | Where-Object { $_.ID -ne $SelectedID }
					$script:NoMatch += $NewContact
				} elseif ($Type -eq 'O365') {
					$OldContact = $script:NoO365Match | Where-Object { $_.ID -eq $SelectedID }
					$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $SelectedID }
					$script:NoO365Match += $NewContact
				} else {
					$MatchUpdated = buildITGMatch $NewContact
					$script:FullMatches = [System.Collections.ArrayList] ($script:FullMatches | Where-Object { $_.ID -ne $SelectedID })
					$script:FullMatches.Add($MatchUpdated) | Out-Null

					$Emails = @()
					foreach ($Email in $NewContact."contact-emails") {
						$Emails += $Email."label-name" + ": " + $Email.value
					}
					$Row = @('', '', '', '', '', '', '', '')
					$Row[0] = $NewContact.ID
					$Row[1] = $NewContact.Name
					$Row[2] = $NewContact.Title
					$Row[3] = $NewContact."contact-type-name"
					$Row[4] = $NewContact."location-name"
					$Row[5] = $Emails -join ','
					$Row[6] = $NewContact."resource-url"
					$Row[7] = $NewContact.notes
					$NoMatchesGrid.Rows.Add($Row) | Out-Null
					$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
				}
				
				if ($NewContact."contact-type-name" -and $NewContact."contact-type-name" -notin $script:EmployeeContactTypes) {
					# New contact type is not a billed employee, remove
					if ($Type -eq 'AD') {
						$script:NoMatch = $script:NoMatch | Where-Object { $_.ID -ne $SelectedID }
					} elseif ($Type -eq 'O365') {
						$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $SelectedID }
					} else {
						$script:FullMatches = $script:FullMatches | Where-Object { $_.ID -ne $SelectedID }
					}
					$script:EmployeeContacts = $script:EmployeeContacts | Where-Object { $_.ID -ne $SelectedID }
					$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
				}

				if ($Type -eq "O365") {
					# If this is an O365 match, see if we can now match it via email
					$OldEmails = $OldContact."contact-emails".value
					$NewEmails = $NewContact."contact-emails".value
					$EmailsDiff = $NewEmails | Where-Object { $OldEmails -NotContains $_ } # Gets any new emails that were added to the contact

					# Email search
					$O365Match = $false
					foreach ($Email in $EmailsDiff) {
						$O365Match = $script:O365Mailboxes | Where-Object { $_.PrimarySmtpAddress -like $Email }
						if ($O365Match) { break; }
						$O365Match = $script:O365Mailboxes | Where-Object { $_.EmailAddresses -contains $Email }
						if ($O365Match) { break; }
					}

					# If more than 1 match, narrow down to 1
					$O365Match = $O365Match | Sort-Object PrimarySmtpAddress -Unique
					if ($O365Match -and ($O365Match | Measure-Object).Count -gt 1) {
						$O365Match = MultipleMatchesForm 'O365' $NewContact $O365Match

						# Update the users notes in IT Glue to set the primary email
						$NewEmailMatch = $O365Match.PrimarySmtpAddress
						$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
						$CurrentNotes = $CurrentNotes.TrimEnd()
						$UserUpdate = 
							@{
								type = "contacts"
								attributes = @{
									notes = $CurrentNotes + "`nPrimary O365 Email: " + $NewEmailMatch
								}	
							}
						Set-ITGlueContacts -id $SelectedID -data $UserUpdate
					}

					if ($O365Match) {
						$match = [PSCustomObject]@{
							id = $NewContact.ID
							name = $NewContact.Name
							type = $NewContact."contact-type-name"
							itglue = $NewContact
							o365 = $O365Match
						}
						$script:O365Matches.Add($match) | Out-Null
						$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $SelectedID }
						$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
					}
				}

				# Show the updated message
				showUpdatedLabel($UpdatedLbl)
			} else {
				# Contact was deleted
				if ($Type -eq 'AD') {
					$script:NoMatch = $script:NoMatch | Where-Object { $_.ID -ne $SelectedID }
				} elseif ($Type -eq 'O365') {
					$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $SelectedID }
				} else {
					$script:FullMatches = [System.Collections.ArrayList] ($script:FullMatches | Where-Object { $_.ID -ne $SelectedID })
				}
				$script:EmployeeContacts = $script:EmployeeContacts | Where-Object { $_.ID -ne $SelectedID }
				$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
				showUpdatedLabel($UpdatedLbl)
			}
		}
	})

	$ignoreContact.Add_Click({
		$SelectedID = 0
		if ($NoMatchesGrid.CurrentRow) {
			$SelectedID = $NoMatchesGrid.CurrentRow.Cells['ID'].Value
		}
		if ($SelectedID -and $SelectedID -ge 0) {
			$SelectedRowID = $NoMatchesGrid.CurrentCell.RowIndex
			doIgnoreContact $Type $SelectedID

			# Remove from datagridview table
			if ($Type -ne 'ChangeMatches') {
				$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
			} else {
				$currentADUsername.text = $null
			}

			# Show the updated message
			showUpdatedLabel($UpdatedLbl)
		}
	})

	$ignoreContact2.Add_Click({
		$SelectedID = 0
		if ($NoMatchesGrid.CurrentRow) {
			$SelectedID = $NoMatchesGrid.CurrentRow.Cells['ID'].Value
		}
		if ($SelectedID -and $SelectedID -ge 0) {
			$SelectedRowID = $NoMatchesGrid.CurrentCell.RowIndex
			doIgnoreContact 'O365' $SelectedID

			# Remove from datagridview table
			if ($Type -ne 'ChangeMatches') {
				$NoMatchesGrid.Rows.RemoveAt($SelectedRowID)
			} else {
				$currentO365Email.text = $null
			}

			# Show the updated message
			showUpdatedLabel($UpdatedLbl)
		}
	})

	function doIgnoreContact {
		param($CType, $ContactID)

		# update IT Glue notes and remove from $ITGADNoMatch or $Match array
		$CurrentNotes = (Get-ITGlueContacts -id $ContactID).data.attributes[0].notes
		$CurrentNotes = $CurrentNotes.TrimEnd()
		if ($CType -eq 'AD' -or $CType -eq 'ChangeMatches') {
			$NewNotes = $CurrentNotes + "`n# No AD Account"
		} else {
			$NewNotes = $CurrentNotes + "`n# No O365 Account"
		}
		$UserUpdate = 
			@{
				type = "contacts"
				attributes = @{
					notes = $NewNotes
				}	
			}

		Set-ITGlueContacts -id $ContactID -data $UserUpdate

		$ITGlueUser = $script:EmployeeContacts | Where-Object { $_.ID -like $ContactID }
		if ($CType -eq 'AD' -or $CType -eq 'ChangeMatches') {
			$script:NoMatchButIgnore += $ITGlueUser
			$script:NoMatch = $script:NoMatch | Where-Object { $_.ID -ne $ContactID }
		} elseif ($CType -eq 'O365') {
			$script:NoO365MatchButIgnore += $ITGlueUser
			$script:NoO365Match = $script:NoO365Match | Where-Object { $_.ID -ne $ContactID }
		}

		if ($Type -eq 'ChangeMatches') {
			$MatchToChange = $script:FullMatches | Where-Object { $_.ID -eq $ContactID }
			if ($CType -eq 'O365') {
				$script:O365Matches = [System.Collections.ArrayList] ($script:O365Matches | Where-Object { $_.ID -ne $ContactID })
				$MatchToChange."O365-Connected?" = $false
				$MatchToChange."O365-Name" = $null
				$MatchToChange."O365-PrimarySmtp" = $null
				$MatchToChange."O365-Emails" = $null
			} else {
				$script:ADMatches = [System.Collections.ArrayList] ($script:ADMatches | Where-Object { $_.ID -ne $ContactID })
				$MatchToChange."AD-Connected?" = $false
				$MatchToChange."AD-Name" = $null
				$MatchToChange."AD-Username" = $null
				$MatchToChange."AD-Email" = $null
			}
			$script:FullMatches = [System.Collections.ArrayList] ($script:FullMatches | Where-Object { $_.ID -ne $ContactID })
			$script:FullMatches.Add($MatchToChange) | Out-Null
		}
	}

	$doneFixingMatches.Add_Click({
		if ($null -ne $global:timer) {
			$global:timer.Stop()
			$global:timer = $null
		}
		[void]$NoMatchForm.Close()
	})

	[void]$NoMatchForm.ShowDialog()
}

# Display a no match form for the AD checked results
if ($CheckAD -and $NoMatch) {
	NoMatchForm('AD')
}

# Get O365/Exchange Email accounts
if ($CheckEmail) {
	Write-Host "Getting $EmailType Mailboxes. This may take a minute..." -ForegroundColor 'black' -BackgroundColor 'red'

	# Get the mailbox info and put it all together
	if ($EmailType -eq "O365") {
		$O365Mailboxes = Get-EXOMailbox -ResultSize unlimited -PropertySets Minimum, AddressList, Delivery, SoftDelete -Properties WhenCreated | 
			Select-Object -Property Name, DisplayName, Alias, PrimarySmtpAddress, EmailAddresses, 
				RecipientTypeDetails, Guid, UserPrincipalName, ImmutableId,
				DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled, WhenCreated |
			Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
		$AzureUsers = Get-MgUser -All -Property Id, UserPrincipalName, AccountEnabled, AssignedLicenses, DisplayName, GivenName, Surname, JobTitle, BusinessPhones, MobilePhone, FaxNumber, Department, OfficeLocation | Select-Object Id, UserPrincipalName, AccountEnabled, AssignedLicenses, DisplayName, GivenName, Surname, JobTitle, BusinessPhones, MobilePhone, FaxNumber, Department, OfficeLocation
		$DisabledAccounts = $AzureUsers | Where-Object { $_.AccountEnabled -eq $false } | Select-Object -ExpandProperty UserPrincipalName
		$UnlicensedUsers = $AzureUsers | Where-Object {
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

		if (!$LicenseTranslationTable) {
			New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null
			Invoke-WebRequest -UseBasicParsing -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" -OutFile "C:\Temp\O365LicenseTranslationTable.csv"
			$FullLicenseTranslationTable = Import-CSV -Path "C:\Temp\O365LicenseTranslationTable.csv"
			$LicenseTranslationTable_Temp = $FullLicenseTranslationTable | 
				Group-Object String_Id, Product_Display_Name | 
				 Foreach-Object { $_.Group | Select-Object String_Id, Product_Display_Name -First 1} | 
				  Sort-Object String_Id, Product_Display_Name

			$LicenseTranslationTable = @{}
			$LicenseTranslationTable_Temp | ForEach-Object {
				$LicenseTranslationTable[$_.String_Id] = $_.Product_Display_Name
			}
		}

		$LicensePlanList = Get-MgSubscribedSku
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AssignedLicenses -Value @()
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AAD_ObjectID -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name PrimaryLicense -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Phones -Value @()
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name MobilePhone -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Fax -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Department -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Office -Value $null
		
		$O365Mailboxes | ForEach-Object { 
			if ($_.UserPrincipalName -in $AzureUsers.UserPrincipalName) {
				$Mailbox = $_
				$LicenseSkus = ($AzureUsers | Where-Object { $_.UserPrincipalName -eq $Mailbox.UserPrincipalName }).AssignedLicenses | Select-Object SkuId
				$Licenses = @()
				$LicenseSkus | ForEach-Object {
					$sku = $_.SkuId
					foreach ($license in $licensePlanList) {
						if ($sku -eq $license.SkuId) {
							$Licenses += $license.SkuPartNumber
							break
						}
					}
				}
				$_.AssignedLicenses = $Licenses
				$_.PrimaryLicense = "None"

				foreach ($PrimaryLicenseType in $O365LicenseTypes_Primary.GetEnumerator()) {
					if ($PrimaryLicenseType.Key -in $Licenses) {
						$_.PrimaryLicense = $LicenseTranslationTable[$PrimaryLicenseType.Key]
						break
					}
				}


				$AzureUser = $AzureUsers | Where-Object { $_.UserPrincipalName -eq $Mailbox.UserPrincipalName }
				$_.AAD_ObjectID = $AzureUser.Id
				$_.FirstName = $AzureUser.GivenName
				$_.LastName = $AzureUser.Surname
				$_.Title = $AzureUser.JobTitle
				$_.Phones = @($AzureUser.BusinessPhones)
				$_.MobilePhone = $AzureUser.MobilePhone
				$_.Fax = $AzureUser.FaxNumber
				$_.Department = $AzureUser.Department
				$_.Office = $AzureUser.OfficeLocation
			}
		}
	} else {
		$O365Mailboxes = Get-Mailbox -ResultSize unlimited | 
			Select-Object -Property Name, DisplayName, UserPrincipalName, Alias, PrimarySmtpAddress, EmailAddresses, SamAccountName, 
				RecipientTypeDetails, AccountDisabled, IsDirSynced, Guid,
				DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled |
			Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null
		$O365MailboxUsers =  Get-User -ResultSize unlimited | Select-Object Name, FirstName, LastName, Title, Phone, MobilePhone, Fax
		Write-Host "Collecting mailbox statistics."
		$O365MailboxStats = Get-Mailbox -ResultSize unlimited | Get-MailboxStatistics | Select-Object DisplayName, LastLogonTime 
		Write-Host "Collected all mailbox statistics."

		for ($i = 0; $i -lt $O365Mailboxes.Count; $i++) {
			$O365MailboxUser = $O365MailboxUsers | Where-Object { $_.Name -like $O365Mailboxes[$i].Name }
			$O365Mailboxes[$i].FirstName = $O365MailboxUser.FirstName
			$O365Mailboxes[$i].LastName = $O365MailboxUser.LastName
			$O365Mailboxes[$i].Title = $O365MailboxUser.Title
			$O365Mailboxes[$i].Phones = @($O365MailboxUser.Phone)
			$O365Mailboxes[$i].MobilePhone = $O365MailboxUser.MobilePhone
			$O365Mailboxes[$i].Fax = $O365MailboxUser.Fax
			$O365MailboxStat = $O365MailboxStats | Where-Object { $_.DisplayName -like $O365Mailboxes[$i].DisplayName }
		}
		$UnlicensedUsers = @()
	}

	if ($EmailType -eq "O365") {
		Disconnect-ExchangeOnline -Confirm:$false
	} elseif ($ExchangeServerFQDN) {
		Remove-PSSession $Session
	}
	$MailboxCount = ($O365Mailboxes | Measure-Object).Count
	Write-Host "Got all $MailboxCount mailboxes. Now comparing them with IT Glue accounts."
    
    # Cleanup the email list
	for ($i = 0; $i -lt $O365Mailboxes.Count; $i++) {
		$EmailAddresses = $O365Mailboxes[$i].EmailAddresses
		$EmailAddresses = $EmailAddresses | Where-Object { $_ -notmatch '^SPO\:SPO_.+' }
        $EmailAddresses = $EmailAddresses -replace '^SIP:|SMTP:', ''
		$O365Mailboxes[$i].EmailAddresses = $EmailAddresses
	}

	# Make comparisons to IT Glue list
	$ITGO365Matches = New-Object -TypeName "System.Collections.ArrayList"
	$NoITGO365Match = @()
	$NoITGO365MatchButIgnore = @() # For IT Glue contacts without an O365 account
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
			$NoITGO365MatchButIgnore += $User
			continue
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

			# If still too many, show multiple matches form
			if (($O365Match | Measure-Object).Count -gt 1) {
				$O365Match = MultipleMatchesForm 'O365' $User $O365Match

				# Update the users notes in IT Glue to set the primary email
				$NewEmailMatch = $O365Match.PrimarySmtpAddress
				$CurrentNotes = (Get-ITGlueContacts -id $User.id).data.attributes[0].notes
				if ($CurrentNotes) {
					$CurrentNotes = $CurrentNotes.TrimEnd()
				}
				$UserUpdate = 
					@{
						type = "contacts"
						attributes = @{
							notes = $CurrentNotes + "`nPrimary O365 Email: " + $NewEmailMatch
						}	
					}
				Set-ITGlueContacts -id $User.id -data $UserUpdate
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
			$ITGO365Matches.Add($match) | Out-Null
		} else {
			if ($Type -ne 'Terminated' -and $Type -ne "Employee - On Leave" -and $User.ID -in $EmployeeContacts.id) {
				$NoITGO365Match += $User
			}
		}
	}
	$O365MatchCount = ($ITGO365Matches | Measure-Object).Count
	Write-Host "Finished matching all existing IT Glue contacts to their email accounts. $O365MatchCount matches were made."

	# Display a no match form for the O365 checked results
	if ($NoITGO365Match) {
		NoMatchForm('O365')
	}

	$UnmatchedO365 = $O365Mailboxes | Where-Object { $ITGO365Matches.o365.PrimarySmtpAddress -notcontains $_.PrimarySmtpAddress } | Where-Object { ($_.AssignedLicenses | Measure-Object).Count -gt 0 } | Sort-Object -Property @{ Expression = "PrimaryLicense" }, @{ Expression = "DisplayName" }
	Write-Host "$(($UnmatchedO365 | Measure-Object).Count) O365 accounts found without a match."
}


# Build existing matches list
function buildITGMatch {
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
	$MatchToAdd = buildITGMatch $Contact
	$FullMatches.Add($MatchToAdd) | Out-Null
}

Write-Host "All existing matches between IT Glue, AD, and the email system have now been made. Now matching missing AD accounts to O365..."


# Make comparisons directly between unmatched AD accounts and Email
$ADO365Matches = New-Object -TypeName "System.Collections.ArrayList"
foreach ($ADUser in $UnmatchedAD) {
	$O365Match = @()
	$Emails = @($ADUser.EmailAddress)
	if ($ADUser.Username -like "*@*") {
		$Emails += $ADUser.Username
	}
	if ($ADUser.UserPrincipalName) {
		$Emails += $ADUser.UserPrincipalName
	}
	$Emails = $Emails | Sort-Object -Unique

	$PrimaryEmail = $ADUser.EmailAddress
	if (!$PrimaryEmail -and ($Emails | Measure-Object).Count -gt 0) {
		$PrimaryEmail = $Emails | Select-Object -First 1 
	}
	$FirstName = $ADUser.GivenName
	$LastName = $ADUser.Surname
	$FullName = $ADUser.Name
	$DisplayName = $ADUser.DisplayName

	$HasEmails = $false
	if (($Emails | Measure-Object).Count -gt 0) {
		$HasEmails = $true
	}
	
	# Look for a match
	while (!$O365Match) {
		# Try ObjectID to Immutable ID first (for O365 to AD with Entra Connect Sync matches)
		if ($ADUser.ObjectGUID -and $O365Mailboxes[0].ImmutableId) {
			$guid = [guid]$ADUser.ObjectGUID
    		$byteArray = $guid.ToByteArray()
    		$calculatedImmutableId = [System.Convert]::ToBase64String($byteArray)
			$O365Match += $O365Mailboxes | Where-Object { $_.ImmutableId -eq $calculatedImmutableId}
		}
		if ($O365Match) { break; }
		# Try to match AAD ObjectID to Azure ID (for O365 to Azure matches)
		if ($ADType -eq "Azure" -and $ADUser.Id) {			
			$O365Match += $O365Mailboxes | Where-Object { $_.AAD_ObjectID -eq $ADUser.Id }
		}
		if ($O365Match) { break; }
		# Match on UserPrincipalName
		if ($ADUser.UserPrincipalName) {
			$O365Match += $O365Mailboxes | Where-Object { $_.UserPrincipalName -eq $ADUser.UserPrincipalName }
		}
		if ($O365Match) { break; }
		# Email search
		if ($HasEmails) {
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
		if ($FirstName -and $LastName) {
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
		}
		# Check Full Name and Display Name
		if ($FullName -and $DisplayName) {
			$O365Match = $O365Mailboxes | Where-Object { $_.DisplayName -like $DisplayName -or $_.DisplayName -like $FullName }
			if ($O365Match) { break; }
			$O365Match = $O365Mailboxes | Where-Object { $_.Name -like $DisplayName -or $_.DisplayName -like $FullName }
			if ($O365Match) { break; }
			$O365Match = $UnlicensedUsers | Where-Object { $_.DisplayName -like $DisplayName -or $_.DisplayName -like $FullName }
			if ($O365Match) { break; }
			$O365Match = $UnlicensedUsers | Where-Object { $_.Name -like $DisplayName -or $_.DisplayName -like $FullName }
			if ($O365Match) { break; }
		}

		# Get the root of each email address (before @) for the next checks
		if ($HasEmails) {
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
		if ($HasEmails) {
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
		if ($HasEmails) {
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

		# If still too many, show multiple matches form
		if (($O365Match | Measure-Object).Count -gt 1) {
			$O365Match = MultipleMatchesForm 'O365' $User $O365Match
		}
	}

	# Add to the Match or NoMatch array
	if ($O365Match) {
		$match = [PSCustomObject]@{
			name = $DisplayName
			adUPN = $ADUser.UserPrincipalName
			o365UPN = $O365Match.UserPrincipalName
			ad = $ADUser
			o365 = $O365Match
		}
		$ADO365Matches.Add($match) | Out-Null
	}
}
$ADO365MatchCount = ($ADO365Matches | Measure-Object).Count
Write-Host "Finished matching all unmatched AD accounts to their email accounts. $ADO365MatchCount matches were made."

# Now get any remaining AD and O365 accounts that don't have any matches
$UnmatchedAD = $UnmatchedAD | Where-Object { $_.UserPrincipalName -notin $ADO365Matches.adUPN }
$UnmatchedO365 = $UnmatchedO365 | Where-Object { $_.UserPrincipalName -notin $ADO365Matches.o365UPN }

$UsersToCreate = $ADO365Matches
$UnmatchedAD | ForEach-Object {
	$entry = [PSCustomObject]@{
		name = $_.DisplayName
		adUPN = $_.UserPrincipalName
		o365UPN = $false
		ad = $_
		o365 = $false
	}
	$UsersToCreate.Add($entry) | Out-Null
}
$UnmatchedO365 | ForEach-Object {
	$entry = [PSCustomObject]@{
		name = $_.DisplayName
		adUPN = $false
		o365UPN = $_.UserPrincipalName
		ad = $false
		o365 = $_
	}
	$UsersToCreate.Add($entry) | Out-Null
}

# Lets see if we can find any AD Groups that are primarily used by inactive users and suggest they get added to the $EmailOnlyGroupsIgnore variable
if ($ADType -eq "OnPremise") {
	$DaysInactive = 30
	$ThresholdDate = (Get-Date).AddDays(-$DaysInactive)
	$PercentageThreshold = 95
	$UserStatus = @{}

	foreach ($User in $ADEmployees) {
		$IsInactive = $false

		if ($null -ne $User.LastLogonDate) {
			# Check if the last logon is older than 30 days
			if ($User.LastLogonDate -lt $ThresholdDate) {
				$IsInactive = $true
			}
		} else {
			# If the user has never logged in, check if the account itself is older than 30 days
			# This prevents flagging brand-new users who haven't logged in yet as "inactive"
			if ($User.Created -lt $ThresholdDate) {
				$IsInactive = $true
			}
		}

		# Store the inactive status using the DistinguishedName as the key 
		# (Group.Members outputs an array of DistinguishedNames)
		$UserStatus[$User.DistinguishedName] = $IsInactive
	}

	$AllGroups = Get-ADGroup -Filter * -Properties Members
	$Results = @()

	foreach ($Group in $AllGroups) {
		$TotalUserCount = 0
		$InactiveUserCount = 0

		foreach ($MemberDN in $Group.Members) {
			# Check if the group member is a user we just evaluated 
			# (This naturally filters out nested groups, computers, or contacts)
			if ($UserStatus.ContainsKey($MemberDN)) {
				$TotalUserCount++
				
				if ($UserStatus[$MemberDN] -eq $true) {
					$InactiveUserCount++
				}
			}
		}

		# Calculate the percentage only if the group actually contains users
		if ($TotalUserCount -gt 0) {
			$InactivePercentage = ($InactiveUserCount / $TotalUserCount) * 100

			# If the group meets or exceeds the 95% threshold, add it to the results
			if ($InactivePercentage -ge $PercentageThreshold) {
				$Results += [PSCustomObject]@{
					GroupName       = $Group.Name
					TotalUsers      = $TotalUserCount
					InactiveUsers   = $InactiveUserCount
					InactivePercent = [math]::Round($InactivePercentage, 2)
					GroupCategory   = $Group.GroupCategory
				}
			}
		}
	}

	# Display the results and see if the end user wants to add these to the email only groups
	if ($Results) {
		Write-Host "The following groups have more than $PercentageThreshold% inactive users. You may want to consider adding these to the `\$EmailOnlyGroupsIgnore` variable since they are likely used for email distribution lists rather than security permissions:" -ForegroundColor Yellow
		$Results | Format-Table -AutoSize

		$AddToIgnore = Read-Host "Do you want to add these groups to the `$EmailOnlyGroupsIgnore` variable (will only be for this run)? (Y/N)"
		if ($AddToIgnore -eq 'Y') {
			$CopyPasteString = @()
			foreach ($Group in $Results) {
				if ($EmailOnlyGroupsIgnore -notcontains $Group.GroupName) {
					$EmailOnlyGroupsIgnore += $Group.GroupName
					$CopyPasteString += $Group.GroupName
				}
			}
			Write-Host "Selected groups have been added to the `$EmailOnlyGroupsIgnore` variable." -ForegroundColor Green
			Write-Host "To make this change permanent, please edit 'User Audit - Constants.ps1' and add the following to the `$EmailOnlyGroupsIgnore variable: " -ForegroundColor Yellow
			Write-Host "`"$($CopyPasteString -join '", "')`"" -ForegroundColor Yellow
		} else {
			Write-Host "No changes made to the `\$EmailOnlyGroupsIgnore` variable." -ForegroundColor Cyan
		}
	}
}

# Creates form for mapping OUs/Offices/Departments to an ITG Location
function Get-ITGLocationSelection {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Primary,

        [Parameter(Mandatory=$false)]
        [string]$OUPath,

		[Parameter(Mandatory=$false)]
        [string]$UserDisplayName,

        [Parameter(Mandatory=$true)]
        [array]$ITGLocations,

		[Parameter(Mandatory=$false)]
        [int]$MappingType = 1
    )

    # Load required Windows Forms and Drawing assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Initialize the main Form window
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Location Selection"
    $form.Size = New-Object System.Drawing.Size(550, 220)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

	# Get match type name
	switch ($MappingType) {
		1 { $MatchType = "OU" }
		2 { $MatchType = "Department" }
		3 { $MatchType = "Office Location" }
		default {
			$MappingType = 1;
			$MatchType = "OU"
		}
	}

    # Label 1: Primary Message	
    $lblPrimary = New-Object System.Windows.Forms.Label
    $lblPrimary.Text = "Please select the ITG location matching the $($MatchType): $Primary"
    $lblPrimary.Location = New-Object System.Drawing.Point(15, 20)
    $lblPrimary.AutoSize = $true
    $form.Controls.Add($lblPrimary)

	# Label 2: User Display Name (if provided)
	if ($UserDisplayName) {
		$lblUser = New-Object System.Windows.Forms.Label
		$lblUser.Text = "Reviewing User: $UserDisplayName"
		$lblUser.Location = New-Object System.Drawing.Point(15, 45)
		$lblUser.MaximumSize = New-Object System.Drawing.Size(400, 0) 
		$lblUser.AutoSize = $true
		$form.Controls.Add($lblUser)
	}

    # Label 3: Full OU Path
	if ($MappingType -eq 1 -and $OUPath) {
		$lblPath = New-Object System.Windows.Forms.Label
		$lblPath.Text = "Full Path: $OUPath"
		$lblPath.Location = New-Object System.Drawing.Point(15, 60)
		$lblPath.MaximumSize = New-Object System.Drawing.Size(400, 0) 
		$lblPath.AutoSize = $true
		$form.Controls.Add($lblPath)
	}

    # ComboBox (Dropdown)
    $comboBox = New-Object System.Windows.Forms.ComboBox
    $comboBox.Location = New-Object System.Drawing.Point(15, 90)
    $comboBox.Width = 400
    $comboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList

    # Create the ArrayList for DataBinding
    $arrayList = New-Object System.Collections.ArrayList
    
    # --- NEW: Inject the empty/skip option at the top ---
    $emptyOption = [PSCustomObject]@{ ID = $false; name = "-- Do not map this $($MatchType) --" }
    [void]$arrayList.Add($emptyOption)
    
    # Add the actual locations below it
    [void]$arrayList.AddRange($ITGLocations)

    # Bind the updated list to the ComboBox
    $comboBox.DataSource = $arrayList
    $comboBox.DisplayMember = "name"
    $comboBox.ValueMember = "ID"
    $form.Controls.Add($comboBox)

    # Submit Button
    $btnSubmit = New-Object System.Windows.Forms.Button
    $btnSubmit.Location = New-Object System.Drawing.Point(235, 135)
    $btnSubmit.Text = "Submit"
    $btnSubmit.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnSubmit
    $form.Controls.Add($btnSubmit)

    # Cancel Button
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(325, 135)
    $btnCancel.Text = "Cancel"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $btnCancel
    $form.Controls.Add($btnCancel)

    $form.Topmost = $true

    $result = $form.ShowDialog()

    # Return the ID (which will be $null if they chose the "Do not map" option)
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $comboBox.SelectedValue
    } else {
        return $null
    }
}

# Parse text out from a phone number
function Format-PhoneNumber {
	param($PhoneNumber)

	# Remove all non-numeric characters
	$Digits = ($PhoneNumber -replace '[^0-9+]' , '')

	# If the number has 10 digits, assume it's a Canadian number and format it accordingly
	if ($Digits.Length -eq 10) {
		return "($($Digits.Substring(0,3))) $($Digits.Substring(3,3))-$($Digits.Substring(6,4))"
	} else {
		# Otherwise, just return the digits as they are
		return $Digits
	}
}

# Check if a phone number is unique in the contact
function Get-PhoneNumberUniqueness {
	param($PhoneNumber, $ExistingContact)

	$Digits = ($PhoneNumber -replace '[^0-9]' , '')

	foreach ($ContactPhone in $ExistingContact."contact-phones") {
		$ExistingPhoneDigits = ($ContactPhone.value -replace '[^0-9]' , '')
		if ($ExistingPhoneDigits -eq $Digits) {
			return $false
		}
		$ExistingExtensionDigits = ($ContactPhone.extension -replace '[^0-9]' , '')
		if ($ExistingExtensionDigits -eq $Digits) {
			return $false
		}
	}

	return $true
}

function New-ITGPhoneContactHash {
	param($PhoneNumber, $Type, $Primary, $PrimarySet, $LocMainPhone)

	$ParsedNumber = Format-PhoneNumber $PhoneNumber

	if ($ParsedNumber.length -lt 7) {
		return @{
			"value" = Format-PhoneNumber $LocMainPhone
			"label-name" = $Type
			"primary" = if ($PrimarySet) { $false } else { $Primary }
			"extension" = $ParsedNumber
		}
	} else {
		return @{
			"value" = $ParsedNumber
			"label-name" = $Type
			"primary" = if ($PrimarySet) { $false } else { $Primary }
			"extension" = $null
		}
	}
}

# Now run through unique AD/O365 accounts that aren't in ITG, guess contact type, create a list for review, then import all users into ITG
$ITGContactsToAdd = New-Object -TypeName "System.Collections.ArrayList"
$LocationMappings_OU = @{}
$LocationMappings_Department = @{}
$LocationMappings_Office = @{}
$SingleLocationMappingPreference = $false
foreach ($UserToCreate in $UsersToCreate) {
	$NewContact = @{
		"first-name" = ""
		"last-name" = ""
		"title" = ""
		"contact-type-id" = $false
		"location-id" = $false
		"contact-emails" = @()
		"contact-phones" = @()
	}

	$HasAD = [bool]($UserToCreate.adUPN -or $UserToCreate.ad)
	$HasO365 = [bool]($UserToCreate.o365UPN -or $UserToCreate.o365)

	# First Name
	if ($HasAD -and $UserToCreate.ad.GivenName) {
		$NewContact."first-name" = $UserToCreate.ad.GivenName
	} elseif ($HasO365 -and $UserToCreate.o365.FirstName) {
		$NewContact."first-name" = $UserToCreate.o365.FirstName
	} elseif ($HasAD -and $UserToCreate.ad.DisplayName -and $UserToCreate.ad.DisplayName.trim() -like "* *") {
		$NewContact."first-name" = (($UserToCreate.ad.DisplayName.trim() -split " ") | Select-Object -SkipLast 1) -join " "
	} elseif ($HasO365 -and $UserToCreate.o365.DisplayName -and $UserToCreate.o365.DisplayName.trim() -like "* *") {
		$NewContact."first-name" = (($UserToCreate.o365.DisplayName.trim() -split " ") | Select-Object -SkipLast 1) -join " "
	} elseif ($HasAD -and $UserToCreate.ad.Name -and $UserToCreate.ad.Name.trim() -like "* *") {
		$NewContact."first-name" = (($UserToCreate.ad.Name.trim() -split " ") | Select-Object -SkipLast 1) -join " "
	} elseif ($HasO365 -and $UserToCreate.o365.Name -and $UserToCreate.o365.Name.trim() -like "* *") {
		$NewContact."first-name" = (($UserToCreate.o365.Name.trim() -split " ") | Select-Object -SkipLast 1) -join " "
	} elseif ($HasAD -and $UserToCreate.ad.DisplayName) {
		$NewContact."first-name" = $UserToCreate.ad.DisplayName
	} elseif ($HasAD -and $UserToCreate.ad.Name) {
		$NewContact."first-name" = $UserToCreate.ad.Name
	} elseif ($HasO365 -and $UserToCreate.o365.DisplayName) {
		$NewContact."first-name" = $UserToCreate.o365.DisplayName
	} elseif ($HasO365 -and $UserToCreate.o365.Name) {
		$NewContact."first-name" = $UserToCreate.o365.Name
	} else {
		$NewContact."first-name" = $UserToCreate.name
	}

	# Last Name
	if ($HasAD -and $UserToCreate.ad.Surname) {
		$NewContact."last-name" = $UserToCreate.ad.Surname
	} elseif ($HasO365 -and $UserToCreate.o365.LastName) {
		$NewContact."last-name" = $UserToCreate.o365.LastName
	} elseif ($HasAD -and $UserToCreate.ad.DisplayName -and (($UserToCreate.ad.DisplayName.trim() -split " ") | Measure-Object).Count -gt 1) {
		$NewContact."last-name" = (($UserToCreate.ad.DisplayName.trim() -split " ") | Select-Object -Last 1)
	} elseif ($HasO365 -and $UserToCreate.o365.DisplayName -and (($UserToCreate.o365.DisplayName.trim() -split " ") | Measure-Object).Count -gt 1) {
		$NewContact."last-name" = (($UserToCreate.o365.DisplayName.trim() -split " ") | Select-Object -Last 1)
	} elseif ($HasAD -and $UserToCreate.ad.Name -and (($UserToCreate.ad.Name.trim() -split " ") | Measure-Object).Count -gt 1) {
		$NewContact."last-name" = (($UserToCreate.ad.Name.trim() -split " ") | Select-Object -Last 1)
	} elseif ($HasO365 -and $UserToCreate.o365.Name -and (($UserToCreate.o365.Name.trim() -split " ") | Measure-Object).Count -gt 1) {
		$NewContact."last-name" = (($UserToCreate.o365.Name.trim() -split " ") | Select-Object -Last 1)
	} else {
		$NewContact."last-name" = "."
	}

	# Title
	if ($HasAD -and $UserToCreate.ad.Title) {
		$NewContact.title = $UserToCreate.ad.Title
	} elseif ($HasO365 -and $UserToCreate.o365.Title) {
		$NewContact.title = $UserToCreate.o365.Title
	}

	# Emails
	$Emails = @()
	if ($HasAD -and $UserToCreate.ad.EmailAddress) {
		$Emails += $UserToCreate.ad.EmailAddress
	}
	if ($HasO365) {
		if ($UserToCreate.o365.PrimarySmtpAddress -notlike 'no license') {
			$Emails += $UserToCreate.o365.PrimarySmtpAddress
		}
		$UserToCreate.o365.EmailAddresses | Foreach-Object {
			if ($_ -like "*@*" -and $_ -notlike "*onmicrosoft.com" -and $_.trim() -notlike "* *" -and $_ -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
				$Emails += $_
			}
		}
	}
	$Emails = @($Emails | Sort-Object -Unique)

	$PrimaryEmail = $false
	if (($Emails | Measure-Object).Count -gt 0) {
		if (($Emails | Measure-Object).Count -eq 1) {
			$PrimaryEmail = $Emails[0]
		} elseif ($HasO365 -and $UserToCreate.o365.PrimarySmtpAddress -notlike 'no license') {
			$PrimaryEmail = $UserToCreate.o365.PrimarySmtpAddress
		} elseif ($HasAD) {
			$PrimaryEmail = $UserToCreate.ad.EmailAddress
		} else {
			$PrimaryEmail = $Emails | Select-Object -First 1 
		}
		$PrimaryEmail = $PrimaryEmail.trim()
	}

	if (($Emails | Measure-Object).Count -gt 0) {
		$Emails | Foreach-Object {
			$NewContact."contact-emails" += @{
				value = $_.trim()
				primary = if ($PrimaryEmail -eq $_.trim()) { $true } else { $false }
				"label-name" = "Work"
			}
		}
	}

	# Location
	if (!$HasMultipleLocations -and !$SingleLocationMappingPreference) {
		# See if the end user wants to set all of the locations to the primary, or not set locations at all
		$title = "Select Location Mapping Option"
		$message = "Only 1 location was found in ITG. Do you want to map all users to this location? Or leave the location empty for all contacts?"
		$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Map contacts to 1 location."
		$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Don't map contacts."
		$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
		$result = $host.ui.PromptForChoice($title, $message, $options, 0)

		if ($result -eq 0) {
			Write-Host "Proceeding to map contacts..."
			$SingleLocationMappingPreference = "map"
		} else {
			Write-Host "Cancelled mapping of contacts."
			$SingleLocationMappingPreference = "dontmap"
		}
	}
	
	if (!$HasMultipleLocations -and $SingleLocationMappingPreference) {
		if ($SingleLocationMappingPreference -eq "map") {
			# Map all contact to the 1 location
			$NewContact."location-id" = @($Locations)[0].id
		} elseif ($SingleLocationMappingPreference -eq "dontmap") {
			# Don't map contacts to a location
			$NewContact."location-id" = $false
		}
	} elseif ($HasMultipleLocations) {
		foreach ($MappingPreference in $MapITGLocationsPreference) {
			if ($MappingPreference -eq 1) {
				# Map on OU
				if ($HasAD -and $UserToCreate.ad.OUs) {
					$OUPath = (($UserToCreate.ad.OUs[($UserToCreate.ad.OUs.Count -1)..0]) -join "\")

					if (!$LocationMappings_OU.ContainsKey($OUPath)) {
						$ToMap = Get-ITGLocationSelection -Primary $UserToCreate.ad.PrimaryOU -OUPath $OUPath -ITGLocations $Locations -MappingType 1 -UserDisplayName $UserToCreate.name
						if ($null -ne $ToMap) {
							$LocationMappings_OU[$OUPath] = $ToMap
						}
					}

					if ($LocationMappings_OU[$OUPath]) {
						$NewContact."location-id" = $LocationMappings_OU[$OUPath]
					}
					break
				}
			} elseif ($MappingPreference -eq 2) {
				# Map on Department
				$Department = $false
				if ($HasAD -and $UserToCreate.ad.Department) {
					$Department = $UserToCreate.ad.Department.Trim()
				} elseif ($HasO365 -and $UserToCreate.o365.Department) {
					$Department = $UserToCreate.o365.Department.Trim()
				}


				if ($Department) {
					if (!$LocationMappings_Department.ContainsKey($Department)) {
						$ToMap = Get-ITGLocationSelection -Primary $Department -ITGLocations $Locations -MappingType 2 -UserDisplayName $UserToCreate.name
						if ($null -ne $ToMap) {
							$LocationMappings_Department[$Department] = $ToMap
						}
					}

					if ($LocationMappings_Department[$Department]) {
						$NewContact."location-id" = $LocationMappings_Department[$Department]
					}
					break
				}
			} elseif ($MappingPreference -eq 3) {
				# Map on Office
				$Office = $false
				if ($HasAD -and $UserToCreate.ad.Office) {
					$Office = $UserToCreate.ad.Office.Trim()
				} elseif ($HasO365 -and $UserToCreate.o365.Office) {
					$Office = $UserToCreate.o365.Office.Trim()
				}


				if ($Office) {
					if (!$LocationMappings_Office.ContainsKey($Office)) {
						$ToMap = Get-ITGLocationSelection -Primary $Office -ITGLocations $Locations -MappingType 3 -UserDisplayName $UserToCreate.name
						if ($null -ne $ToMap) {
							$LocationMappings_Office[$Office] = $ToMap
						}
					}

					if ($LocationMappings_Office[$Office]) {
						$NewContact."location-id" = $LocationMappings_Office[$Office]
					}
					break
				}
			} else {
				# No mapping
			}
		}
		
		
	}

	# Phone #s
	$LocationMainPhoneNum = $null
	if ($NewContact."location-id") {
		$LocationMainPhoneNum = ($Locations | Where-Object { $_.id -eq $NewContact."location-id" }).'phone'
	}
	if (!$LocationMainPhoneNum) {
		$LocationMainPhoneNum = $Locations | Where-Object { $_.primary -eq $true -and $_.phone } | Select-Object -First 1 -ExpandProperty 'phone' -ErrorAction SilentlyContinue
	}

	$PrimarySet = $false
	if ($HasAD -and $UserToCreate.ad.OfficePhone) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.ad.OfficePhone -Type "Work" -Primary $true -PrimarySet $false -LocMainPhone $LocationMainPhoneNum
		$PrimarySet = $true
	}
	if ($HasAD -and $UserToCreate.ad.MobilePhone -and (Get-PhoneNumberUniqueness -PhoneNumber $UserToCreate.ad.MobilePhone -ExistingContact $NewContact)) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.ad.MobilePhone -Type "Mobile" -Primary $true -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
		$PrimarySet = $true
	}
	if ($HasAD -and $ADType -eq "Azure" -and $UserToCreate.ad.BusinessPhones) {
		$UserToCreate.ad.BusinessPhones | ForEach-Object {
			if (Get-PhoneNumberUniqueness -PhoneNumber $_ -ExistingContact $NewContact) {
				$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $_ -Type "Work" -Primary $true -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
				$PrimarySet = $true
			}
		}
	}
	if ($HasAD -and $UserToCreate.ad.ipPhone -and (Get-PhoneNumberUniqueness -PhoneNumber $UserToCreate.ad.ipPhone -ExistingContact $NewContact)) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.ad.ipPhone -Type "Work" -Primary $true -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
		$PrimarySet = $true
	}

	if ($HasO365 -and $UserToCreate.o365.MobilePhone -and (Get-PhoneNumberUniqueness -PhoneNumber $UserToCreate.o365.MobilePhone -ExistingContact $NewContact)) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.o365.MobilePhone -Type "Mobile" -Primary $true -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
		$PrimarySet = $true
	}
	if ($HasO365 -and $UserToCreate.o365.Phones) {
		$UserToCreate.o365.Phones | ForEach-Object {
			if (Get-PhoneNumberUniqueness -PhoneNumber $_ -ExistingContact $NewContact) {
				$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $_ -Type "Work" -Primary $true -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
				$PrimarySet = $true
			}
		}
	}

	if ($HasAD -and $UserToCreate.ad.HomePhone -and (Get-PhoneNumberUniqueness -PhoneNumber $UserToCreate.ad.HomePhone -ExistingContact $NewContact)) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.ad.HomePhone -Type "Other" -Primary $false -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
	}
	if ($HasAD -and $UserToCreate.ad.Fax) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.ad.Fax -Type "Fax" -Primary $false -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
	}

	if ($HasO365 -and $UserToCreate.o365.Fax -and (Get-PhoneNumberUniqueness -PhoneNumber $UserToCreate.o365.Fax -ExistingContact $NewContact)) {
		$NewContact.'contact-phones' += New-ITGPhoneContactHash -PhoneNumber $UserToCreate.o365.Fax -Type "Fax" -Primary $false -PrimarySet $PrimarySet -LocMainPhone $LocationMainPhoneNum
	}

	# Contact Type
	$ContactType = $false

	$EmailOnly = $false
	if ($HasO365 -and $HasAD -and $UserToCreate.o365.AccountDisabled -eq $false -and $UserToCreate.o365.RecipientTypeDetails -like 'UserMailbox' -and $UserToCreate.AD.Groups -and $UserToCreate.o365.PrimarySmtpAddress -notlike 'no license') {
		# Email only if AD & O365 + not in any employee AD groups
		$EmployeeGroups = @()
		if ($HasAD -and $UserToCreate.AD.Groups) {
			foreach ($Group in $UserToCreate.AD.Groups) {
				if (($EmailOnlyGroupsIgnore | ForEach-Object{$Group -like $_}) -notcontains $true ) {
					$EmployeeGroups += $Group
				}
			}
		}

		# Unless AD type is Azure and the user has a non-email only license
		if ($ADType -ne "Azure" -and ($EmployeeGroups | Measure-Object).Count -eq 0) {
			$EmailOnly = $true
		}

		if ($ADType -eq "Azure" -and $EmailType -ne "O365" -and ($EmployeeGroups | Measure-Object).Count -eq 0) {
			$EmailOnly = $true
		}

		if ($ADType -eq "Azure" -and $EmailType -eq "O365" -and ($EmployeeGroups | Measure-Object).Count -eq 0) {
			if (($UserToCreate.o365.AssignedLicenses | Measure-Object).Count -gt 0) {
				$O365Licenses_NotEmailOnly = $UserToCreate.o365.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }
				if (($O365Licenses_NotEmailOnly | Measure-Object).Count -eq 0) {
					$EmailOnly = $true
				}
			} else {
				$EmailOnly = $true
			}
		}
	}

	if ($HasO365 -and !$HasAD -and $EmailType -eq "O365" -and $UserToCreate.o365.AccountDisabled -eq $false -and $UserToCreate.o365.RecipientTypeDetails -like 'UserMailbox' -and ($UserToCreate.o365.AssignedLicenses | Measure-Object).Count -gt 0 -and $UserToCreate.o365.PrimarySmtpAddress -notlike 'no license') {
		# Email only if only O365 and only has email only licenses
		$O365Licenses_NotEmailOnly = $UserToCreate.o365.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }
		if (($O365Licenses_NotEmailOnly | Measure-Object).Count -eq 0) {
			$EmailOnly = $true
		}
	}

	# If it looks email-only from the AD groups, and this is O365, lets double check if there are any office activated devices or intune devices (if so, it's not email only)
	if ($EmailType -eq "O365" -and $EmailOnly -eq $true -and ($UserToCreate.o365.AssignedLicenses | Measure-Object).Count -gt 0) {
		$O365Licenses_NotEmailOnly = $UserToCreate.o365.AssignedLicenses | Where-Object { $_ -notin $O365LicenseTypes_EmailOnly }

		if (($O365Licenses_NotEmailOnly | Measure-Object).Count -gt 0) {
			$O365Devices = Get-MgUserRegisteredDevice -UserId $UserToCreate.o365.AAD_ObjectID
			if (($O365Devices | Where-Object { !$_.DeletedDateTime } | Measure-Object).Count -gt 0) {
				$EmailOnly = $false
			} else {
				$IntuneDevices = Get-MgUserOwnedDevice -UserId $UserToCreate.o365.AAD_ObjectID
				if (($IntuneDevices | Where-Object { !$_.DeletedDateTime } | Measure-Object).Count -gt 0) {
					$EmailOnly = $false
				}
			}
		}
	}

	# Check to see if this user looks like a councillor, trustee, or similar (where they generally aren't billed, but can easily be misclassified)
	# This is used for an extra safety check
	$CouncillorStatus = $false
	if ($Municipality) {
		$TypesToCheck = @("Councillor", "Trustee", "Board Member")
		$TypesToCheckWithSpaces = $TypesToCheck | Where-Object { $_ -like "* *" }

		if (($UserToCreate.ad.DisplayName -and ($TypesToCheck | Where-Object { $UserToCreate.ad.DisplayName -like "*$($_)*" })) -or
			($UserToCreate.ad.Name -and ($TypesToCheck | Where-Object { $UserToCreate.ad.Name -like "*$($_)*" })) -or
			($UserToCreate.ad.Description -and ($TypesToCheck | Where-Object { $UserToCreate.ad.Description -like "*$($_)*" })) -or
			($UserToCreate.ad.EmailAddress -and ($TypesToCheck | Where-Object { $UserToCreate.ad.EmailAddress -like "*$($_)*" })) -or
			($UserToCreate.ad.EmailAddress -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.EmailAddress -like "*$($_ -replace " ", "_")*" })) -or
			($UserToCreate.ad.EmailAddress -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.EmailAddress -like "*$($_ -replace " ", "-")*" })) -or
			($UserToCreate.ad.EmailAddress -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.EmailAddress -like "*$($_ -replace " ", ".")*" })) -or
			($UserToCreate.ad.Username -and ($TypesToCheck | Where-Object { $UserToCreate.ad.Username -like "*$($_)*" })) -or
			($UserToCreate.ad.Username -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.Username -like "*$($_ -replace " ", "_")*" })) -or
			($UserToCreate.ad.Username -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.Username -like "*$($_ -replace " ", "-")*" })) -or
			($UserToCreate.ad.Username -and ($TypesToCheckWithSpaces | Where-Object { $UserToCreate.ad.Username -like "*$($_ -replace " ", ".")*" })) -or
			($UserToCreate.ad.Title -and ($TypesToCheck | Where-Object { $UserToCreate.ad.Title -like "*$($_)*" })) -or 
			($UserToCreate.ad.Groups -and ($TypesToCheck | Where-Object { $UserToCreate.ad.Groups -like "$($_)*" })) -or 
			($ADType -ne "Azure" -and $UserToCreate.ad.OUs -and ($TypesToCheck | Where-Object { $UserToCreate.ad.OUs -like "$($_)*" }))) 
		{
			$CouncillorStatus = $true
		}
	}

	# Guess Contact Type
	if (
		(!$HasAD -and !$HasO365) -or (!$HasAD -and $HasO365 -and $UserToCreate.o365.AccountDisabled -eq $true) -or 
		($HasAD -and !$HasO365 -and $UserToCreate.ad.Enabled -eq $false) -or ($HasAD -and !$HasO365 -and $UserToCreate.AD.OUs -like '*Disabled*') -or 
		($HasAD -and $HasO365 -and $UserToCreate.ad.Enabled -eq $false -and $UserToCreate.o365.AccountDisabled -eq $true) -or ($HasAD -and $HasO365 -and $UserToCreate.AD.OUs -like '*Disabled*' -and $UserToCreate.o365.AccountDisabled -eq $true) -or
		($HasAD -and $HasO365 -and $UserToCreate.ad.Enabled -eq $false -and $UserToCreate.o365.AccountDisabled -eq $false -and ($UserToCreate.o365.DisplayName -like "*Disabled*" -or $UserToCreate.ad.DisplayName -like "*Disabled*" -or $UserToCreate.ad.Description -like "*Disabled*" -or $UserToCreate.o365.PrimarySmtpAddress -like 'no license'))
	) {
		$ContactType = "ToTerminated"
	} elseif ((!$HasAD -and $EmailOnly) -or ($HasAD -and $EmailOnly -and ($IgnoreLastLogonDate -or !$UserToCreate.ad.LastLogonDate -or ($UserToCreate.ad.LastLogonDate -and $UserToCreate.ad.LastLogonDate -lt (Get-Date).AddDays(-30))))) {
		$ContactType = "ToEmailOnly"
	} elseif ($CouncillorStatus -and ($IgnoreLastLogonDate -or !$UserToCreate.ad.LastLogonDate -or ($UserToCreate.ad.LastLogonDate -and $UserToCreate.ad.LastLogonDate -lt (Get-Date).AddDays(-30)))) {
		$ContactType = "ToEmailOnly"
		if (!$NewContact.title) {
			$NewContact.title = "Councillor"
		}
	} elseif (
		($HasAD -and !$EmailOnly -and ($UserToCreate.ad.LastLogonDate -ge (Get-Date).AddDays(-30) -or $UserToCreate.ad.Created -ge (Get-Date).AddDays(-14))) -or 
		(!$HasAD -and $ADType -ne "OnPremise" -and $HasO365 -and !$EmailOnly -and $UserToCreate.o365.RecipientTypeDetails -like 'UserMailbox')
	) {
		if ($NewContact.title -like "*contract*" -or ($HasAD -and $UserToCreate.ad.Description -like "*contract*")) {
			$ContactType = "ToContractor"
		} elseif ($NewContact.title -like "*seasonal*" -or ($HasAD -and $UserToCreate.ad.Description -like "*seasonal*") -or $NewContact.title -like "*temporary*" -or ($HasAD -and $UserToCreate.ad.Description -like "*temporary*")) {
			$ContactType = "ToTemporary"
		} elseif ($NewContact.title -like "*vendor*" -or ($HasAD -and $UserToCreate.ad.Description -like "*vendor*")) {
			$ContactType = "ToVendor"
		} elseif ($NewContact.title -like "*shared*" -or ($HasAD -and $UserToCreate.ad.Description -like "*shared*") -or $UserToCreate.name -like "EOC *") {
			$ContactType = "ToSharedAccount"
		} elseif ($NewContact."last-name" -eq ".") {
			$ContactType = "ToServiceAccount"
		} else {
			$ContactType = "ToEmployee"
		}
	} elseif (!$HasAD -and $HasO365 -and $UserToCreate.o365.RecipientTypeDetails -notlike 'UserMailbox' -and $UserToCreate.o365.RecipientTypeDetails -notlike 'None') {
		$ContactType = "ToSharedMailbox"
	} elseif (!$HasAD -and $HasO365 -and $UserToCreate.o365.RecipientTypeDetails -like 'UserMailbox' -and $NewContact."last-name" -ne ".") {
		$ContactType = "ToEmailOnly"
	} elseif (!$HasAD -and $HasO365 -and $NewContact."last-name" -eq ".") {
		$ContactType = "ToSharedMailbox"
	} elseif ($HasAD -and !$EmailOnly -and $UserToCreate.ad.LastLogonDate) {
		if ($NewContact.title -like "*contract*" -or ($HasAD -and $UserToCreate.ad.Description -like "*contract*")) {
			$ContactType = "ToContractor"
		} elseif ($NewContact.title -like "*seasonal*" -or ($HasAD -and $UserToCreate.ad.Description -like "*seasonal*") -or $NewContact.title -like "*temporary*" -or ($HasAD -and $UserToCreate.ad.Description -like "*temporary*")) {
			$ContactType = "ToTemporary"
		} elseif ($NewContact.title -like "*vendor*" -or ($HasAD -and $UserToCreate.ad.Description -like "*vendor*")) {
			$ContactType = "ToVendor"
		} elseif ($NewContact.title -like "*shared*" -or ($HasAD -and $UserToCreate.ad.Description -like "*shared*") -or $UserToCreate.name -like "EOC *") {
			$ContactType = "ToSharedAccount"
		} elseif ($NewContact."last-name" -eq ".") {
			$ContactType = "ToServiceAccount"
		} else {
			$ContactType = "ToEmployee"
		}
	} elseif ($EmailOnly) {
		$ContactType = "ToEmailOnly"
	} else {
		$ContactType = $false
	}

	if ($ContactType) {
		if ($ContactTypeMapping[$ContactType]) {
			if ($ContactTypeMapping[$ContactType] -is [int] -or $ContactTypeMapping[$ContactType] -is [double]) {
				$NewContact."contact-type-id" = $ContactTypeMapping[$ContactType]
			} else {
				$ContactTypeMatch = $ContactTypes | Where-Object { $_.name -like $ContactTypeMapping[$ContactType] }
				if ($ContactTypeMatch) {
					$NewContact."contact-type-id" = $ContactTypeMatch.id
				}
			}
		}
	}


	$ITGContactsToAdd.Add($NewContact) | Out-Null
}

$ITGContactsToAdd_Review = $ITGContactsToAdd | Foreach-Object {
	$ToAdd = $_
	[PSCustomObject]@{
		"First Name" = $_.'first-name'
		"Last Name" = $_.'last-name'
		"Title" = $_.title
		"Emails" = ($_.'contact-emails' | Sort-Object {$_.primary} -Descending).value -join ", "
		"Phones" = ($_.'contact-phones' | Sort-Object {$_.primary} -Descending | Select-Object @{Name="phone"; Expression={ if (!$_.extension) { $_.value } else { "$($_.value)x$($_.extension)"} }}).phone -join ", "
		"Contact Type" = ($ContactTypes | Where-Object { $_.id -eq $ToAdd.'contact-type-id' }).name
		"Location" = ($Locations | Where-Object { $_.id -eq $ToAdd.'location-id' }).name
	}
}

Write-Host "The following contacts will be added to ITG:" -ForegroundColor Green
$ITGContactsToAdd_Review | Out-GridView -Title "Contacts to Add to ITG" -PassThru
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host "The full list has been exported as a CSV to the current directory as ITGContactsToAdd_$timestamp.csv" -ForegroundColor Green
$ITGContactsToAdd_Review | Export-Csv -Path ".\ITGContactsToAdd_$timestamp.csv" -NoTypeInformation -Encoding UTF8

# Now upload all users in $ITGContactsToAdd to ITG Contacts
$title = "Confirm Upload"
$message = "Are you sure you want to upload $($ITGContactsToAdd.Count) contacts to ITGlue?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Upload contacts to ITGlue."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Cancel the upload."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$result = $host.ui.PromptForChoice($title, $message, $options, 1)

if ($result -eq 0) {
	Write-Host "Uploading contacts to ITGlue..." -ForegroundColor Green
	$i = 0
	$totalContacts = ($ITGContactsToAdd | Measure-Object).Count
	foreach ($ContactAttributes in $ITGContactsToAdd) {
		$i++
		
		# Remove empty or false values from ContactAttributes
		$CleanedAttributes = @{}
		foreach ($key in $ContactAttributes.Keys) {
			$value = $ContactAttributes[$key]
			if ($value -is [array]) {
				if (($value | Measure-Object).Count -gt 0) {
					$CleanedAttributes[$key] = $value
				}
			} elseif ($value -is [hashtable]) {
				if ($value.Count -gt 0) {
					$CleanedAttributes[$key] = $value
				}
			} elseif ($null -ne $value -and $value -ne $false -and $value -ne "") {
				$CleanedAttributes[$key] = $value
			}
		}
		
		Write-Progress -Activity "Uploading Contacts to ITGlue" -PercentComplete $PercentComplete -Status ("$i of $totalContacts complete - " + $PercentComplete + "% (Uploading: $($ContactAttributes.'first-name') $($ContactAttributes.'last-name'))")
		try {
			$NewContactData = @{
				type = "contacts"
				attributes = $CleanedAttributes
			}
			$NewContact = New-ITGlueContacts -organization_id $orgID -data $NewContactData
			Write-Host "Successfully uploaded contact: $($ContactAttributes.'first-name') $($ContactAttributes.'last-name') (ITG ID: $($NewContact.data.id))" -ForegroundColor Green
		} catch {
			Write-Host "Failed to upload contact: $($ContactAttributes.'first-name') $($ContactAttributes.'last-name'). Error: $_" -ForegroundColor Red
		}
		[int]$PercentComplete = ($i / $totalContacts * 100)
		Start-Sleep -Milliseconds 500 # Sleep for a short time to avoid hitting API rate limits
	}
	Write-Progress -Activity "Uploading Contacts to ITGlue" -Status "Complete" -Completed
} else {
	Write-Host "Upload cancelled." -ForegroundColor Yellow
	exit
}
