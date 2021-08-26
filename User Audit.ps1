#Requires -RunAsAdministrator
Set-ExecutionPolicy Unrestricted
#####################################################################
### Load Variables from external file
### Make sure you setup your variables in the User Audit - Constants.ps1 file
. "$PSScriptRoot\User Audit - Constants.ps1"
. "$PSScriptRoot\O365Licenses.ps1"
$CustomOverview_FlexAssetID = 219027
$GitHubVersion = "https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/currentversion.txt"
$UpdateFile = "https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/update.ps1"
#####################################################################
Write-Host "User audit starting..."

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

# Check for any required updates
$UpdatesAvailable = $false
$CurrentVersion = Get-Content "$PSScriptRoot\currentversion.txt"
$NextVersion = $null
try {
	$NextVersion = (New-Object System.Net.WebClient).DownloadString($GitHubVersion).Trim([Environment]::NewLine)
} catch [System.Exception] {
	Write-Host $_ -ForegroundColor Red
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

		$UpdatePath = "$PSScriptRoot\update.ps1"
		(New-Object System.Net.Webclient).DownloadFile($UpdateFile, $UpdatePath)
		FixFilePermissions -Path $UpdatePath
		Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList '-File', $UpdatePath, "User_Audit"
		exit
	}
}
### Update check complete

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
# If using my old version of the ITGlueAPI under 2.1.0, upgrade to the official version
$Version = (Get-Module ITGlueAPI).Version
if ($Version.Major -lt 2 -or $Version.Minor -lt 1) {
	Remove-Module ITGlueAPI
	Uninstall-Module ITGlueAPI
	Remove-Item -LiteralPath "C:\Program Files\WindowsPowerShell\Modules\ITGlueAPI" -Force -Recurse -ErrorAction Ignore
	Install-Module -Name ITGlueAPI
	Import-Module ITGlueAPI -Force
}
If (Get-Module -ListAvailable -Name "ImportExcel") {Import-module ImportExcel} Else { install-module ImportExcel -Force; import-module ImportExcel}
# Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy
Export-ITGlueModuleSettings

# This line allows popup boxes to work
Add-Type -AssemblyName PresentationFramework

# Create the timer variable for use later on in gui's
$global:timer = $null

Write-Host "Successfully imported required modules and configured the ITGlue API."

if ($CheckEmail) {
	# Connect to the mail service (it works better doing this first thing)
	if ($EmailType -eq "O365") {
		Write-Host "Connecting to Office 365..."
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

		If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {
			Import-Module ExchangeOnlineManagement
		} else {
			Install-Module PowerShellGet -Force
			Install-Module -Name ExchangeOnlineManagement
		}
		if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
			Connect-ExchangeOnline -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -AppID $O365UnattendedLogin.AppID -Organization $O365UnattendedLogin.Organization -ShowProgress $true -ShowBanner:$false
		} else {
			Connect-ExchangeOnline -UserPrincipalName $O365LoginUser -ShowProgress $true -ShowBanner:$false
		}

		# If using a version under 1.0.1, upgrade
		$Version = (Get-Module ExchangeOnlineManagement).Version
		if ($Version.Major -lt 1 -or $Version.Built -lt 1) {
			Update-Module -Name ExchangeOnlineManagement
			Import-Module ExchangeOnlineManagement -Force
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
				New-StoredCredential -Comment 'Exchange Server Login (for User Audit)' -Credentials $(Get-Credential -Message "Enter the exchange server login details:") -Target 'ExchangeServer' | Out-Null
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

# Get the organizations name
$OrganizationInfo = (Get-ITGlueOrganizations -id $OrgID).data
$OrgFullName = $OrganizationInfo[0].attributes.name
$OrgShortName = $OrganizationInfo[0].attributes."short-name"

$ContactCount = ($FullContactList | Measure-Object).Count
Write-Host "Got the contact data from IT Glue. $ContactCount contacts were found."

######################
### Pre-Cleanup Checks 
### (this should be done first manually, but lets just make sure that nothing was missed)
######################
$RunPreCleanup = $false
# Check if the billing history folder has files in it, if so, this isn't the first time run so skip this automatically
$historyPath = "C:\billing_history\"
if (!((Test-Path -Path $historyPath) -and (Test-Path -Path ($historyPath+"*")))) {
	$RunPreCleanup = [System.Windows.MessageBox]::Show('Would you like to run some pre-cleanup checks? This will help verify that the contacts have been cleaned up correctly. This cannot check sync status of contacts, please do that manually.', 'Run Pre-Cleanup Checks?', 'YesNo')
}

if ($RunPreCleanup -eq 'Yes') {
	Write-Host "===================================" -ForegroundColor Blue
	Write-Host "Running Pre-Cleanup Checks."

	# Duplicate Locations
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

	# Contacts - find duplicates
	Write-Host "Checking for duplicate contacts."
	$UniqueContacts = $FullContactList.attributes."name" | Select-Object -Unique
	$DuplicateContacts = @()
	if ($UniqueContacts) {
		$DuplicateContacts = Compare-Object -ReferenceObject $UniqueContacts -DifferenceObject $FullContactList.attributes."name"
	}
	$DuplicateIDs = @()

	foreach ($Contact in $DuplicateContacts.InputObject) {
		$DuplicateIDs += ($FullContactList | Where-Object { $_.attributes.name -like $Contact }).id
	}

	if ($DuplicateIDs) {
		$ShowDuplicates = $false
		$ShowDuplicates = [System.Windows.MessageBox]::Show('Duplicate contacts were found in the pre-cleanup check. Would you like to see these duplicates?', 'Duplicate Contacts Found', 'YesNo')

		if ($ShowDuplicates -eq 'Yes') {
			$DupeContactsTable = @()
			foreach ($ID in $DuplicateIDs) {
				$DupeContactsTable += ($FullContactList | Where-Object { $_.id -eq $ID }).attributes | 
					Select-Object Name, @{Name="Contact Type"; E={$_."contact-type-name"}}, Title, @{Name="Location"; E={$_."location-name"}}, 
						@{Name="Primary Email"; E={($_."contact-emails" | Where-Object {$_.primary -eq $true}).value}}, @{Name="Link"; E={$_."resource-url"}}
			}
			$DupeContactsTable | Out-GridView -PassThru -Title "Duplicate Contacts"
		}
	}

	# Contacts - missing emails / phone number
	Write-Host "Checking for contacts without an email or phone number."
	$ContactsNoEmailPhone = $FullContactList | Where-Object { ($_.attributes."contact-emails" | Measure-Object).Count -eq 0 -and ($_.attributes."contact-phones" | Measure-Object).Count -eq 0}

	if ($ContactsNoEmailPhone) {
		$ShowContacts = $false
		$ShowContacts = [System.Windows.MessageBox]::Show('Contacts with no email or phone number were found. Would you like to view them?', 'Contacts Without Email or Phone # Found', 'YesNo')

		if ($ShowContacts -eq 'Yes') {
			$BadContactsTable = @()
			foreach ($Contact in $ContactsNoEmailPhone) {
				$BadContactsTable += $Contact.attributes | 
					Select-Object Name, @{Name="Contact Type"; E={$_."contact-type-name"}}, Title, @{Name="Location"; E={$_."location-name"}}, 
						@{Name="Emails"; E={$_."contact-emails".value}}, @{Name="Phone Numbers"; E={$_."contact-phones"."formatted-value"}}, @{Name="Link"; E={$_."resource-url"}}
			}
			$BadContactsTable | Out-GridView -PassThru -Title "Contacts without Email or Phone #"
		}
	}


	# Contacts - wrong email domain
	Write-Host "Checking for contacts with an incorrect email domain."
	$Domains = (Get-ITGlueDomains -organization_id $OrgID).data
	if ($Domains) {
		$DomainNames = $Domains.attributes.name
		$BadContacts = $FullContactList | Where-Object { 
			$BadContact = $false
			foreach ($ContactEmail in $_.attributes."contact-emails") {
				$Email = $ContactEmail.value
				if (($DomainNames | Where-Object { $Email -like "*"+$_ } | Measure-Object).Count -gt 0) {
					$BadContact = $false
					break
				} else {
					$BadContact = $true
				}
			}

			if ($BadContact) {
				return $true
			} else {
				return $false
			}
		}
		$IgnoreContactTypes = @('Contractor', 'External User', 'Other', 'Service Account', 'Terminated', 'Vendor Support')
		$BadContacts = $BadContacts | Where-Object {$IgnoreContactTypes -notcontains $_.attributes."contact-type-name" }

		if ($BadContacts) {
			$ShowContacts = $false
			$ShowContacts = [System.Windows.MessageBox]::Show('Contacts were found with an incorrect domain. Would you like to view them? Note, if this list is wrong, update the organizations domains in ITG.', 'Contacts Found With Incorrect Email Domain', 'YesNo')
	
			if ($ShowContacts -eq 'Yes') {
				$BadContactsTable = @()
				foreach ($Contact in $BadContacts) {
					$BadContactsTable += $Contact.attributes | 
						Select-Object Name, @{Name="Contact Type"; E={$_."contact-type-name"}}, Title, @{Name="Location"; E={$_."location-name"}}, 
							@{Name="Emails"; E={$_."contact-emails".value}}, @{Name="Link"; E={$_."resource-url"}}
				}
				$BadContactsTable | Out-GridView -PassThru -Title "Contacts Found With Incorrect Email Domain"
			}
		}
	} else {
		Write-Host "No domains were found for this organizations so the script could not check for emails with incorrect domains. Please add all email domains this organization uses to its domains in ITG." -ForegroundColor Red
	}

	Write-Host "Pre-Cleanup Check Complete."

	# Re-get the contact list
	Write-Host "Getting an updated contact list from IT Glue."
	$FullContactList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data
	Write-Host "===================================" -ForegroundColor Blue
}

######################
### Check for bad email/phone types (from integrations)
### Any emails with the type "Email" or phone #s with the type "Office" will not sync to Autotask
######################
Write-Host "Checking for bad email/phone # types..."
$FixContactEmails = @()
$FixContactPhone = @()
foreach ($Contact in $FullContactList) {
	if ($Contact.attributes."contact-type-name" -eq "Terminated") {
		continue;
	}
	if ($Contact.attributes."contact-emails"."label-name" -contains "Email") {
		$FixContactEmails += $Contact
	}
	if ($Contact.attributes."contact-phones"."label-name" -contains "Office") {
		$FixContactPhone += $Contact
	}
}

if (($FixContactEmails | Measure-Object).count -gt 0 -or ($FixContactPhone | Measure-Object).count -gt 0) {
	Write-Host "Bad types found!"
	$FixContacts = @()
	foreach ($Contact in $FixContactEmails) {
		$Issue = "Email"
		if ($Contact.id -in $FixContactPhone.id) {
			$Issue = "Email & Phone"
		}
		$Details = [PsCustomObject]@{
			"id" = $Contact.id
			"name" = $Contact.attributes.name
			"issue" = $Issue
			"link" = $Contact.attributes."resource-url"
		}
		$FixContacts += $Details
	}

	foreach ($Contact in $FixContactPhone) {
		if ($Contact.id -notin $FixContactEmails.id) {
			$Details = [PsCustomObject]@{
				"id" = $Contact.id
				"name" = $Contact.attributes.name
				"issue" = "Phone"
				"link" = $Contact.attributes."resource-url"
			}
			$FixContacts += $Details
		}
	}

	[System.Windows.MessageBox]::Show('Issues with the email or phone type of certain contacts were found. ' +
		'When contacts sync to ITG from O365 they are given the email type "Email" and phone type "Office". These types will not sync through to Autotask. ' +
		'Please change these types to any other option so that the data will sync through to O365.', 'Issues Were Found')

	$FixContacts | Sort-Object -Property issue, name | Out-GridView -PassThru -Title "Please fix the email/phone types on the following accounts:"
	
	# Re-get the contact list
	Write-Host "Getting an updated contact list from IT Glue."
	$FullContactList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data
	Write-Host "===================================" -ForegroundColor Blue
	
} else {
	Write-Host "No issues found."
}


# Get the list of contacts that are considered an employee type
$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
$EmployeeContacts = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $EmployeeContactTypes -or !$_."contact-type-name"}




### Build the Multiple Matches Found form
# Generates a form to allow a user to choose a match when multiple are found
# @param str $Type 'O365' or 'AD'
# @param obj $Contact the IT Glue contact object
# @param arr $FoundMatches an array of found matches (either $ADMatches or $O365Matches)
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

if ($CheckAD) {
	# Get all AD users
	Write-Host "===================================" -ForegroundColor Blue
	Write-Host "Getting AD users for comparison."
	$FullADUsers = Get-ADUser -Filter * -Properties * | 
						Select-Object -Property Name, GivenName, Surname, @{Name="Username"; E={$_.SamAccountName}}, EmailAddress, Enabled, 
										Description, LastLogonDate, @{Name="PrimaryOU"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)')[0].Groups[2]}}, 
										@{Name="OUs"; E={[regex]::matches($_.DistinguishedName, '\b(OU=)([^,]+)').Value -replace 'OU='}}, 
										@{Name="PrimaryCN"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)')[0].Groups[2]}}, 
										@{Name="CNs"; E={[regex]::matches($_.DistinguishedName, '\b(CN=)([^,]+)').Value -replace 'CN='}}, 
										City, Department, Division, Title
	Write-Host "Got AD accounts. Getting associated AD group memberships."
	$i = 0
	$ADUserCount = ($FullADUsers | Measure-Object).Count
	$FullADUsers | ForEach-Object {
		$i++
		$_ | Add-Member -MemberType NoteProperty -Name Groups -Value $null
		$_.Groups = @((Get-ADPrincipalGroupMembership $_.Username | Select-Object Name).Name)
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
		
		# Look for a match
		while (!$ADMatch) {
			# Check notes for a username
			$ADMatch += $ADEmployees | Where-Object { $Notes -match ".*(Username: " + $_.Username + "(\s|W|$)).*" }
			if ($ADMatch) { break; }
			# Primary email search
			if ($PrimaryEmail) {
				$ADMatch += $ADEmployees | Where-Object { $_.EmailAddress -like $PrimaryEmail }
			}
			# First and last name
			$ADMatch += $ADEmployees | Where-Object { $_.GivenName -like $FirstName -and $_.Surname -like $LastName }
			if ($ADMatch) { break; }
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

			# Update the users notes in IT Glue to set the primary username
			$NewUsername = $ADMatch.Username
			$CurrentNotes = (Get-ITGlueContacts -id $User.id).data.attributes[0].notes
			$CurrentNotes = $CurrentNotes.TrimEnd()
			$UserUpdate = 
				@{
					type = "contacts"
					attributes = @{
						notes = $CurrentNotes + "`nUsername: " + $NewUsername
					}	
				}
			Set-ITGlueContacts -id $User.id -data $UserUpdate
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
						# Username was found in AD, update IT Glue notes and move from $NoMatch to $ADMatches
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
						# Email was found in O365, update IT Glue notes and move from $NoO365Match to $O365Matches
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

						$MatchUpdated = buildMatch $ITGlueUser
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

						$MatchUpdated = buildMatch $ITGlueUser
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
					$MatchUpdated = buildMatch $NewContact
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

		# update IT Glue notes and remove from $NoMatch or $Match array
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

$UnmatchedAD = $ADEmployees | Where-Object { $ADMatches.ad.Username -notcontains $_.Username } | Where-Object { $_.Enabled -eq "True" }
if (($UnmatchedAD | Measure-Object).Count -gt 0) {
	Write-Host "Warning! AD accounts found without a match." -ForegroundColor Red
	$UnmatchedAD | Out-GridView -PassThru -Title "Warning! AD accounts found without a match."
}
# Write unmatched to a file so we can see how it has changed in the future
New-Item -ItemType Directory -Force -Path "C:\billing_audit" | Out-Null
$unmatchedJson = $UnmatchedAD | ConvertTo-Json
$matchingPath = "C:\billing_audit\unmatchedAD.json"
$unmatchedJson | Out-File -FilePath $matchingPath
Write-Host "Exported unmatched AD accounts to a json file."


# Check against O365/Exchange
if ($CheckEmail) {
	Write-Host "Getting $EmailType Mailboxes. This may take a minute..." -ForegroundColor 'black' -BackgroundColor 'red'

	# Get the mailbox info and put it all together
	if ($EmailType -eq "O365") {
		$O365Mailboxes = Get-EXOMailbox -ResultSize unlimited -PropertySets Minimum, AddressList, Delivery, SoftDelete | 
			Select-Object -Property Name, DisplayName, Alias, PrimarySmtpAddress, EmailAddresses, 
				RecipientTypeDetails, Guid, UserPrincipalName, 
				DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled |
			Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
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

		# If there are a large amount of mailboxes, give an option to skip getting mailbox statistics as it can be quite slow
		$CheckInactivity = $true
		if (($O365Mailboxes | Measure-Object).Count -gt 150) {
			$ApproxTime = ($O365Mailboxes | Measure-Object).Count * 0.3 # based on my tests it takes roughly 0.3 seconds per mailbox to get the statistics
			if ($ApproxTime -gt 60) {
				$ApproxTime = [Math]::Round(($ApproxTime / 60), 2)
				$ApproxTimeStr = [string]$ApproxTime + " minutes"
			} else {
				$ApproxTimeStr = [string]$ApproxTime + " seconds"
			}
			$GetStats = [System.Windows.MessageBox]::Show("A large amount of mailboxes were found and it will take approximately $ApproxTimeStr to get the statistics for these. This is required to check for inactive mailboxes. Would you like to get the statistics and check for inactive mailboxes?", 'Get Statistics?', 'YesNo')
			if ($GetStats -ne "Yes") { 
				$CheckInactivity = $false
			}
		}

		$LicensePlanList = Get-AzureADSubscribedSku
		$AzureUsers = Get-AzureADUser -All $true | Select-Object UserPrincipalName, AssignedLicenses, GivenName, Surname, JobTitle
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name AssignedLicenses -Value @()
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name PrimaryLicense -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null

		if ($CheckInactivity) {
			$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastUserActionTime -Value $null

			# This fancy bit of code allows us to create a progress bar for getting mailbox statistics. 
			# Due to the way Get-MailboxStatistics runs, we can't actually see how far it is through the process so we break it up into pieces so we know the progress.
			# We also don't just run a foreach on each mailbox alias because it takes significantly longer doing it on a per alias basis. It is much faster in batches.
			$TotalMailboxes = ($O365Mailboxes | Measure-Object).Count
			$BreakPoint = 0
			if ($TotalMailboxes -ge 250) {
				$BreakPoint = 50
			} elseif ($TotalMailboxes -ge 50) {
				$BreakPoint = 25
			} elseif ($TotalMailboxes -gt 25) {
				$BreakPoint = [int][Math]::Ceiling($TotalMailboxes / 2)
			} else {
				$BreakPoint = $TotalMailboxes
			}

			$O365MailboxStats = @()
			$ProgressCount = 0
			$Loops = [int][Math]::Ceiling($TotalMailboxes / $BreakPoint)
			for ($i = 0; $i -lt $Loops; $i++) {
				$StartIndex = $BreakPoint * $i
				$EndIndex = $BreakPoint * ($i + 1) - 1
				$MailboxSubset = $O365Mailboxes[$StartIndex..$EndIndex].Alias

				if ($i -eq 0) {
					$TimeRemaining = [Math]::Round(($TotalMailboxes * 0.3), 2)
					Write-Progress -Activity "Getting Mailbox Statistics" -PercentComplete 1 -SecondsRemaining $TimeRemaining -Status ("Working - 1%")
				}
				$O365MailboxStats += $MailboxSubset | Get-MailboxStatistics | Select-Object DisplayName, LastUserActionTime
				$ProgressCount += $MailboxSubset.Count
				$MailboxesRemaining = $TotalMailboxes - $ProgressCount
				$TimeRemaining = [Math]::Round(($MailboxesRemaining * 0.3), 2)
				[int]$PercentComplete = ($ProgressCount / $TotalMailboxes * 100)
				Write-Progress -Activity "Getting Mailbox Statistics" -PercentComplete $PercentComplete -SecondsRemaining $TimeRemaining -Status ("Working - " + $PercentComplete + "%")
			}
			Write-Progress -Activity "Getting Mailbox Statistics" -Status "Ready" -Completed
			Write-Host "Collected all mailbox statistics."
		}
		
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
				$_.FirstName = $AzureUser.GivenName
				$_.LastName = $AzureUser.Surname
				$_.Title = $AzureUser.JobTitle

				if ($CheckInactivity) {
					$O365MailboxStat = $O365MailboxStats | Where-Object { $_.DisplayName -like $Mailbox.DisplayName }
					$_.LastUserActionTime = $O365MailboxStat.LastUserActionTime
				}
			}
		}
	} else {
		$O365Mailboxes = Get-Mailbox -ResultSize unlimited | 
			Select-Object -Property Name, DisplayName, Alias, PrimarySmtpAddress, EmailAddresses, SamAccountName, 
				RecipientTypeDetails, AccountDisabled, IsDirSynced, Guid,
				DeliverToMailboxAndForward, ForwardingSmtpAddress, ForwardingAddress, HiddenFromAddressListsEnabled |
			Where-Object { $_.RecipientTypeDetails -notlike "DiscoveryMailbox" }
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name FirstName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastName -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name Title -Value $null
		$O365Mailboxes | Add-Member -MemberType NoteProperty -Name LastUserActionTime -Value $null
		$O365MailboxUsers =  Get-User -ResultSize unlimited | Select-Object Name, FirstName, LastName, Title
		Write-Host "Collecting mailbox statistics."
		$O365MailboxStats = Get-Mailbox -ResultSize unlimited | Get-MailboxStatistics | Select-Object DisplayName, LastLogonTime 
		Write-Host "Collected all mailbox statistics."
		$CheckInactivity = $true

		for ($i = 0; $i -lt $O365Mailboxes.Count; $i++) {
			$O365MailboxUser = $O365MailboxUsers | Where-Object { $_.Name -like $O365Mailboxes[$i].Name }
			$O365Mailboxes[$i].FirstName = $O365MailboxUser.FirstName
			$O365Mailboxes[$i].LastName = $O365MailboxUser.LastName
			$O365Mailboxes[$i].Title = $O365MailboxUser.Title
			$O365MailboxStat = $O365MailboxStats | Where-Object { $_.DisplayName -like $O365Mailboxes[$i].DisplayName }
			$O365Mailboxes[$i].LastUserActionTime = $O365MailboxStat.LastLogonTime
		}
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
			$O365Matches.Add($match) | Out-Null
		} else {
			if ($Type -ne 'Terminated' -and $Type -ne "Employee - On Leave" -and $User.ID -in $EmployeeContacts.id) {
				$NoO365Match += $User
			}
		}
	}
	$O365MatchCount = ($O365Matches | Measure-Object).Count
	Write-Host "Finished matching all IT Glue contacts to their email accounts. $O365MatchCount matches were made."
	
	# Display a no match form for the O365 checked results
	if ($NoO365Match) {
		NoMatchForm('O365')
	}

	# Display a warning with any licensed O365 accounts that don't have an IT Glue match
	if ($EmailType -eq "O365") {
		$UnmatchedO365 = $O365Mailboxes | Where-Object { $O365Matches.o365.PrimarySmtpAddress -notcontains $_.PrimarySmtpAddress } | Where-Object { ($_.AssignedLicenses | Measure-Object).Count -gt 0 }
		if (($UnmatchedO365 | Measure-Object).Count -gt 0) {
			Write-Host "Warning! O365 accounts found without a match." -ForegroundColor Red
			$UnmatchedO365 | Out-GridView -PassThru -Title "Warning! O365 accounts found without a match."
		}
	}

	# Write unmatched to a file so we can see how it has changed in the future
	New-Item -ItemType Directory -Force -Path "C:\billing_audit" | Out-Null
	$unmatchedJson = $UnmatchedO365 | ConvertTo-Json
	$matchingPath = "C:\billing_audit\unmatchedO365.json"
	$unmatchedJson | Out-File -FilePath $matchingPath
	Write-Host "Exported unmatched O365 accounts to a json file."
}

######################
### Display a list of all the matches that were made
### Allow a staff member to override any matches

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

# Add indicators to $FullMatches for names that don't match exactly to make the AD & O365 Matches form easier to navigate
foreach ($Match in $FullMatches) {
	$NameParts = $Match."ITG-Name".split(' ')
	$SimilarName = $true
	foreach ($part in $NameParts) {
		if (($Match."AD-Name" -and $Match."AD-Name" -notlike "*$part*") -or ($Match."O365-Name" -and $Match."O365-Name" -notlike "*$part*")) {
			$SimilarName = $false
			break
		}
	}

	$Match | Add-Member -MemberType NoteProperty -Name "Discrepancy" -Value ""
	if (!$SimilarName) {
		$Match.Discrepancy = ">>"
	} elseif (($Match."AD-Name" -and $Match."AD-Name" -notlike "*"+$Match."ITG-Name"+"*") -or ($Match."O365-Name" -and $Match."O365-Name" -notlike "*"+$Match."ITG-Name"+"*")) {
		$Match.Discrepancy = "--"
	} elseif ($Match."AD-Name" -and $Match."ITG-Name" -notlike "*"+$Match."AD-Name"+"*") {
		$Match.Discrepancy = "=="
	}
}

[System.Windows.MessageBox]::Show('All matches have now been made. The next window will show you those matches. If there are any you want to change, select them from the list (Ctrl + Click for multiple), then click OK. Otherwise, click Cancel.
	' + [Convert]::ToChar(10) + '
	The left-hand column will help guide you to discrepancies.
	Legend:
	>> ITG Name has a major difference with AD or Email
	-- ITG Name has a slight difference with AD or Email
	== AD Name is similar to ITG but has extra text', 
	"Matches Found")
$ChangeMatches = $FullMatches | 
	Select-Object Discrepancy, id, ITG-Name, Type, Title, Location, @{Name="ITG-Emails"; E={$_."ITG-Emails".value}}, AD-Connected?, AD-Name, AD-Username, AD-Email, O365-Connected?, O365-Name, O365-Emails, ITG-URL, ITG-Notes |
	Sort-Object -Property @{Expression="AD-Connected?"; Descending=$true}, @{Expression="O365-Connected?"; Descending=$true}, "ITG-Name" |
	Out-GridView -PassThru -Title 'AD & O365 Matches'

if ($ChangeMatches) {
	$ChangeMatches = $FullMatches | Where-Object { $ChangeMatches.ID -contains $_.ID } |
		Select-Object id, @{Name='Name';E={$_."ITG-Name"}}, Title, @{Name='contact-type-name';E={$_."Type"}}, @{Name='location-name';E={$_."Location"}},
			@{Name='contact-emails';E={$_."ITG-Emails"}}, @{Name='resource-url';E={$_."ITG-URL"}}, @{Name='notes';E={$_."ITG-Notes"}}
	NoMatchForm('ChangeMatches')
}
Write-Host "===================================" -ForegroundColor Blue

# If this is the first time running the script, suggest restarting it
$FirstTimeRun = $false
$historyPath = "C:\billing_history\"
if (!((Test-Path -Path $historyPath) -and (Test-Path -Path ($historyPath+"*")))) {
	$FirstTimeRun = [System.Windows.MessageBox]::Show('It looks like you are currently setting up this script. If you just made large changes to users including editing/deleting accounts in IT Glue, you will want to restart this script. Would you like to continue? (No to end the script.)', 'Continue?', 'YesNo')
	if ($FirstTimeRun -eq "No") {
		exit
	}
}

Write-Host "All matches between IT Glue, AD, and the email system have now been made. Audit commencing."

# Write matches to a file so that we can quickly match in the future for the billing update script
New-Item -ItemType Directory -Force -Path "C:\billing_audit" | Out-Null
$matchingJson = $FullMatches | ConvertTo-Json
$matchingPath = "C:\billing_audit\contacts.json"
$matchingJson | Out-File -FilePath $matchingPath
Write-Host "Exported a contact matching json file."


#############################################
##### Matches Made. Find Discrepancies. #####
#############################################

if ($FullMatches) {
	$WarnContacts = New-Object -TypeName "System.Collections.ArrayList"

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
				if ($EmailOnlyHaveAD -and $HasEmail -and $EmailEnabled -and $O365Match.o365.RecipientTypeDetails -like 'UserMailbox' -and $ADMatch.PSObject.Properties.Name -contains "Groups") {
					$EmployeeGroups = @()
					foreach ($Group in $ADMatch.Groups) {
						if (($EmailOnlyGroupsIgnore | ForEach-Object{$Group -like $_}) -notcontains $true ) {
							$EmployeeGroups += $Group
						}
					}
					if (($EmployeeGroups | Measure-Object).Count -eq 0) {
						$EmailOnly = $true
					}
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
				} elseif ((!$ADMatch.LastLogonDate -or $ADMatch.LastLogonDate -lt (Get-Date).AddDays(-150)) -and (!$EmailOnlyHaveAD -or ($ContactType -notlike "Employee - Email Only" -and !$EmailOnly)) -and $ContactType -ne "Employee - On Leave" -and 'MaybeTerminate' -notin $IgnoreWarnings -and !$InactivityO365Preference) {
					# MaybeTerminate
					$WarnObj.type = "MaybeTerminate"
					$WarnObj.reason = "AD Account Unused. Maybe disable it? Please review. (Last login > 150 days ago.)"
					# If $InactivityO365Preference is $true, this gets skipped and will only be checked in the O365 section if the O365 account is inactive
				} elseif ($ContactType -eq 'Terminated' -and 'ToEnabled' -notin $IgnoreWarnings) {
					# ToEnabled
					$WarnObj.type = "ToEnabled"
					$WarnObj.reason = "AD Account Enabled. IT Glue Contact should not be 'Terminated'."
				} elseif ($ContactType -notlike "Employee - Part Time" -and ($ADMatch.Description -like "*part?time*" -or $ADMatch.Description -like "*casual*" -or
							$ADMatch.Title -like "*part?time*" -or $ADMatch.Title -like "*casual*") -and !$EmailOnly -and 'ToEmployeePartTime' -notin $IgnoreWarnings) {
					# ToEmployeePartTime
					$WarnObj.type = "ToEmployeePartTime"
					$WarnObj.reason = "AD account appears to be part time. Consider changing the IT Glue Contact type to 'Employee - Part Time'."
				} elseif ($ContactType -notlike "Contractor" -and ($ADMatch.Description -like "*contract*" -or $ADMatch.Title -like "*contract*") -and !$EmailOnly -and 'ToContractor' -notin $IgnoreWarnings) {
					# ToContractor
					$WarnObj.type = "ToContractor"
					$WarnObj.reason = "AD account appears to be a contractor. Consider changing the IT Glue Contact type to 'Contractor'."
				} elseif ($ContactType -notlike "Employee - Temporary" -and $ContactType -ne "Employee - On Leave" -and ($ADMatch.Description -like "*seasonal*" -or $ADMatch.Description -like "*temporary*" -or 
							$ADMatch.Title -like "*seasonal*" -or $ADMatch.Title -like "*temporary*") -and !$EmailOnly -and 'ToTemporary' -notin $IgnoreWarnings) {
					# ToTemporary
					$WarnObj.type = "ToTemporary"
					$WarnObj.reason = "AD account appears to be a temporary or seasonal employee. Consider changing the IT Glue Contact type to 'Employee - Temporary'."
				} elseif ($ContactType -notlike "Vendor" -and ($ADMatch.Description -like "*vendor*" -or $ADMatch.Description -like "*support*" -or
							$ADMatch.Title -like "*vendor*" -or $ADMatch.Title -like "*support*") -and 'ToVendor' -notin $IgnoreWarnings) {
					# ToVendor
					$WarnObj.type = "ToVendor"
					$WarnObj.reason = "AD account appears to be a vendor account. Consider changing the IT Glue Contact type to 'Vendor Support'."
					# TODO: Also check the Vendor's in it glue and search for names in AD that match the vendor names, or for contacts that are related items on vendors
				} elseif ($ContactType -notlike "Employee - Email Only" -and $EmailOnly -and 'ToEmailOnly' -notin $IgnoreWarnings) {
					#ToEmailOnly
					$WarnObj.type = "ToEmailOnly"
					$WarnObj.reason = "AD account has no groups but an email account is setup. Consider changing the IT Glue Contact type to 'Employee - Email Only'."
				} elseif (!$ContactType) {
					#ToEmployee
					$WarnObj.type = "ToEmployee"
					$WarnObj.reason = "AD account appears to be a regular employee. Consider changing the IT Glue Contact type to 'Employee'."
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
				if (!$HasAD -and $CheckAD -and $ContactType -ne 'Terminated') {
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
			if ($EmailOnlyHaveAD -and $HasAD -and $ADEnabled -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and $ADMatch.ad.PSObject.Properties.Name -contains "Groups") {
				$EmployeeGroups = @()
				foreach ($Group in $ADMatch.ad.Groups) {
					if (($EmailOnlyGroupsIgnore | ForEach-Object{$Group -like $_}) -notcontains $true ) {
						$EmployeeGroups += $Group
					}
				}
				if (($EmployeeGroups | Measure-Object).Count -eq 0) {
					$EmailOnly = $true
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
			} elseif ($CheckInactivity -and $ContactType -ne 'Terminated' -and (($O365Match.LastUserActionTime -and $O365Match.LastUserActionTime -lt (Get-Date).AddDays(-150)) -or !$O365Match.LastUserActionTime) -and ($O365Match.RecipientTypeDetails -like 'UserMailbox' -or $O365Match.RecipientTypeDetails -like 'None') -and $ContactType -ne "Employee - On Leave" -and 'MaybeTerminate' -notin $IgnoreWarnings) {
				# MaybeTerminate
				$WarnObj.type = "MaybeTerminate"
				$WarnObj.reason = "$EmailType Account Unused. Maybe disable it? Please review. (Last login > 150 days ago.)"
			} elseif ($InactivityO365Preference -and $CheckInactivity -and $ContactType -ne 'Terminated' -and $HasAD -and (!$ADEnabled -or ($ADMatch.ad.LastLogonDate -and $ADMatch.ad.LastLogonDate -lt (Get-Date).AddDays(-150))) -and (($O365Match.LastUserActionTime -and $O365Match.LastUserActionTime -lt (Get-Date).AddDays(-150)) -or !$O365Match.LastUserActionTime) -and $ContactType -ne "Employee - On Leave" -and 'MaybeTerminate' -notin $IgnoreWarnings) {
				# MaybeTerminate
				$WarnObj.type = "MaybeTerminate"
				$WarnObj.reason = "$EmailType Account and associated AD Account are Unused. Maybe disable them? Please review. (Last login > 150 days ago.)"
			} elseif ($O365Match.RecipientTypeDetails -like 'SharedMailbox' -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and $O365Match.DisplayName -like "*" + $Contact."last-name" + "*" -and 'MaybeTerminate' -notin $IgnoreWarnings) {
				# MaybeTerminate
				$WarnObj.type = "MaybeTerminate"
				$WarnObj.reason = "$EmailType Account is a Shared Mailbox and appears to be a terminated account. Consider changing the IT Glue type to 'Terminated'."
			} elseif ($O365Match.DeliverToMailboxAndForward -eq $false -and $ContactType -ne 'Terminated' -and $ContactType -ne 'Employee - On Leave' -and ($O365Match.ForwardingSmtpAddress -or $O365Match.ForwardingAddress) -and $ContactType -ne "Employee - On Leave" -and 'MaybeTerminate' -notin $IgnoreWarnings -and 'MaybeTerminate[Forwarding]' -notin $IgnoreWarnings) {
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
			} elseif ($ContactType -notlike "Internal / Shared Mailbox" -and $ContactType -ne 'Terminated' -and $O365Match.RecipientTypeDetails -notlike 'UserMailbox' -and $O365Match.RecipientTypeDetails -notlike 'None' -and 'ToSharedMailbox' -notin $IgnoreWarnings) {
				# ToSharedMailbox
				$WarnObj.type = "ToSharedMailbox"
				$WarnObj.reason = "$EmailType account appears to be a shared mailbox. Consider changing the IT Glue Contact type to 'Internal / Shared Mailbox'."
			} elseif ($ContactType -notlike "Employee - Email Only" -and $ContactType -notlike "External User" -and $ContactType -notlike "Internal / Shared Mailbox" -and $CheckAD -and (!$HasAD -or $EmailOnly) -and $O365Match.RecipientTypeDetails -like 'UserMailbox' -and 'ToEmailOnly' -notin $IgnoreWarnings) {
				# ToEmailOnly
				$WarnObj.type = "ToEmailOnly"
				if ($EmailOnly) {
					$WarnObj.reason = "$EmailType account has an associated AD account but it appears to be email-only. Consider changing the IT Glue Contact type to 'Employee - Email Only'. Alternatively: 'External User' or 'Internal / Shared Mailbox'."
				} else {	
					$WarnObj.reason = "$EmailType account has no associated AD account. Consider changing the IT Glue Contact type to 'Employee - Email Only'. Alternatively: 'External User' or 'Internal / Shared Mailbox'."
				}
			} elseif ($ContactType -notlike "Employee - Part Time" -and $ContactType -notlike "Employee - Email Only" -and 
						($O365Match.DisplayName -like "*part?time*" -or $O365Match.DisplayName -like "*casual*" -or
						$O365Match.Title -like "*part?time*" -or $O365Match.Title -like "*casual*") -and 'ToEmployeePartTime' -notin $IgnoreWarnings) {
				# ToEmployeePartTime
				$WarnObj.type = "ToEmployeePartTime"
				$WarnObj.reason = "$EmailType account appears to be part time. Consider changing the IT Glue Contact type to 'Employee - Part Time'."
			} elseif ($ContactType -notlike "Contractor" -and $ContactType -notlike "Employee - Email Only" -and 
						($O365Match.DisplayName -like "*contract*" -or $O365Match.Title -like "*contract*") -and 'ToContractor' -notin $IgnoreWarnings) {
				# ToContractor
				$WarnObj.type = "ToContractor"
				$WarnObj.reason = "$EmailType account appears to be a contractor. Consider changing the IT Glue Contact type to 'Contractor'."
			} elseif ($ContactType -notlike "Employee - Temporary" -and $ContactType -ne "Employee - On Leave" -and $ContactType -notlike "Employee - Email Only" -and 
						($O365Match.DisplayName -like "*seasonal*" -or $O365Match.DisplayName -like "*temporary*" -or 
						$O365Match.Title -like "*seasonal*" -or $O365Match.Title -like "*temporary*") -and 'ToTemporary' -notin $IgnoreWarnings) {
				# ToTemporary
				$WarnObj.type = "ToTemporary"
				$WarnObj.reason = "$EmailType account appears to be a temporary or seasonal employee. Consider changing the IT Glue Contact type to 'Employee - Temporary'."
			}

			if ($WarnObj.type) {
				$Existing = $WarnContacts | Where-Object { $_.id -eq $MatchID }
				if (!$Existing -or ($Existing -and $Existing.type -notlike $WarnObj.type)) {
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

				if ($WarnObj.type -like "ToTerminated" -or $WarnObj.type -like "ImproperlyTerminated" -or $WarnObj.type -like "MaybeTerminate*") {
					# If O365 was given preference when checking inactivity, now check if the AD account is inactive since the O365 account looks like it should be or is terminated
					if ($InactivityO365Preference -and $HasAD -and $ADEnabled) {
						$ADMatch = ($ADMatches | Where-Object { $_.ID -eq $MatchID }).ad
						if ($ADMatch.LastLogonDate -and $ADMatch.LastLogonDate -lt (Get-Date).AddDays(-150) -and 'MaybeTerminate' -notin $IgnoreWarnings) {
							$ADWarnObj = @{
								id = $MatchID
								category = 'AD'
								type = "MaybeTerminate"
								reason = "AD Account Unused. Maybe disable it? Please review. (Last login > 150 days ago.)"
								name = $Contact.name
							}
							$WarnContacts.Add($ADWarnObj) | Out-Null
						}
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
			} elseif ($ContactType -notlike "Employee - Part Time" -and ($Contact.notes -like "*part?time*" -or $Contact.notes -like "*casual*" -or
						$Contact.title -like "*part?time*" -or $Contact.title -like "*casual*") -and 'ToEmployeePartTime' -notin $IgnoreWarnings) {
				# ToEmployeePartTime
				$WarnObj.type = "ToEmployeePartTime"
				$WarnObj.reason = "ITG account appears to be part time. Consider changing the IT Glue Contact type to 'Employee - Part Time'."
			} elseif ($ContactType -notlike "Contractor" -and ($Contact.notes -like "*contract*" -or $Contact.title -like "*contract*") -and 'ToContractor' -notin $IgnoreWarnings) {
				# ToContractor
				$WarnObj.type = "ToContractor"
				$WarnObj.reason = "ITG account appears to be a contractor. Consider changing the IT Glue Contact type to 'Contractor'."
			} elseif ($ContactType -notlike "Employee - Temporary" -and $ContactType -ne 'Employee - On Leave' -and ($Contact.notes -like "*seasonal*" -or $Contact.notes -like "*temporary*" -or
						$Contact.title -like "*seasonal*" -or $Contact.title -like "*temporary*") -and 'ToTemporary' -notin $IgnoreWarnings) {
				# ToTemporary
				$WarnObj.type = "ToTemporary"
				$WarnObj.reason = "ITG account appears to be a temporary or seasonal employee. Consider changing the IT Glue Contact type to 'Employee - Temporary'."
			} elseif ($ContactType -notlike "Vendor" -and ($Contact.notes -like "*vendor*" -or $Contact.notes -like "*support*" -or
						$Contact.title -like "*vendor*" -or $Contact.title -like "*support*") -and 'ToVendor' -notin $IgnoreWarnings) {
				# ToVendor
				$WarnObj.type = "ToVendor"
				$WarnObj.reason = "ITG account appears to be a vendor account. Consider changing the IT Glue Contact type to 'Vendor Support'."
			} elseif (!$ContactType) {
				#ToUnknown
				$WarnObj.type = "ToUnknown"
				$WarnObj.reason = "ITG account has no contact type but no suggestion could be made. Please fix the type manually."
			}

			if ($WarnObj.type){
				$WarnContacts.Add($WarnObj) | Out-Null
			}
		}
	}

	$WarnCount = ($WarnContacts | Measure-Object).Count
	Write-Host "Audit complete. $($WarnCount) issues have been found."

	if ($WarnCount -gt 0) {
		$WarnContacts = $WarnContacts | Sort-Object @{Expression={$_.type}}, @{Expression={$_.category}}, @{Expression={$_.name}}

		# Create a form to display the warnings
		Add-Type -AssemblyName System.Windows.Forms
		[System.Windows.Forms.Application]::EnableVisualStyles()

		$warningsForm                    = New-Object system.Windows.Forms.Form
		$warningsForm.ClientSize         = New-Object System.Drawing.Point(800,400)
		$warningsForm.text               = "Warnings / Suggestions for Contacts"
		$warningsForm.TopMost            = $false

		$Label1                          = New-Object system.Windows.Forms.Label
		$Label1.text                     = "Warnings and Suggestions:"
		$Label1.AutoSize                 = $true
		$Label1.width                    = 25
		$Label1.height                   = 10
		$Label1.location                 = New-Object System.Drawing.Point(11,13)
		$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$warningsGrid                    = New-Object system.Windows.Forms.DataGridView
		$warningsGrid.width              = 772
		$warningsGrid.height             = 306
		$warningsGrid.ColumnCount = 9
		$warningsGrid.ColumnHeadersVisible = $true
		$warningsGrid.Columns[0].Name = "ID"
		$warningsGrid.Columns[0].Visible = $false
		$warningsGrid.Columns[1].Name = "Name"
		$warningsGrid.Columns[2].Name = "Type"
		$warningsGrid.Columns[3].Name = "AD Username"
		$warningsGrid.Columns[4].Name = "O365 Email"
		$warningsGrid.Columns[5].Name = "Suggestion Type"
		$warningsGrid.Columns[6].Name = "Suggestion Category"
		$warningsGrid.Columns[7].Name = "Suggestion"
		$warningsGrid.Columns[8].Name = "ITG Link"

		$csvTable = @()
		foreach ($Warnings in $WarnContacts){
			$FullMatchID = $Warnings.id
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

			$properties = [ordered]@{
				"ID" = $null
				"Name" = $null
				"Type" = $null
				"AD-Username" = $null
				"O365-Email" = $null
				"Suggestion-Type" = $null
				"Suggestion-Category" = $null
				"Suggestion" = $null
				"ITG-Link" = $null
			}
			$csvRow = New-Object PSObject -Property $properties

			$Row = @('', '', '', '', '', '', '', '', '')
			$Row[0] = $csvRow.ID = $ContactID
			$Row[1] = $csvRow.Name = $Contact.name
			$Row[2] = $csvRow.Type = $Contact."contact-type-name"
			$Row[3] = $csvRow."AD-Username" = $ADUsername
			$Row[4] = $csvRow."O365-Email" = $O365Email
			$Row[5] = $csvRow."Suggestion-Type" = $Warnings.type
			$Row[6] = $csvRow."Suggestion-Category" = $Warnings.category
			$Row[7] = $csvRow.Suggestion = $Warnings.reason
			$Row[8] = $csvRow."ITG-Link" = $Contact."resource-url"

			$warningsGrid.Rows.Add($Row) | Out-Null
			$csvTable += $csvRow
		}

		$warningsGrid.Anchor             = 'top,right,bottom,left'
		$warningsGrid.location           = New-Object System.Drawing.Point(13,37)

		$exportCSVBtn                  = New-Object system.Windows.Forms.Button
		$exportCSVBtn.text             = "Export List to CSV"
		$exportCSVBtn.width            = 165
		$exportCSVBtn.height           = 30
		$exportCSVBtn.Anchor           = 'bottom,left'
		$exportCSVBtn.location         = New-Object System.Drawing.Point(11,360)
		$exportCSVBtn.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$continueBtn                     = New-Object system.Windows.Forms.Button
		$continueBtn.text                = "Continue"
		$continueBtn.width               = 105
		$continueBtn.height              = 30
		$continueBtn.Anchor              = 'right,bottom'
		$continueBtn.location            = New-Object System.Drawing.Point(679,360)
		$continueBtn.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$ignoreWarningBtn                = New-Object system.Windows.Forms.Button
		$ignoreWarningBtn.text           = "Ignore Warning"
		$ignoreWarningBtn.width          = 134
		$ignoreWarningBtn.height         = 30
		$ignoreWarningBtn.Anchor         = 'right,bottom'
		$ignoreWarningBtn.location       = New-Object System.Drawing.Point(527,360)
		$ignoreWarningBtn.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$warningsForm.controls.AddRange(@($Label1,$warningsGrid,$exportCSVBtn,$continueBtn,$ignoreWarningBtn))

		# Allow url links to be clickable
		$warningsGrid.Add_CellMouseDoubleClick({
			$ColumnIndex = $warningsGrid.CurrentCell.ColumnIndex
			$ColumnValue = $warningsGrid.CurrentCell.Value

			# verify they clicked on a URL, if so, launch it
			if ($ColumnIndex -eq 8 -and ($ColumnValue -as [System.URI]).AbsoluteURI -ne $null) {
				Start-Process $ColumnValue
			}
		})

		$exportCSVBtn.Add_Click({ 
			$Path = $PSScriptRoot + "\ITG_Contact_Change_Suggestions.csv"
			$csvTable | Export-Csv -Path $Path -NoTypeInformation
			[System.Windows.MessageBox]::Show('CSV Exported. You can find it at: ' + $Path)
		})

		$ignoreWarningBtn.Add_Click({
			$SelectedID = 0
			if ($warningsGrid.CurrentRow) {
				$SelectedID = $warningsGrid.CurrentRow.Cells['ID'].Value
				$SelectedType = $warningsGrid.CurrentRow.Cells[5].Value
				$SelectedCategory = $warningsGrid.CurrentRow.Cells[6].Value
			}
			if ($SelectedID -and $SelectedID -ge 0) {
				$SelectedRowID = $warningsGrid.CurrentCell.RowIndex

				# update IT Glue notes and remove from warnings array
				$CurrentNotes = (Get-ITGlueContacts -id $SelectedID).data.attributes[0].notes
				$CurrentNotes = $CurrentNotes.TrimEnd()
				$NewNotes = $CurrentNotes + "`n# Ignore " + $SelectedType + " Warnings"
				$UserUpdate = 
					@{
						type = "contacts"
						attributes = @{
							notes = $NewNotes
						}	
					}

				Set-ITGlueContacts -id $SelectedID -data $UserUpdate

				$script:WarnContacts = [System.Collections.ArrayList] ($script:WarnContacts | Where-Object { $_.ID -ne $SelectedID -and $_.type -ne $SelectedType -and $_.category -ne $SelectedCategory })
				$warningsGrid.Rows.RemoveAt($SelectedRowID)
			}
		})

		$continueBtn.Add_Click({
			[void]$warningsForm.Close()
		})

		[void]$warningsForm.ShowDialog()
	}
}

# Re-get the contact list (since we likely just updated the types)
Write-Host "Getting an updated contact list from IT Glue."
$FullContactList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data
$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
$EmployeeContacts = $FullContactList.attributes | Where-Object {$_."contact-type-name" -in $EmployeeContactTypes -or !$_."contact-type-name"}

Write-Host "===================================" -ForegroundColor Blue

# Export a csv into the billing history folder (overwrite if same month)
New-Item -ItemType Directory -Force -Path "C:\billing_history" | Out-Null
$Month = Get-Date -Format "MM"
$Year = Get-Date -Format "yyyy"
$historyContacts = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data | ConvertTo-Json
$historyPath = "C:\billing_history\contacts_$($Month)_$($Year).json"
$historyContacts | Out-File -FilePath $historyPath
Write-Host "Exported a billing history file."

$ExportChoice = $false
$ExportChoice = [System.Windows.MessageBox]::Show('Would you like to export the full user list showing matched AD/O365 accounts?', 'Export Matched User List', 'YesNo')

if ($ExportChoice -eq 'Yes') {
	# Export matched user list to CSV
	$csvTable = @()
	foreach ($Match in $FullMatches) {
		$MatchID = $Match.id
		$Contact = $EmployeeContacts | Where-Object { $_.ID -eq $MatchID }

		$properties = [ordered]@{
			"ID" = $Contact.id
			"Name" = $Contact.name
			"Type" = $Contact."contact-type-name"
			"Location" = $Contact."location-name"
			"Has AD?" = $false
			"AD Name" = $null
			"AD Username" = $null
			"Has O365?" = $false
			"O365 Name" = $null
			"O365 Email" = $null
			"O365 License" = $null
			"ITG Link" = $Contact."resource-url"
		}
		$csvRow = New-Object PSObject -Property $properties

		if ($CheckAD) {
			$ADMatch = ($ADMatches | Where-Object { $_.ID -eq $MatchID }).ad
			if ($ADMatch) {
				$csvRow."Has AD?" = $true
				$csvRow."AD Name" = $ADMatch.Name
				$csvRow."AD Username" = $ADMatch.Username
			}
		}
		if ($CheckEmail) {
			$O365Match = ($O365Matches | Where-Object { $_.ID -eq $MatchID }).o365
			if ($O365Match) {
				$csvRow."Has O365?" = $true
				$csvRow."O365 Name" = $O365Match.DisplayName
				$csvRow."O365 Email" = $O365Match.PrimarySmtpAddress
				if ($O365Match.PrimaryLicense) {
					$csvRow."O365 License" = $O365Match.PrimaryLicense
				}
			}
		}

		$csvTable += $csvRow
	}

	$csvTable = $csvTable | Sort-Object "Has AD?", "Has O365?", Type, Location, Name -Descending
	$Path =  $PSScriptRoot + "\$($OrgShortName)_Matched_User_List.csv"
	$csvTable | Export-Csv -Path $Path -NoTypeInformation
	[System.Windows.MessageBox]::Show('CSV Exported. You can find it at: ' + $Path)
	Write-Host "Exported the full matched user list." -ForegroundColor Green

	# TODO: Upload to ITG
}

$O365AuditChoice = $false
$O365AuditChoice = [System.Windows.MessageBox]::Show('Would you like to run an audit of Office 365 licenses?', 'Audit Office 365 Licenses', 'YesNo')

if ($O365AuditChoice -eq 'Yes') {
	Write-Host "This option is not available yet. Skipping." -ForegroundColor Red
}

$ExportChoice = $false
$ExportChoice = [System.Windows.MessageBox]::Show('Would you like to export the user list for billing purposes?', 'Export Billing User List', 'YesNo')

if ($ExportChoice -eq 'Yes') {
	# Export billing user list to CSV
	Write-Host "Generating billing report..."

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
	$historyPath = "C:\billing_history\contacts_$($LastMonth)_$($LastYear).json"
	if (Test-Path $historyPath) {
		$CheckChanges = $true
		$HistoryContactList = Get-Content -Path $historyPath -Raw | ConvertFrom-Json
	}

	# Get a fresh list of contacts from IT Glue
	$FullContactList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data
	$FullContactList.attributes | Add-Member -MemberType NoteProperty -Name ID -Value $null
	$FullContactList | ForEach-Object { $_.attributes.id = $_.id }
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
	Add-ExcelTable -PassThru -Range $ws.Cells["A4:C$($totalsTblLastRow)"] -TableName Totals -TableStyle "Light21" -ShowFilter:$false -ShowTotal -ShowFirstColumn -TotalSettings @{"Billed" = "Sum"; "Unbilled" = "Sum"} | Out-Null
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
		Add-ExcelTable -PassThru -Range $ws.Cells["A$($totalsByLocFirstRow):C$($totalsTblLastRow)"] -TableName TotalsByLoc -TableStyle "Light21" -ShowFilter:$false -ShowTotal -ShowFirstColumn -TotalSettings @{"Billed" = "Sum"; "Unbilled" = "Sum"} | Out-Null
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

	# Give the option to upload to ITG. This will update the Service Agreement asset and attach the billing report (removing any old version from the same month).
	$UpdateITGChoice = $false
	$UpdateITGChoice = [System.Windows.MessageBox]::Show('Would you like to update the Service Agreement in IT Glue and upload a copy of the billing report?', 'Update IT Glue', 'YesNo')

	if ($UpdateITGChoice -eq 'Yes') {
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

		if ($TotalsByLocation) {
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
						<th>$($_.Location)</th>
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
					if ($_.name -eq "billing-report-user-list") {
						return
					}
					$property = $_.name
					$FlexAssetBody.attributes.traits.$property = $_.value
				}
			}

			# Add the new data to be uploaded
			$FlexAssetBody.attributes.traits."number-of-billed-users" = $TotalBilled
			$FlexAssetBody.attributes.traits."user-breakdown" = $UserBreakdownTable
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
			} else {
				$FlexAssetBody.attributes."organization-id" = $OrgID
				$FlexAssetBody.attributes."flexible-asset-type-id" = $FilterID.id
				$FlexAssetBody.attributes.traits."billed-by" = "User"
				$ExistingFlexAsset = New-ITGlueFlexibleAssets -data $FlexAssetBody
				Write-Host "Uploaded a new $FlexAssetName asset."
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
			}
			
		} else {
			Write-Host "Something went wrong when trying to find the $FlexAssetName asset type. Could not update IT Glue." -ForegroundColor Red
		}

		#  Export an Office 365 license report
		if ($CheckEmail -and $EmailType -eq "O365") {
			Write-Host "Exporting Office 365 license report..."
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
			New-Item -ItemType Directory -Force -Path ($PSScriptRoot + "\O365LicenseOverview")
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
			}
		}
	}
	Write-Host "User Audit Complete!" -ForegroundColor Black -BackgroundColor Green
	Read-Host "Press ENTER to close..." 
}
