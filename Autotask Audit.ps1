# Install-ModuleFromGitHub -GitHubRepo chrisjantzen/AutotaskAPI -Branch master -moduleName AutotaskAPI
Import-Module AutotaskAPI
Add-Type -AssemblyName PresentationFramework
$Autotask_CompanyID = "<Autotask Company ID>"
$AutotaskZoneID = "<Autotask Zone ID>"
$DuplicatesOnEmails = $true
Write-Host "Started the Autotask cleanup."

# $Creds = get-credential -Credential 
$Username = "<Autotask API Username>"
$Password = ConvertTo-SecureString -String '<Autotask API Password>' -AsPlainText -Force
$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password
Add-AutotaskAPIAuth -ApiIntegrationcode '<Autotask API Integration Code>' -credentials $Creds

# Get locations, contacts, and countries
$Autotask_Locations = Get-AutotaskAPIResource -Resource CompanyLocations -SimpleSearch "CompanyID eq $Autotask_CompanyID" | Where-Object { $_.isActive -eq "True" }
$Autotask_Contacts = Get-AutotaskAPIResource -Resource Contacts -SimpleSearch "CompanyID eq $Autotask_CompanyID" | Where-Object { $_.isActive -eq 1 }
$Autotask_CountryIDs = @()
$Autotask_CountryIDs += ($Autotask_Contacts.countryID | Sort-Object -Unique)
$Autotask_CountryIDs += $Autotask_Locations.countryID
$Autotask_CountryIDs = $Autotask_CountryIDs | Sort-Object -Unique

$Autotask_CountriesLookup = @{}
foreach ($countryID in $Autotask_CountryIDs) {
	$Autotask_CountriesLookup[$countryID] = (Get-AutotaskAPIResource -Resource Countries -SimpleSearch "Id eq $countryID")[0].DisplayName
}
$Autotask_Locations | Add-Member -MemberType NoteProperty -Name country -value $null
$Autotask_Locations | ForEach-Object { $_.country = $Autotask_CountriesLookup[$_.countryID] }

# Multiple active locations, let user cull some
if (($Autotask_Locations | Measure-Object).Count -gt 1) {
	[System.Windows.MessageBox]::Show('Multiple active locations were found in Autotask. The following window will list them all. Please Ctrl+Click (to select) each location you wish to keep. Any locations that are not selected will be deleted!')
	$KeepLocations = $Autotask_Locations | Select-Object id, name, isPrimary, address1, address2, city, postalCode, state, country, phone, alternatePhone1, alternatePhone2, fax, description | Out-GridView -PassThru -Title "Autotask Locations (Select to keep, all unselected will be Deleted!)"
	$KeepLocations = $KeepLocations.id

	# Remove the unselected ones
	if (($KeepLocations | Measure-Object).Count -gt 0) {
		$DeleteIDs = ($Autotask_Locations | Where-Object { $_.id -notin $KeepLocations }).id

		if ($DeleteIDs) {
			$DeleteCount = @($DeleteIDs).Count
			$Continue = [System.Windows.MessageBox]::Show("You have selected $DeleteCount location(s) to disable. Are you sure you want to continue?", 'Continue removing locations?', 'YesNo')
		
			if ($Continue -eq "Yes") { 
				Get-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Where-Object { $_.id -in $DeleteIDs } | ForEach-Object { $_.IsActive = "false"; $_.IsPrimary = "false"; $_ } | Set-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Out-Null
				$Autotask_Locations = Get-AutotaskAPIResource -Resource CompanyLocations -SimpleSearch "CompanyID eq $Autotask_CompanyID" | Where-Object { $_.isActive -eq "True" }
				$Autotask_Locations | Add-Member -MemberType NoteProperty -Name country -value $null
				$Autotask_Locations | ForEach-Object { $_.country = $Autotask_CountriesLookup[$_.countryID] }
				Write-Host "Disabled unwanted locations."
			}
		}
	}
}

# Verify there is still a primary location
$PrimaryLocation = $Autotask_Locations | Where-Object { $_.IsPrimary -eq "True" }
if (($PrimaryLocation | Measure-Object).Count -eq 0) {
	Write-Host "No locations are currently set as the Primary location. Attempting to fix..." -ForegroundColor Red

	if (($Autotask_Locations | Measure-Object).Count -eq 1) {
		Get-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Where-Object { $_.isActive -eq "True" } | Select-Object -First 1 | ForEach-Object { $_.IsPrimary = "True"; $_ } | Set-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Out-Null
		Write-Host "Set the single remaining location as the Primary location."
	} else {
		[System.Windows.MessageBox]::Show('Multiple active locations exist. Please choose the Primary location.')
		$PrimaryLocation = $Autotask_Locations | Select-Object id, name, isPrimary, address1, address2, city, postalCode, state, country, phone, alternatePhone1, alternatePhone2, fax, description | Out-GridView -PassThru -Title "Autotask Locations (Select the Primary Location.)"
		$PrimaryLocation = ($PrimaryLocation | Select-Object -First 1).id

		Get-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Where-Object { $_.id -eq $PrimaryLocation } | ForEach-Object { $_.IsPrimary = "True"; $_ } | Set-AutotaskAPIResource -Resource CompanyLocationsChild -ID $Autotask_CompanyID | Out-Null
		Write-Host "Set the chosen location as the Primary location."
	}
}

# Address Cleanup
# Check each contacts Location field and Custom Address fields to see if they match, if not, update the address fields
$FixedCount = 0
$ContactsRaw = Get-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID
Write-Host "Starting contact address cleanup..."
foreach ($Contact in $Autotask_Contacts) {
	$LocationID = $Contact.CompanyLocationID
	if (!$LocationID) {
		continue
	}
	$LocationInfo = $Autotask_Locations | Where-Object { $_.id -eq $LocationID }

	if ($LocationInfo) {
		if ($Contact.AddressLine -ne $LocationInfo.address1 -or $Contact.AddressLine1 -ne $LocationInfo.address2 -or $Contact.City -ne $LocationInfo.city -or 
			$Contact.State -ne $LocationInfo.state -or $Contact.ZipCode -ne $LocationInfo.postalCode -or $Contact.CountryID -ne $LocationInfo.countryID) {
				# Address differs from location, update
				$ContactsRaw | Where-Object { $_.Id -eq $Contact.Id } | 
					ForEach-Object { 
						$_.AddressLine = $LocationInfo.address1; 
						$_.AddressLine1 = $LocationInfo.address2; 
						$_.City = $LocationInfo.city; 
						$_.State = $LocationInfo.state; 
						$_.ZipCode = $LocationInfo.postalCode; 
						$_.CountryID = $LocationInfo.countryID; 
						$_ 
					} | 
					Set-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID | Out-Null
				$FixedCount++
		}
	} else {
		# Location is disabled or doesn't exist, remove it
		$ContactsRaw | Where-Object { $_.Id -eq $Contact.Id } | 
			ForEach-Object { 
				$_.CompanyLocationID = $null; 
				$_
			} | 
			Set-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID | Out-Null
		$FixedCount++
	}
}

if ($FixedCount -gt 0) {
	Write-Host "Fixed $FixedCount contact(s) where the address fields did not match their location."
	$Autotask_Contacts = Get-AutotaskAPIResource -Resource Contacts -SimpleSearch "CompanyID eq $Autotask_CompanyID" | Where-Object { $_.isActive -eq 1 }
} else {
	Write-Host "No contacts required cleaning!"
}

### Build the contact location matching form, it will be used by the next piece of code
# @return int/str the id of the location to match it to. 0 to remove the address entirely. "pass" to ignore the address and move on (default).

function LocationMatchingForm {
	param(
		[psObject]$Address, 
		[array]$Locations, 
		[int]$Remaining
	)

	if (!$Address -or !$Locations) {
		Write-Host 'No address or locations were provided to the Location Matching Form. Unable to continue.'
		return
	}

	$NewLocation = "pass" # Default: Ignore

	Add-Type -AssemblyName System.Windows.Forms
	[System.Windows.Forms.Application]::EnableVisualStyles()

	$AddressToLocation               = New-Object system.Windows.Forms.Form
	$AddressToLocation.ClientSize    = New-Object System.Drawing.Point(630,293)
	$AddressToLocation.text          = "Map the address to a location:"
	$AddressToLocation.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
	$AddressToLocation.TopMost       = $false


	$Groupbox1                       = New-Object system.Windows.Forms.Groupbox
	$Groupbox1.height                = 131
	$Groupbox1.width                 = 595
	$Groupbox1.Anchor                = 'top,right,bottom,left'
	$Groupbox1.text                  = "Map a location:"
	$Groupbox1.location              = New-Object System.Drawing.Point(18,27)

	$Groupbox3                       = New-Object system.Windows.Forms.Groupbox
	$Groupbox3.height                = 68
	$Groupbox3.width                 = 266
	$Groupbox3.Anchor                = 'top,bottom,left'
	$Groupbox3.text                  = "Address:"
	$Groupbox3.location              = New-Object System.Drawing.Point(16,25)

	# build address string
	$AddressStr = $Address.addressLine
	if ($Address.addressLine1) {
		$AddressStr += ", " + $Address.addressLine1
	}
	if ($AddressStr) {
		$AddressStr += "`n"
	}
	$AddressStr += $Address.city
	if ($Address.state) {
		$AddressStr += ", " + $Address.state
	}
	if ($Address.zipCode) {
		$AddressStr += " " + $Address.zipCode
	}
	if ($Address.country) {
		if ($AddressStr) {
			$AddressStr += "`n"
		}
		$AddressStr += $Address.country
	}


	$contactAddress                  = New-Object system.Windows.Forms.Label
	$contactAddress.text             = $AddressStr
	$contactAddress.AutoSize         = $true
	$contactAddress.width            = 250
	$contactAddress.height           = 35
	$contactAddress.location         = New-Object System.Drawing.Point(8,17)
	$contactAddress.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	if ($Remaining -eq 0) {
		$RemainingStr = "This is the last address to map."
	} elseif ($Remaining -eq 1) {
		$RemainingStr = "1 address left to map."
	} else {
		$RemainingStr = "$Remaining addresses left to map."
	}

	$remainingLabel                  = New-Object system.Windows.Forms.Label
	$remainingLabel.text             = $RemainingStr
	$remainingLabel.AutoSize         = $true
	$remainingLabel.width            = 25
	$remainingLabel.height           = 10
	$remainingLabel.location         = New-Object System.Drawing.Point(26,106)
	$remainingLabel.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

	$Label1                          = New-Object system.Windows.Forms.Label
	$Label1.text                     = "TO"
	$Label1.AutoSize                 = $true
	$Label1.width                    = 25
	$Label1.height                   = 10
	$Label1.location                 = New-Object System.Drawing.Point(299,69)
	$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

	$Groupbox4                       = New-Object system.Windows.Forms.Groupbox
	$Groupbox4.height                = 60
	$Groupbox4.width                 = 246
	$Groupbox4.Anchor                = 'top,right,bottom'
	$Groupbox4.text                  = "Location:"
	$Groupbox4.location              = New-Object System.Drawing.Point(334,24)

	$locationsDropdown               = New-Object system.Windows.Forms.ComboBox
	$locationsDropdown.text          = "Ignore"
	$locationsDropdown.width         = 222
	$locationsDropdown.height        = 20

	$LocationIDMap = @{}
	[void]$locationsDropdown.Items.Add("Ignore")
	foreach ($Location in $Autotask_Locations) {
		$LocationStr = $Location.name + " (" + $Location.address1 + ", " + $Location.city + ", " + $Location.state + ")"
		$ID = $locationsDropdown.Items.Add($LocationStr)
		$LocationIDMap[$ID] = $Location.id
	}
	$ID = $locationsDropdown.Items.Add("No Address")
	$LocationIDMap[$ID] = 0

	$locationsDropdown.location      = New-Object System.Drawing.Point(10,24)
	$locationsDropdown.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$saveBtn                         = New-Object system.Windows.Forms.Button
	$saveBtn.text                    = "Save"
	$saveBtn.width                   = 60
	$saveBtn.height                  = 30
	$saveBtn.Anchor                  = 'right,bottom'
	$saveBtn.location                = New-Object System.Drawing.Point(520,90)
	$saveBtn.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)


	$Groupbox2                       = New-Object system.Windows.Forms.Groupbox
	$Groupbox2.height                = 100
	$Groupbox2.width                 = 596
	$Groupbox2.Anchor                = 'right,bottom,left'
	$Groupbox2.text                  = "Instructions:"
	$Groupbox2.location              = New-Object System.Drawing.Point(18,183)

	$instructions1                   = New-Object system.Windows.Forms.Label
	$instructions1.text              = "Map the address to a location. The location will overwrite the address."
	$instructions1.AutoSize          = $true
	$instructions1.width             = 25
	$instructions1.height            = 10
	$instructions1.location          = New-Object System.Drawing.Point(16,18)
	$instructions1.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$instructions2                   = New-Object system.Windows.Forms.Label
	$instructions2.text              = "If you want to remove the address entirely, choose `"No Address`"."
	$instructions2.AutoSize          = $true
	$instructions2.width             = 25
	$instructions2.height            = 10
	$instructions2.location          = New-Object System.Drawing.Point(16,45)
	$instructions2.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

	$instructions3                   = New-Object system.Windows.Forms.Label
	$instructions3.text              = "If you want to leave the address as-is (with the location dropdown unset), choose `"Ignore`"."
	$instructions3.AutoSize          = $true
	$instructions3.width             = 25
	$instructions3.height            = 10
	$instructions3.location          = New-Object System.Drawing.Point(16,74)
	$instructions3.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',10)


	$AddressToLocation.controls.AddRange(@($Groupbox1,$Groupbox2))
	$Groupbox2.controls.AddRange(@($instructions1,$instructions2,$instructions3))
	$Groupbox1.controls.AddRange(@($remainingLabel,$Groupbox3,$Groupbox4,$Label1,$saveBtn))
	$Groupbox3.controls.AddRange(@($contactAddress))
	$Groupbox4.controls.AddRange(@($locationsDropdown))

	$saveBtn.Add_Click({
		$SelectedID = $locationsDropdown.SelectedIndex;
		if ($SelectedID -gt 0) {
			Set-Variable -scope 1 -Name "NewLocation" -Value $LocationIDMap[$SelectedID]
		} else {
			Set-Variable -scope 1 -Name "NewLocation" -Value "pass"
		}
		[void]$AddressToLocation.Close()
	})

	[void]$AddressToLocation.ShowDialog()

	$NewLocation
	return
}


# Check all contacts to see if their address fields are setup, but not their Location dropdown field
$Autotask_ContactsWithAddress = $Autotask_Contacts | Where-Object { $_.addressLine -and !$_.companyLocationID }
$ContactUniqueAddresses = $Autotask_ContactsWithAddress | Select-Object addressLine, addressLine1, city, state, zipCode, countryID | 
							Sort-Object addressLine, addressLine1, city, state, zipCode, countryID | Get-Unique -AsString
$ContactUniqueAddresses | Add-Member -MemberType NoteProperty -Name country -value $null
$ContactUniqueAddresses | ForEach-Object { if ($_.countryID) { $_.country = $Autotask_CountriesLookup[$_.countryID] } }
$ContactUniqueAddresses | Add-Member -MemberType NoteProperty -Name id -value $null
$i = 0
$ContactUniqueAddresses | ForEach-Object { $i++; $_.id = $i }

# Give the user the option to map addresses to full locations
if (($ContactUniqueAddresses | Measure-Object).Count -gt 0) {
	$i = 0
	$Total = ($ContactUniqueAddresses | Measure-Object).Count
	$AddressToLocationMap = @{}
	$ChangesMade = $false
	Write-Host "Addresses were found on contacts with no location set. Please use the form to map these addresses to a proper location."
	foreach ($Address in $ContactUniqueAddresses) {
		$i++
		$Remaining = $Total - $i
		$LocationID = LocationMatchingForm -Address $Address -Locations $Autotask_Locations -Remaining $Remaining
		$AddressToLocationMap[$Address.id] = $LocationID
		if ($LocationID -ne "pass") {
			$ChangesMade = $true
		}
	}

	if ($ChangesMade) {
		Write-Host "Updating location of contacts..."
		$ContactCount = ($Autotask_ContactsWithAddress | Measure-Object).Count
		$i = 0
		$ContactsRaw = Get-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID
		$UpdatedContacts = @()

		foreach ($Contact in $Autotask_ContactsWithAddress) {
			$i++
			$AddressID = ($ContactUniqueAddresses | Where-Object { 
				$_.addressLine -eq $Contact.addressLine -and 
				$_.addressLine1 -eq $Contact.addressLine1 -and 
				$_.city -eq $Contact.city -and 
				$_.state -eq $Contact.state -and 
				$_.zipCode -eq $Contact.zipCode -and 
				$_.countryID -eq $Contact.countryID
			} | Select-Object -First 1).id

			if (!$AddressID -or !$AddressToLocationMap.ContainsKey($AddressID)) {
				continue
			}
			$LocationID = $AddressToLocationMap[$AddressID]
			$LocationInfo = $null
			if ($LocationID -eq "pass") {
				continue
			} elseif ($LocationID -gt 0) {
				$LocationInfo = $Autotask_Locations | Where-Object{ $_.id -eq $LocationID }
			}

			Write-Progress -Activity "Updating contact locations and addresses." -Status "Updating contact #$($Contact.Id) ($i of $ContactCount)." -PercentComplete (($i / $ContactCount) * 80)

			# Update the contact with the new location (store them all in a variable for now)
			if ($LocationInfo) {
				$UpdatedContacts += $ContactsRaw | Where-Object { $_.Id -eq $Contact.Id } | 
					ForEach-Object { 
						$_.CompanyLocationID = $LocationID; 
						$_.AddressLine = $LocationInfo.address1; 
						$_.AddressLine1 = $LocationInfo.address2; 
						$_.City = $LocationInfo.city; 
						$_.State = $LocationInfo.state; 
						$_.ZipCode = $LocationInfo.postalCode; 
						$_.CountryID = $LocationInfo.countryID; 
						$_ 
					}
			} elseif ($LocationID -eq 0) {
				$UpdatedContacts += $ContactsRaw | Where-Object { $_.Id -eq $Contact.Id } | 
					ForEach-Object { 
						$_.CompanyLocationID = $null; 
						$_.AddressLine = $null; 
						$_.AddressLine1 = $null; 
						$_.City = $null; 
						$_.State = $null; 
						$_.ZipCode = $null; 
						$_.CountryID = $null; 
						$_ 
					}
			}
		}
		# Send the updates to Autotask
		if ($UpdatedContacts) {
			Write-Progress -Activity "Updating contact locations and addresses." -Status "Sending updates to Autotask." -PercentComplete (($i / $ContactCount) * 85)
			$UpdatedContacts | Set-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID | Out-Null
			Write-Progress -Activity "Updating contact locations and addresses." -Status "Complete!" -PercentComplete 100
		}
		Write-Host "All contacts have now been updated."

		$Autotask_Contacts = Get-AutotaskAPIResource -Resource Contacts -SimpleSearch "CompanyID eq $Autotask_CompanyID" | Where-Object { $_.isActive -eq 1 }
	}
}

# Look for duplicate contacts
Write-Host "Checking for duplicate contacts."
$Autotask_Contacts | Add-Member -MemberType NoteProperty -Name fullName -value $null
$Autotask_Contacts | ForEach-Object { $_.fullName = $_.firstName + " " + $_.lastName }

$UniqueContacts = $Autotask_Contacts.fullName | Select-Object -Unique
$DuplicateContacts = @()
if ($UniqueContacts) {
	$DuplicateContacts = Compare-Object -ReferenceObject $UniqueContacts -DifferenceObject $Autotask_Contacts.fullName
}
$DuplicateIDs = @()

foreach ($Contact in $DuplicateContacts.InputObject) {
	$DuplicateIDs += ($Autotask_Contacts | Where-Object { $_.fullName -like $Contact }).id
}

# and find anything with duplicate emails
if ($DuplicatesOnEmails) { 
	$EmailFieldNames = @("emailAddress", "emailAddress2", "emailAddress3")
	$DuplicateEmailObjects = @()
	foreach ($EmailField in $EmailFieldNames) {
		$UniqueEmails = @(($Autotask_Contacts | Where-Object {$_.$EmailField -ne $null}).$EmailField | Select-Object -Unique)

		foreach ($EmailField2 in $EmailFieldNames) {
			$DuplicateEmails = @()
			if ($UniqueEmails -and ($Autotask_Contacts.$EmailField2 | Measure-Object).Count -gt 0) {
				$Emails = @(($Autotask_Contacts | Where-Object {$_.$EmailField2 -ne $null}).$EmailField2)
				if ($EmailField -eq $EmailField2) {
					$DuplicateEmails = Compare-Object -ReferenceObject $UniqueEmails -DifferenceObject $Emails
					$DuplicateEmailObjects += $DuplicateEmails.InputObject
				} else {
					$DuplicateEmails = Compare-Object -ReferenceObject $UniqueEmails -DifferenceObject $Emails -IncludeEqual -ExcludeDifferent
					$DuplicateEmailObjects += $DuplicateEmails.InputObject
				}
			}
		}
	}
	$DuplicateEmailObjects = $DuplicateEmailObjects | Select-Object -Unique

	foreach ($Email in $DuplicateEmailObjects) {
		$ID = ($Autotask_Contacts | Where-Object { $_.emailAddress -like $Email -or $_.emailAddress2 -like $Email -or $_.emailAddress3 -like $Email }).id
		if ($ID -notin $DuplicateIDs) {
			$DuplicateIDs += $ID
		}
	}
}


# lets also add anything marked "(Old)"
$OldContacts = @($Autotask_Contacts | Where-Object { $_.lastName -like "*(Old)" })
foreach ($Contact in $OldContacts) {
	$LastName = $Contact.lastName
	$LastName = $LastName.Substring(0, $LastName.Length-6)
	$ConnectedContact = $Autotask_Contacts | Where-Object { $_.firstName -eq $Contact.firstName -and $_.lastName -eq $LastName }
	$OldContacts += $ConnectedContact
}
if ($OldContacts) {
	$DuplicateIDs += $OldContacts.id
}

$DuplicateIDs = $DuplicateIDs | Sort-Object -Unique

if ($DuplicateIDs) {
	$ShowDuplicates = $false
	$ShowDuplicates = [System.Windows.MessageBox]::Show('Duplicate contacts were found in Autotask. Would you like to see these duplicates?', 'Duplicate Contacts Found', 'YesNo')

	if ($ShowDuplicates -eq 'Yes') {
		$DupeContactsTable = @()
		foreach ($ID in $DuplicateIDs) {
			$TicketCount = (Get-AutotaskAPIResource -Resource Tickets -SimpleSearch "ContactID eq $ID" | Measure-Object).Count

			$DupeContactsTable += $Autotask_Contacts | Where-Object { $_.id -eq $ID } | 
				Select-Object id, fullName, 
					@{Name="Location"; Expression={ 
						if ($_.companyLocationID) { 
							$LocID = $_.companyLocationID
							($Autotask_Locations | Where-Object {$_.id -eq $LocID}).name
						}
					}}, 
					@{Name="Address"; Expression = {
						$Address = $_.addressLine;
						if ($_.city) { $Address += ", " + $_.city; }
						if ($_.state) { $Address += ", " + $_.state; } 
						if ($_.countryID) { $Address += ", " + $Autotask_CountriesLookup[$_.countryID]; }
						$Address
					}}, 
					title, emailAddress, emailAddress2, emailAddress3, phone, mobilePhone, alternatePhone, @{Name="ticketCount"; E={$TicketCount}},
					@{Name="URL"; E={
						"https://ww$($AutotaskZoneID).autotask.net/Autotask/AutotaskExtend/ExecuteCommand.aspx?Code=OpenContact&ContactID=$ID"
					}}
		}

		$DupeContactsTable = $DupeContactsTable | Sort-Object -Property fullName, Location, Address, ticketCount, ID
		
		# Display form - we use a full form here instead of just a datagridview so that you can select the URL individually, rather than the entire row
		Add-Type -AssemblyName System.Windows.Forms
		[System.Windows.Forms.Application]::EnableVisualStyles()

		$DuplicateContactsForm           = New-Object system.Windows.Forms.Form
		$DuplicateContactsForm.ClientSize  = New-Object System.Drawing.Point(800,600)
		$DuplicateContactsForm.text      = "Duplicate Contacts"
		$DuplicateContactsForm.TopMost   = $false

		$dupeContactsGrid                = New-Object system.Windows.Forms.DataGridView
		$dupeContactsGrid.width          = 790
		$dupeContactsGrid.height         = 543

		$dupeContactsGrid.ColumnCount = 13
		$dupeContactsGrid.ColumnHeadersVisible = $true
		$dupeContactsGrid.Columns[0].Name = "ID"
		$dupeContactsGrid.Columns[1].Name = "Name"
		$dupeContactsGrid.Columns[2].Name = "Location"
		$dupeContactsGrid.Columns[3].Name = "Address"
		$dupeContactsGrid.Columns[4].Name = "Title"
		$dupeContactsGrid.Columns[5].Name = "Email Address"
		$dupeContactsGrid.Columns[6].Name = "Email Address 2"
		$dupeContactsGrid.Columns[7].Name = "Email Address 3"
		$dupeContactsGrid.Columns[8].Name = "Phone"
		$dupeContactsGrid.Columns[9].Name = "Mobile Phone"
		$dupeContactsGrid.Columns[10].Name = "Alternate Phone"
		$dupeContactsGrid.Columns[11].Name = "Ticket Count"
		$dupeContactsGrid.Columns[12].Name = "URL"
		$dupeContactsGrid.Columns[12].Width = 600
		foreach ($contact in $DupeContactsTable){
			$row = @($contact.id, $contact.fullName, $contact.Location, $contact.Address, $contact.title, $contact.emailAddress, $contact.emailAddress2, $contact.emailAddress3, $contact.phone, $contact.mobilePhone, $contact.alternatePhone, $contact.ticketCount, $contact.URL)
			$dupeContactsGrid.Rows.Add($row) | Out-Null
		}
		$dupeContactsGrid.Anchor         = 'top,right,bottom,left'
		$dupeContactsGrid.location       = New-Object System.Drawing.Point(4,4)

		$renameBtn                       = New-Object system.Windows.Forms.Button
		$renameBtn.text                  = "Mark as Old"
		$renameBtn.width                 = 95
		$renameBtn.height                = 30
		$renameBtn.Anchor                = 'right,bottom'
		$renameBtn.location              = New-Object System.Drawing.Point(698,558)
		$renameBtn.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$continueBtn                       = New-Object system.Windows.Forms.Button
		$continueBtn.text                  = "Continue"
		$continueBtn.width                 = 77
		$continueBtn.height                = 30
		$continueBtn.Anchor                = 'right,bottom'
		$continueBtn.location              = New-Object System.Drawing.Point(607,558)
		$continueBtn.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

		$Label1                          = New-Object system.Windows.Forms.Label
		$Label1.text                     = "Select an account, press `"Mark as Old`",  and the script will append `"(Old)`" to the contacts name. `n You can then manually merge them in Autotask. Press `"Continue`" to close this form."
		$Label1.AutoSize                 = $true
		$Label1.width                    = 25
		$Label1.height                   = 10
		$Label1.Anchor                	 = 'left,bottom'
		$Label1.location                 = New-Object System.Drawing.Point(10,557)
		$Label1.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)


		$DuplicateContactsForm.controls.AddRange(@($dupeContactsGrid,$renameBtn,$continueBtn,$Label1))

		# Allow url links to be clickable
		$dupeContactsGrid.Add_CellMouseDoubleClick({
			$ColumnIndex = $dupeContactsGrid.CurrentCell.ColumnIndex
			$ColumnValue = $dupeContactsGrid.CurrentCell.Value

			# verify they clicked on a URL, if so, launch it
			if ($ColumnIndex -eq 12 -and ($ColumnValue -as [System.URI]).AbsoluteURI -ne $null) {
				Start-Process $ColumnValue
			}
		})

		$renameBtn.Add_Click({
			$SelectedIDs = ($dupeContactsGrid.SelectedCells.OwningRow.Cells | Where-Object { $_.ColumnIndex -eq 0 }).Value | Select-Object -Unique
			$renameBtn.text = "Updating..."
			$renameBtn.enabled = $false

			if (($SelectedIDs | Measure-Object).Count -gt 0) {
				Get-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID | Where-Object { $_.Id -in $SelectedIDs -and $_.lastName -notlike "* (Old)" } | ForEach-Object { $_.LastName = $_.LastName + " (Old)"; $_ } | Set-AutotaskAPIResource -Resource CompanyContactsChild -ID $Autotask_CompanyID | Out-Null
				$dupeContactsGrid.Rows | ForEach-Object {
					$ContactID = $_.Cells[0].Value
					$CurrentName = $_.Cells[1].Value
					if ($ContactID -in $SelectedIDs -and $CurrentName -notlike "* (Old)") {
						$ContactInfo = $Autotask_Contacts | Where-Object { $_.Id -eq $ContactID }
						$NewName = $ContactInfo.firstName + " " + $ContactInfo.lastName + " (Old)"
						$_.Cells[1].Value = $NewName
					}
				}
			}

			$renameBtn.text = "Done!"
			Start-Sleep -Milliseconds 500
			$renameBtn.text = "Mark as Old"
			$renameBtn.enabled = $true
		})

		$continueBtn.Add_Click({
			[void]$DuplicateContactsForm.Close()
		})

		[void]$DuplicateContactsForm.ShowDialog()
	}
}

Write-Host "Completed the Autotask cleanup."