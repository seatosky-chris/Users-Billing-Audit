param($RunAfter = $null)

# Give the script a sec to close & release handles.
Write-Output "[*] Sleeping 3 seconds"
Start-Sleep -Seconds 3

Write-Output "[*] Downloading files"

$Scripts_BillingUpdate = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/User_Billing_Update.ps1")
$Scripts_UserAudit = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/User%20Audit.ps1")
$Scripts_O365Licenses = (New-Object System.Net.WebClient).Downloadstring("https://github.com/seatosky-chris/Users-Billing-Audit/blob/main/O365Licenses.ps1")
Read-Host "Press to start"
if ($Scripts_BillingUpdate -eq $null -or $Scripts_UserAudit -eq $null -or $Scripts_O365Licenses -eq $null)
{
    Write-Output "[*] Unable to download files. Aborting"
    exit
}

try 
{
    Write-Output "[*] Updating User_Billing_Update.ps1"
    Remove-Item "$($PWD.Path)\User_Billing_Update.ps1"
    $Scripts_BillingUpdate | Out-File "$($PWD.Path)\User_Billing_Update.ps1"
}
catch [System.Exception] {
    Write-Output "Error saving new version of User_Billing_Update.ps1"
    throw
	Read-Host "Press any key to exit."
    exit
}

try 
{
    Write-Output "[*] Updating User Audit.ps1"
    Remove-Item "$($PWD.Path)\User Audit.ps1"
    $Scripts_UserAudit | Out-File "$($PWD.Path)\User Audit.ps1"
}
catch [System.Exception] {
    Write-Output "Error saving new version of User Audit.ps1"
    throw
	Read-Host "Press any key to exit."
    exit
}

try 
{
    Write-Output "[*] Updating O365Licenses.ps1"
    Remove-Item "$($PWD.Path)\O365Licenses.ps1"
    $Scripts_O365Licenses | Out-File "$($PWD.Path)\O365Licenses.ps1"
}
catch [System.Exception] {
    Write-Output "Error saving new version of O365Licenses.ps1"
    throw
	Read-Host "Press any key to exit."
    exit
}

Write-Output "[*] Done!"

if ($RunAfter) {
	Write-Output "[*] Restarting the $RunAfter script."
	. "$($PWD.Path)\$RunAfter.ps1"
}
exit