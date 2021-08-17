param($RunAfter = $null, $UserAudit = $false, $BillingUpdate = $false)

if ($RunAfter -eq "User_Audit") {
    $RunAfter = "User Audit"
}

# Give the script a sec to close & release handles.
Write-Output "=== User Audit Updater ==="
Write-Output "[*] Updating to new version..."
Write-Output "[*] Sleeping 3 seconds"
Start-Sleep -Seconds 3

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "[*] This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
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

Write-Output "[*] Downloading files"

$Scripts_BillingUpdate = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/User_Billing_Update.ps1")
$Scripts_UserAudit = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/User%20Audit.ps1")
$Scripts_O365Licenses = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/O365Licenses.ps1")
$Scripts_CurrentVersion = (New-Object System.Net.WebClient).Downloadstring("https://raw.githubusercontent.com/seatosky-chris/Users-Billing-Audit/main/currentversion.txt")

if ($Scripts_BillingUpdate -eq $null -or $Scripts_UserAudit -eq $null -or $Scripts_O365Licenses -eq $null -or $Scripts_CurrentVersion -eq $null)
{
    Write-Output "[*] Unable to download files. Aborting"
    exit
}

try 
{
    Write-Output "[*] Updating User_Billing_Update.ps1"
    $UpdatePath = "$($PSScriptRoot)\User_Billing_Update.ps1"
    Remove-Item $UpdatePath
    $Scripts_BillingUpdate | Out-File $UpdatePath
    FixFilePermissions -Path $UpdatePath
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
    $UpdatePath = "$($PSScriptRoot)\User Audit.ps1"
    Remove-Item $UpdatePath 
    $Scripts_UserAudit | Out-File $UpdatePath 
    FixFilePermissions -Path $UpdatePath
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
    $UpdatePath = "$($PSScriptRoot)\O365Licenses.ps1"
    Remove-Item $UpdatePath 
    $Scripts_O365Licenses | Out-File $UpdatePath 
    FixFilePermissions -Path $UpdatePath
}
catch [System.Exception] {
    Write-Output "Error saving new version of O365Licenses.ps1"
    throw
	Read-Host "Press any key to exit."
    exit
}

try 
{
    Write-Output "[*] Updating currentversion.txt"
    $UpdatePath = "$($PSScriptRoot)\currentversion.txt"
    Remove-Item $UpdatePath 
    $Scripts_CurrentVersion | Out-File $UpdatePath 
    FixFilePermissions -Path $UpdatePath
}
catch [System.Exception] {
    Write-Output "Error saving new version of currentversion.txt"
    throw
	Read-Host "Press any key to exit."
    exit
}

Write-Output "[*] Done!"

if ($RunAfter) {
	Write-Output "[*] Restarting the $RunAfter script."
    $Path = "$($PSScriptRoot)\$RunAfter.ps1"
    if ($RunAfter -eq "User Audit") {
        Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-file `"$($Path)`""
    } else {
        $Arguments = ""
        if ($UserAudit) {
            $Arguments = "-UserAudit"
        } elseif ($BillingUpdate) {
            $Arguments = "-BillingUpdate"
        }
        Start-Process -FilePath "$PSHOME\powershell.exe" -ArgumentList "-file `"$($Path)`" $Arguments"
    }
}
exit