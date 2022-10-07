# User Billing Audit
The included scripts are used for auditing our contacts/users in IT Glue and for automating corrections and billing updates based on these contact lists. This consists of 3 scripts and 1 constants file:

### Autotask Audit
This script can be used as a pre-cleanup of Autotask contacts. As these are synced through to IT Glue it is important to have these setup nicely. To use this, you will need to setup a few constants at the top of the file. Configure the Autotask company ID and Autotask Zone ID, as well as your Autotask API credentials. This script only connects to Autotask, not ITG. 

The script cleans up locations, addresses, allows mapping of addresses to locations, cleans up duplicate contacts, and marks contacts for removal with (Old). After anything gets marked as Old, it is up to you to merge the contacts and de-activate the old contact. If duplicate matching is working poorly, try disabling `$DuplicatesOnEmails` (which will prevent it for looking for duplicates based on email).

### User Audit - Constants
This contains all of the variables for both the User Audit and User Billing Update scripts. The file contains extensive comments to help you fill out the required variables. This must be setup before using either of the following 2 scripts. A constants file is specific to a certain customer and must reside in the same folder as the User Audit or User Billing Update script. Alternatively, you can setup multiple User Audit's on one device if doing a cloud-only audit (e.g. Azure & O365); in this case use a Constants folder and the $config param to choose the config you want at-run. More info on script configuration can be found in our internal ITG documentation.

For setting up the O365 Unattended Login details, see: https://github.com/seatosky-chris/Users-Billing-Audit/wiki/Configure-Certificate-for-Unattended-Powershell-Access

### User Audit
This script can be run manually to do a full user audit on an ITG contact list. It will compare the contacts to AD and Office 365 (or Exchange) then provide suggestions on required changes. It must be setup on the customer's AD server and the Constants file must be filled in for it to work. The script will store files in `C:\billing_history\`.

Before running this script, you should ensure a few things are cleaned up. Initially you should clean up the customers location in ITG/Autotask, add any tracked domains to ITG (particularly for their email domain), check on orphaned/unsynced contacts and remove duplicate contacts. More info on this can be found in our internal ITG documentation. On the first time you run this script, it will do a pre-cleanup check to help with this process. This pre-cleanup check will look for a few common issues such as duplicate locations, duplicate contacts, contacts with no email or phone numbers and contacts with an incorrect email domain (doesn't match one of their tracked domains). 

On every run the user audit will check for bad email/phone types. By default, when a contact syncs from O365 the emails/phone numbers will be of a type (Email or Office) that won't sync back to Autotask. This causes a problem as the Autotask contacts are then missing data. The script will look for these and prompt you to correct them. This unfortunately cannot be done automatically due to limitations in the API. You will need to manually edit each contact in this list to change the type away from "Email" or "Office".

The script will then proceed to run the audit. It will get all users from AD and Office 365/Exchange (if enabled in the constants) and then will try to match every AD account with an email account and an ITG contact. It will then show you the entire list of matches for you to verify. At this point you have the option to change matches if required. At this point, if you have to make many changes in ITG to contacts, it is best to restart the script so that it picks up all these changes before commencing with the audit. 

Once all of the matches have been made and accepted, the script will look for any discrepancies and provide a list of suggestions. These suggestions, for the most part, will be about changing contact types which effects the billing. It will look for things like email-only accounts and disabled users. Additionally, it will look for inactive accounts and alert you when an account has been inactive for greater than 150 days so we can inquire if the account should be terminated. Follow the suggestions and make changes as required.

Once you have finished reviewing the changes, the script will update its contact list and then export a csv of the contacts. It will use this in the future to watch for changes. You will also have the option to export a full list of all the matches. Lastly is an option to export a billing report. This will generate a full report of how many users of each billed type there are that accounting can use to update this customers bill. There is also an option to upload this report to ITG. 

### User_Billing_Update
This script is a modified version of the above User Audit script that can be scheduled to run automatically. It will do most of the same things the above script does but instead of providing a GUI, it will send an email of any changes that are required. It will also keep track of some of the info it has sent emails about and then ignore them the next time it sends a new email. Like the User Audit script, it must be setup on the customer's AD server and the Constants file must be filled in for it to work. The script will store files in `C:\billing_history\`.

Before using this script you should run the manual User Audit and ensure that the contact list has been cleaned up properly. This script will not handle and pre-cleanup checks and expects an initial audit to have already been completed. It will make new user matches if necessary (between AD/ITG/Email), but will try to use existing matches you have already approved via a manual audit where possible.

The script can be ran using 2 different flags: `$UserAudit` or `$BillingUpdate`. Set either one to `$true` to run that part of the audit. When automating it, I suggest setting up a User Audit about a week before billing must be updated, and then scheduling a second run for a Billing Audit a week later to send a new billing report to accounting.

If running a user audit, after the script has matched users and found discrepancies, it will create an HTML list of warnings and send them off to a pre-specified email. At this point you can review the suggestions and make changes as necessary. If running a billing audit, the script will generate a billing report, send it off to a pre-specific email, and upload the report to ITG. 

User Audit Example: `PowerShell.exe -ExecutionPolicy Bypass -File "C:\seatosky\User_Billing_Update.ps1" -UserAudit`
Billing Report Example: `PowerShell.exe -ExecutionPolicy Bypass -File "C:\seatosky\User_Billing_Update.ps1" -BillingUpdate`
User Audit with Config Selection Example: `PowerShell.exe -ExecutionPolicy Bypass -File "C:\seatosky\User_Billing_Update.ps1" -UserAudit -config "STS Constants"`