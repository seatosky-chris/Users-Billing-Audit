##################################################################################################################
################################################  PRE-REQUISITES  ################################################
##################################################################################################################
### The script has a few requirements that need to be setup before you can run it:
###   - Run this on a server that is an AD host for the organization.
###   - Powershell 5.1 or above must be installed.
###   - NuGet must be installed. (See AEM script: IMPROVED - ENABLE NUGET POWERSHELL PROVIDER [WIN])
###   - Module Dependencies: 
###     a. Install-Module -Name ITGlueAPI
###     b. Install-Module -Name ImportExcel
###     c. Install-Module -Name AzureAD  # (If email is O365)
###     d. Install-Module -Name ExchangeOnlineManagement  # (If email is O365)
###   - Setup the below constants.
##################################################################################################################


##################################################################################################################
##################################################  CONSTANTS  ###################################################
##################################################################################################################
### Make sure you setup the variables in this file before running the script.
### The APIKey and $OrgID are the most crucial, but you will also want to modify the AD and O365 settings based
### on the organization you are auditing.
### The contact types don't need to be changed but can be adjusted for fine tuning.
##################################################################################################################

####################
# $APIKey
#
# The organization specific APIKey for IT Glue. 
# Generally this is the organizations acronym followed by a "." and then a UUID. 
#
# Example: "STS.f153-ea51-457d-a60b-e5b6e4"
#
$APIKEy =  ""

####################
# $APIEndpoint
#
# The ITGlue endpoint URL. If using an organization specific APIKey, this should be the URL for the AZGlueForwarder. 
# The default URL here should be correct, you just need to add the code.
#
# Example: "https://itgforwarder.azurewebsites.net/api/AzGlueForwarder?code=DM5utp67MRnkNjbSwow3DGC6h4bPOCp1x==&ResourceURI="
#
$APIEndpoint = ""

####################
# $LastUpdatedUpdater_APIURL
#
# The endpoint URL for the Last Updated Updater azure function. 
# This is used to updated the "Scripts - Last Updated" asset in ITG.
#
# Example: "https://lastupdatedupdater.azurewebsites.net/api/LastUpdatedUpdater?code=xxxx=="
#
$LastUpdatedUpdater_APIURL = ""

####################
# $Email_APIKey
#
# The organization specific APIKey for the email forwarder. 
# Generally this is the organizations acronym followed by a "." and then a UUID. 
#
# Example: "STS.fbc853-ea51-457d-a60b-e6b6e4"
#
$Email_APIKey =  ""

####################
# $Email_APIEndpoint
#
# The Email forwarder endpoint url.
# The default URL here should be correct, you just need to add the code.
#
# Example: "https://automail.azurewebsites.net/api/MailForwarder?ResourceURI="
#
$Email_APIEndpoint = ""

####################
# $Device_DB_APIKey
#
# The API key from the Device DB Key Broker
#
# Example: "STS.4466731b-1437-4f38-85ad-28f628c9db76"
#
$Device_DB_APIKey =  ""

####################
# $Device_DB_APIEndpoint
#
# The device db key broker azure function endpoint
# The default URL here should be correct, you just need to add the code.
#
# Example: "https://keybroker.azurewebsites.net/api/KeyBroker?code=DM5utp67MRnkNjbSwow3DGC6h4bPOCp1x==&ResourceURI="
#
$Device_DB_APIEndpoint = ""

####################
# $orgID
#
# The organizations ID in IT Glue. You can get this by navigating to their page in IT Glue, then getting the number from the URL.
# This will be the first 6+ digit number in the URL. See setup guide for more info.
#
# Example: "31359"
#
$orgID = ""

####################
# $CheckAD
#
# If $true, the audit script will connect IT Glue contacts to AD. 
# Set this to $false if the organization does not use AD.
#
$CheckAD = $true

####################
# $CheckEmail
#
# If $true, the audit script will connect IT Glue contacts to their email accounts in O365 or Exchange. 
# Set this to $false if the organization does not use Office 365 or Exchange for email.
#
$CheckEmail = $true

####################
# $EmailOnlyHaveAD
#
# If $true, the audit script will assume that email only accounts can (but don't necessarily) have a connected AD account. 
# Set this to $false if the the email only accounts never have an associated AD account.
# If $EmailType (below) is set to "Exchange" this will be assumed to be $true
#
$EmailOnlyHaveAD = $false

####################
# $EmailType
#
# Set this to either "O365" or "Exchange". This sets the type of email system the organization uses.
# Only used if $CheckEmail is $true. 
#
$EmailType = "O365"

####################
# $O365LoginUser
#
# Set this to the full email of this organization's Office 365 admin account.
# Only used if $CheckEmail is $true and $EmailType is "O365"
#
# Example: "admin@sts.onmicrosoft.com"
#
$O365LoginUser = ""

####################
# $O365UnattendedLogin
#
# Use this in place of the above O365 login for unattended logins using a certificate
# Recommended for automated billing updates
# See this guide for setup instructions: https://github.com/seatosky-chris/Users-Billing-Audit/wiki/Configure-Certificate-for-Unattended-Powershell-Access
#
# AppID is the ID of the Azure app setup above
# TenantID can be found using Get-AzureADTenantDetail  (see ObjectId property, auth with Connect-AzureAD first)
# Organization is the onmicrosoft.com address for the tenant
# CertificateThumbprint can be found using: Get-ChildItem -path ‘Cert:\*’ -Recurse |where {$_.Subject -like ‘*User Audit*’}
#
# Example: @{
#    "AppID" = "9220-9add-48d9-9c59-0e0b3"
#    "TenantID" = "b4e5-6420-4a9c-b20b-7a1b54"
#    "Organization" = "sts.onmicrosoft.com"
#    "CertificateThumprint" = "1DB7ACA9E26A62D8594FE"
#  }
#
$O365UnattendedLogin = @{
  AppID = ""
  TenantID = ""
  Organization = ""
  CertificateThumbprint = ""
}

####################
# $ExchangeServerFQDN
#
# Set this to the fully qualified domain name of your exchange server (if on a different server). 
# If exchange is on the current server, leave it blank.
# Only used if $CheckEmail is $true and $EmailType is "Exchange"
#
# Example: exchange01.sts.local
#
$ExchangeServerFQDN = ""

####################
# $ADUserFolders
# 
# Set this to the folders in AD that contain billable employees, including enabled and disabled accounts (but not service accounts).
# Based on the $ADIncludeSubFolders variable, these folders can either include or disclude nested folders.
# This is an array and you can include multiple folders, separate each by a comma.
#
# Example: "Users"
#
$ADUserFolders = @(
	"Users"
)

####################
# $ADIncludeSubFolders
# 
# Set this to $true if you want the script to query subfolders inside the $ADUserFolders.
#
$ADIncludeSubFolders = $true 

####################
# $EmailOnlyGroupsIgnore
# 
# Set this to the groups in AD to ignore on email only accounts
# This only takes effect if $EmailOnlyHaveAD is $true and the $EmailType is "O365"
# When checking for Email Only accounts that have an AD account, the script assumes an AD account with no groups and an O365 account is email only,
# if there are certain groups that give access to mailing lists or online services, you can list them here to have them be ignored in this check 
#
$EmailOnlyGroupsIgnore = @(
	"Domain Users", "*Email*", "*Contacts*", "*Office365*", "*O365*"
)

####################
# $InactivityO365Preference
# 
# When doing inactivity checks, the audit looks at both AD and the email system. It will flag each separately.
# If this organization has AD and email accounts for employee's but they rarely use their AD accounts, set this to $true.
# It will then give preference to O365 activity and if the O365 account is active, it won't flag the AD account for being inactive.
# IMPORTANT Note! If you decide not to get mailbox statistics when running the script, it will not check inactivity for AD or O365.
#
$InactivityO365Preference = $false 

####################
# $TotalsByLocation
# 
# When exporting a billing report, if $true, a section will be included with the total amount of billed and unbilled users per-location.
#
$TotalsByLocation = $false 

####################
# $EmailFrom
#
# Set the email address and name you want to send user audit emails from
#
# Example: @{
#   Email = 'user.audit@sts.com'
#   Name = "User Audit"
# }
#
$EmailFrom = @{
  Email = 'user.audit@sts.com'
  Name = "User Audit"
}

####################
# $EmailTo_Audit
#
# Set the email addresses and names you want to send user audit emails to
# For user audit corrections / suggested fixes
#
# Example: @(
#   @{
#      Email = 'support@sts.com'
#      Name = "Sea to Sky Helpdesk"
#   }
# )
#
$EmailTo_Audit = @(
  @{
    Email = 'support@sts.com'
    Name = "Sea to Sky Helpdesk"
  }
)

####################
# $EmailTo_BillingUpdate
#
# Set the email addresses and names you want to send user audit emails to
# For billing updates (after corrects, how the bill needs to change)
#
# Example: @(
#   @{
#      Email = 'accounting@sts.com'
#      Name = "Sea to Sky Accounting"
#   }
# )
#
$EmailTo_BillingUpdate = @(
  @{
    Email = 'accounting@sts.com'
    Name = "Sea to Sky Accounting"
  }
)

####################
# $O365StandardLicenses
#
# Map ITG types to the O365 license types that generally should be used for that type
# For the O365 license audit
# This should be an array of hashtables where each hashtable is a set of mappings
# Within the hashtable should be 2 arrays, 1 under the index Types, the 2nd under the index Licenses
# For 'Types', use any ITG types or the 4 special types: "EmployeeContactTypes", "BilledContactTypes", "UnbilledContactTypes" & "ConvertToEmployeeTypes" (correspond to the below contact type mappings)
# For 'Licenses', use any O365 SkuPartNumber (see the keys in O365Licenses.ps1), or 'None' which will allow no licenses for that type
# Types will be matched to as many groups as they exist in and will be allowed any license in one of those groups, the exception being "None"
# Anything in the $O365LicenseTypes_Primary array will be checked and considered wrong if not allowed here, anything in the secondary list will be allowed regardless
#
# Example: @(
#   @{
#       Types = @("BilledContactTypes", "Internal IT")
#       Licenses = @("SPE_E5", "SPE_E3", "SPB", "O365_BUSINESS_PREMIUM", "SMB_BUSINESS_PREMIUM")
#    },
#    @{
#       Types = @("Employee - Email Only", "Contractor")
#       Licenses = @("O365_BUSINESS_ESSENTIALS", "SMB_BUSINESS_ESSENTIALS", "STANDARDPACK", "EXCHANGESTANDARD", "EXCHANGEENTERPRISE", "EXCHANGEESSENTIALS")
#    },
#    @{
#      Types = @("Terminated")
#      Licenses = @("None")
#    }
# )
#
$O365StandardLicenses = @(
   @{
       Types = @("BilledContactTypes", "Internal IT")
       Licenses = @("SPE_E5", "SPE_E3", "SPB", "O365_BUSINESS_PREMIUM", "SMB_BUSINESS_PREMIUM")
    },
    @{
       Types = @("Employee - Email Only", "Contractor")
       Licenses = @("O365_BUSINESS_ESSENTIALS", "SMB_BUSINESS_ESSENTIALS", "STANDARDPACK", "EXCHANGESTANDARD", "EXCHANGEENTERPRISE", "EXCHANGEESSENTIALS", "EXCHANGEDESKLESS")
    },
    @{
      Types = @("Terminated")
      Licenses = @("None")
    }
)


##############################################################################################
##################################  Contact Type Mappings  ###################################
####  The below values modify contact type mappings and usually don't need to be modified.
####  Only modify these if you wish to fine-tune the reports/audit.
##############################################################################################

####################
# $EmployeeContactTypes
# 
# All contact types in IT Glue that are considered regular employees. 
# These contact types will be checked to see if they have been disabled.
#
$EmployeeContactTypes = @( 
	"Approver", "Champion", "Contractor", "Decision Maker", "Employee", 
	"Employee - Email Only", "Employee - Part Time", "Employee - Temporary", "Employee - Multi User",
	"Influencer", "Internal IT", "Management", "Owner", "Shared Account", "Terminated", "Employee - On Leave"
)

####################
# $BilledContactTypes
# 
# All contact types in IT Glue that are considered billed employees.
# These contact types will be shown on the billed user list.
#
$BilledContactTypes = @(
	"Approver", "Champion", "Contractor", "Decision Maker", "Employee", 
	"Employee - Part Time", "Employee - Temporary", "Employee - Multi User",
	"Influencer", "Management", "Owner"
)

####################
# $UnbilledContactTypes
# 
# All contact types in IT Glue that are considered unbilled employees.
# These contact types will be shown on the billed user list as "unbilled accounts"
#
$UnbilledContactTypes = @(
	"Employee - Email Only", "Internal IT", "Shared Account", "Employee - On Leave"
)

####################
# $ConvertToEmployeeTypes
# 
# These contact types are billed employee's with special categorizations in IT Glue. For example management.
# They will be converted to the type "Employee" on the billing report.
#
$ConvertToEmployeeTypes = @(
	"Approver", "Champion", "Decision Maker",
	"Influencer", "Management", "Owner"
)


##############################################################################################
###################################  HTML Email Template  ####################################
####  The below variable is an HTML email template used by the User Billing Update script
####  You should use it with string formatting like so: $EmailTemplate -f "Intro", "Title", "Body", "Footer"
####  There are a few locations in the body where you can enter data through string formatting:
####	0 - The intro line, e.g. 'Contact discrepancies were found at Norland Limited:'
####	1 - The title (in bold), e.g. 'Contract Issues'
####	2 - The body, this should be written in html and can be any length you wish, e.g. <ul><li>Issue #1</li> <li>Issue #2</li></ul>
####	3 - Optional footer text at the end, e.g. 'Please correct these issues before June 11th, at that time billing will be updated.'
##############################################################################################
$EmailTemplate = '
<!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Simple Transactional Email</title>
    <style>
    /* -------------------------------------
        INLINED WITH htmlemail.io/inline
    ------------------------------------- */
	.mobile_table_fallback {{
		display: none;
	}}
    /* -------------------------------------
        RESPONSIVE AND MOBILE FRIENDLY STYLES
    ------------------------------------- */
    @media only screen and (max-width: 620px) {{
      table[class=body] h1 {{
        font-size: 28px !important;
        margin-bottom: 10px !important;
      }}
      table[class=body] p,
            table[class=body] ul,
            table[class=body] ol,
            table[class=body] td,
            table[class=body] span,
            table[class=body] a {{
        font-size: 16px !important;
      }}
      table[class=body] .wrapper,
            table[class=body] .article {{
        padding: 10px !important;
      }}
      table[class=body] .content {{
        padding: 0 !important;
      }}
      table[class=body] .container {{
        padding: 0 !important;
        width: 100% !important;
      }}
      table[class=body] .main {{
        border-left-width: 0 !important;
        border-radius: 0 !important;
        border-right-width: 0 !important;
      }}
      table[class=body] .btn table {{
        width: 100% !important;
      }}
      table[class=body] .btn a {{
        width: 100% !important;
      }}
      table[class=body] .img-responsive {{
        height: auto !important;
        max-width: 100% !important;
        width: auto !important;
      }}
	  table.desktop_only_table {{
		  display: none;
	  }}
	  .mobile_table_fallback {{
		  display: block !important;
	  }}
    }}

    /* -------------------------------------
        PRESERVE THESE STYLES IN THE HEAD
    ------------------------------------- */
    @media all {{
      .ExternalClass {{
        width: 100%;
      }}
      .ExternalClass,
            .ExternalClass p,
            .ExternalClass span,
            .ExternalClass font,
            .ExternalClass td,
            .ExternalClass div {{
        line-height: 100%;
      }}
      .apple-link a {{
        color: inherit !important;
        font-family: inherit !important;
        font-size: inherit !important;
        font-weight: inherit !important;
        line-height: inherit !important;
        text-decoration: none !important;
      }}
      #MessageViewBody a {{
        color: inherit;
        text-decoration: none;
        font-size: inherit;
        font-family: inherit;
        font-weight: inherit;
        line-height: inherit;
      }}
    }}
    </style>
  </head>
  <body class="" style="background-color: #f6f6f6; font-family: sans-serif; -webkit-font-smoothing: antialiased; font-size: 14px; line-height: 1.4; margin: 0; padding: 0; -ms-text-size-adjust: 100%; -webkit-text-size-adjust: 100%;">
    <span class="preheader" style="color: transparent; display: none; height: 0; max-height: 0; max-width: 0; opacity: 0; overflow: hidden; mso-hide: all; visibility: hidden; width: 0;">This is preheader text. Some clients will show this text as a preview.</span>
    <table border="0" cellpadding="0" cellspacing="0" class="body" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background-color: #f6f6f6;">
      <tr>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
        <td class="container" style="font-family: sans-serif; font-size: 14px; vertical-align: top; display: block; Margin: 0 auto; max-width: 580px; padding: 10px; width: 580px;">
          <div class="content" style="box-sizing: border-box; display: block; Margin: 0 auto; max-width: 580px; padding: 10px;">

            <!-- START CENTERED WHITE CONTAINER -->
            <table class="main" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%; background: #ffffff; border-radius: 3px;">

              <!-- START MAIN CONTENT AREA -->
              <tr>
                <td class="wrapper" style="font-family: sans-serif; font-size: 14px; vertical-align: top; box-sizing: border-box; padding: 20px;">
                  <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                    <tr>
                      <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">{0}</p>
						<br />
                        <p style="font-family: sans-serif; font-size: 18px; font-weight: normal; margin: 0; Margin-bottom: 15px;"><strong>{1}</strong></p>
                        {2}
						<br />
                        <p style="font-family: sans-serif; font-size: 14px; font-weight: normal; margin: 0; Margin-bottom: 15px;">{3}</p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

            <!-- END MAIN CONTENT AREA -->
            </table>

            <!-- START FOOTER -->
            <div class="footer" style="clear: both; Margin-top: 10px; text-align: center; width: 100%;">
              <table border="0" cellpadding="0" cellspacing="0" style="border-collapse: separate; mso-table-lspace: 0pt; mso-table-rspace: 0pt; width: 100%;">
                <tr>
                  <td class="content-block" style="font-family: sans-serif; vertical-align: top; padding-bottom: 10px; padding-top: 10px; font-size: 12px; color: #999999; text-align: center;">
                    <span class="apple-link" style="color: #999999; font-size: 12px; text-align: center;">Sea to Sky Network Solutions, 2554 Vine Street, Vancouver BC V6K 3L1</span>
                  </td>
                </tr>
              </table>
            </div>
            <!-- END FOOTER -->

          <!-- END CENTERED WHITE CONTAINER -->
          </div>
        </td>
        <td style="font-family: sans-serif; font-size: 14px; vertical-align: top;">&nbsp;</td>
      </tr>
    </table>
  </body>
</html>'
