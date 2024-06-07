##############################################################################################
####################################  License Mappings  ######################################
####  The below values modify license mappings and usually don't need to be modified.
####  Only modify these if Microsoft has added a new O365 license type or there are other
####   licenses you want to include in audit reports
##############################################################################################

####################
# $O365LicenseTypes_Primary
# 
# A list of 'primary' office 365 license types mapped to their license name
# These should be email licenses primarily (or OneDrive/SharePoint if not email), 
#  you can add other App types to the secondary array below
# A user should generally not have more than 1 license in this list
# The script looks through a users license and grabs the first one it sees that is in this list
# The licenses are in order of preference, from top to bottom
#
# You can find more codes here: https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference
# Or here: https://scripting.up-in-the.cloud/licensing/list-of-o365-license-skuids-and-names.html
#
$O365LicenseTypes_Primary = [ordered]@{
	SPE_E5 = "Microsoft 365 E5"
	SPE_E3 = "Microsoft 365 E3"
	SPB = "Microsoft 365 Business Premium"
	O365_BUSINESS_PREMIUM = "Microsoft 365 Business Standard"
	SMB_BUSINESS_PREMIUM = "Microsoft 365 Business Standard"
	O365_BUSINESS_ESSENTIALS = "Microsoft 365 Business Basic"
	SMB_BUSINESS_ESSENTIALS = "Microsoft 365 Business Basic"
	O365_BUSINESS = "Microsoft 365 Apps for Business"
	SMB_BUSINESS = "Microsoft 365 Apps for Business"
	OFFICESUBSCRIPTION = "Microsoft 365 Apps for Enterprise"
	STANDARDPACK = "Office 365 E1"
	STANDARDWOFFPACK = "Office 365 E2"
	ENTERPRISEPACK = "Office 365 E3"
	DEVELOPERPACK = "Office 365 E3 Developer"
	ENTERPRISEWITHSCAL = "Office 365 E4"
	ENTERPRISEPREMIUM = "Office 365 E5"
	ENTERPRISEPREMIUM_NOPSTNCONF = "Office 365 E5 without audio conferencing"
	MIDSIZEPACK = "Office 365 Midsize Business"
	LITEPACK = "Office 365 Small Business"
	LITEPACK_P2 = "Office 365 Small Business Premium"
  SPE_F1 = "Microsoft 365 F3"
	EXCHANGESTANDARD = "Exchange Online (Plan 1)"
	EXCHANGEENTERPRISE = "Exchange Online (Plan 2)"
	EXCHANGEESSENTIALS = "Exchange Online Essentials"
	EXCHANGE_S_ESSENTIALS = "Exchange Online Essentials"
	EXCHANGEDESKLESS = "Exchange Online Kiosk"
	EXCHANGETELCO = "Exchange Online POP"
  Teams_Ess = "Microsoft Teams Essentials"
  TEAMS_ESSENTIALS_AAD = "Microsoft Teams Essentials (AAD Identity)"
	WACONEDRIVESTANDARD = "OneDrive for Business (Plan 1)"
	WACONEDRIVEENTERPRISE = "OneDrive for Business (Plan 2)"
	SHAREPOINTSTANDARD = "SharePoint Online (Plan 1)"
	SHAREPOINTENTERPRISE = "SharePoint Online (Plan 2)"
}

####################
# $O365LicenseTypes_EmailOnly
# 
# A list of 'email-only' office 365 license types
# These are used for Office 365 only clients for checking if a user account is email only.
#

$O365LicenseTypes_EmailOnly = @(
  "O365_BUSINESS_ESSENTIALS", "SMB_BUSINESS_ESSENTIALS", "STANDARDPACK", "STANDARDWOFFPACK", 
  "EXCHANGESTANDARD", "EXCHANGEENTERPRISE", "EXCHANGEESSENTIALS", "EXCHANGE_S_ESSENTIALS",
  "EXCHANGEDESKLESS", "EXCHANGETELCO", "SPE_F1", "Teams_Ess", "TEAMS_ESSENTIALS_AAD", 
  "WACONEDRIVESTANDARD", "WACONEDRIVEENTERPRISE", "SHAREPOINTSTANDARD", "SHAREPOINTENTERPRISE",
  "ATP_ENTERPRISE", "THREAT_INTELLIGENCE", "FLOW_FREE_FLOW_P2_VIRAL"
)