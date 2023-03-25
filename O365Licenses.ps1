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
	EXCHANGESTANDARD = "Exchange Online (Plan 1)"
	EXCHANGEENTERPRISE = "Exchange Online (Plan 2)"
	EXCHANGEESSENTIALS = "Exchange Online Essentials"
	EXCHANGE_S_ESSENTIALS = "Exchange Online Essentials"
	EXCHANGEDESKLESS = "Exchange Online Kiosk"
	EXCHANGETELCO = "Exchange Online POP"
	WACONEDRIVESTANDARD = "OneDrive for Business (Plan 1)"
	WACONEDRIVEENTERPRISE = "OneDrive for Business (Plan 2)"
	SHAREPOINTSTANDARD = "SharePoint Online (Plan 1)"
	SHAREPOINTENTERPRISE = "SharePoint Online (Plan 2)"
}

####################
# $O365LicenseTypes_Secondary
# 
# A list of 'secondary' office 365 license types mapped to their license name
# These are any other licenses that could be used in tandem with 1 of the Primary licenses (e.g. Project/Visio)
#
$O365LicenseTypes_Secondary = [ordered]@{
  WIN10_PRO_ENT_SUB = "Windows 10 Enterprise E3"
	WIN10_VDA_E5 = "Windows 10 Enterprise E5"
  ATP_ENTERPRISE = "Exchange Online Advanced Threat Protection"
  EMS = "Enterprise Mobility Suite"
  PROJECTPROFESSIONAL = "Project Professional"
  FLOW_FREE = "Microsoft Flow Free"
  POWER_BI_STANDARD = "Power-BI Standard"
  VISIOCLIENT = "Visio Pro Online"
  MCOMEETADV = "PSTN conferencing"
  POWERAPPS_VIRAL = "Microsoft Power Apps & Flow"
  SMB_APPS = "Microsoft Business Apps"
  DYN365_FINANCIALS_TEAM_MEMBERS_SKU = 'Dynamics 365 for Team Members Business Edition'
  
  SWAY = 'SWAY'
  NBPOSTS = 'Social Engagement Additional 10K Posts'
  PROJECT_MADEIRA_PREVIEW_IW_SKU = 'Dynamics 365 for Financials for IWs'
  POWER_BI_INDIVIDUAL_USE = 'Power BI Individual User'
  MCOPSTNPP = 'Skype for Business Communication Credits - Paid?'
  INTUNE_O365 = 'INTUNE'
  DESKLESSWOFFPACK = 'Office 365 (Plan K2)'
  DESKLESSPACK_YAMME = 'Office 365 (Plan K1) with Yammer'
  STANDARDWOFFPACK_GOV = 'Microsoft Office 365 (Plan G2) for Government'
  PROJECT_CLIENT_SUBSCRIPTION = 'Project Pro for Office 365'
  ENTERPRISEWITHSCAL_GOV = 'Microsoft Office 365 (Plan G4) for Government'
  STANDARDWOFFPACK_STUDENT = 'Microsoft Office 365 (Plan A2) for Students'
  STANDARDWOFFPACK_IW_STUDENT = 'Office 365 Education for Students'
  SHAREPOINTWAC = 'Office Online'
  CRMSTANDARD = 'Microsoft Dynamics CRM Online Professional'
  CRMTESTINSTANCE = 'CRM Test Instance'
  EXCHANGEARCHIVE_ADDON = 'Exchange Online Archiving For Exchange Online'
  VISIOONLINE_PLAN1 = 'Visio Online Plan 1'
  CRMIUR = 'CMRIUR'
  PROJECTWORKMANAGEMENT = 'Office 365 Planner Preview'
  PROJECTONLINE_PLAN_2 = 'Project Online and PRO'
  RIGHTSMANAGEMENT = 'Rights Management'
  LOCKBOX = 'Customer Lockbox'
  INTUNE_STORAGE = 'Intune Extra Storage'
  EXCHANGE_ANALYTICS = 'Delve Analytics'
  WINDOWS_STORE = 'Windows Store for Business'
  PROJECTONLINE_PLAN_2_FACULTY = 'Project Online for Faculty Plan 2'
  FLOW_P1 = 'Microsoft Flow Plan 1'
  DESKLESSPACK = 'Office 365 (Plan K1)'
  ENTERPRISEPACK_STUDENT = 'Office 365 (Plan A3) for Students'  
  ENTERPRISEPACK_FACULTY = 'Office 365 (Plan A3) for Faculty'
  PROJECTESSENTIALS = 'Project Lite'
  MCOSTANDARD = 'Skype for Business Online Standalone Plan 2'
  OFFICESUBSCRIPTION_FACULTY = 'Office 365 ProPlus for Faculty'
  POWER_BI_INDIVIDUAL_USER = 'Power BI for Office 365 Individual'
  ENTERPRISEPACKWSCAL = 'Office 365 (Plan E4)'
  SHAREPOINTDESKLESS_GOV = 'SharePoint Online Kiosk'
  EQUIVIO_ANALYTICS = 'Office 365 Advanced eDiscovery'
  ESKLESSWOFFPACK_GOV = 'Microsoft Office 365 (Plan K2) for Government'
  PROJECT_ESSENTIALS = 'Project Lite'
  AAD_PREMIUM = 'Azure Active Directory Premium'
  SHAREPOINTDESKLESS = 'SharePoint Online Kiosk'
  MCOSTANDARD_MIDMARKET = 'Lync Online (Plan 1)'
  IT_ACADEMY_AD = 'Microsoft Imagine Academy'
  MCVOICECONF = 'Skype for Business Online (Plan 3)'
  DYN365_ENTERPRISE_P1_IW = 'Dynamics 365 P1 Trial for Information Workers'
  RIGHTSMANAGEMENT_STANDARD_STUDENT = 'Information Rights Management for Students'
  PARATURE_SUPPORT_ENHANCED = 'Parature Support Enhanced'
  DESKLESS = 'Microsoft StaffHub'
  MCOPSTN2 = 'Domestic and International Calling Plan'
  ATA = 'Advanced Threat Analytics'
  DESKLESSPACK_GOV = 'Microsoft Office 365 (Plan K1) for Government'
  YAMMER_MIDSIZE = 'Yammer'
  EXCHANGESTANDARD_GOV = 'Microsoft Office 365 Exchange Online (Plan 1) only for Government'
  PROJECTONLINE_PLAN1_STUDENT = 'Project Online for Students'
  SQL_IS_SSIM = 'Power BI Information Services'
  INTUNE_A = 'Windows Intune Plan A'
  SHAREPOINTSTORAGE = 'SharePoint storage'
  LOCKBOX_ENTERPRISE = 'Customer Lockbox'
  STANDARDWOFFPACKPACK_STUDENT = 'Office 365 (Plan A2) for Students'
  PROJECTONLINE_PLAN_1_STUDENT = 'Project Online for Students Plan 1'
  RIGHTSMANAGEMENT_STANDARD_FACULTY = 'Information Rights Management for Faculty'
  OFFICESUBSCRIPTION_STUDENT = 'Office ProPlus Student Benefit'
  WACSHAREPOINTENT = 'Office Web Apps with SharePoint (Plan 2)'
  CRMSTORAGE = 'Microsoft Dynamics CRM Online Additional Storage'
  CRMINSTANCE = 'Dynamics CRM Online Additional Production Instance'
  PROJECTONLINE_PLAN1_FACULTY = 'Project Online for Faculty'
  DYN365_TEAM_MEMBERS = 'Dynamics 365 Team Members'
  STANDARDPACK_FACULTY = 'Office 365 (Plan A1) for Faculty'
  CRMPLAN1 = 'Dynamics CRM Online Essential'
  ENTERPRISEPACK_GOV = 'Microsoft Office 365 (Plan G3) for Government'
  STANDARDPACK_GOV = 'Microsoft Office 365 (Plan G1) for Government'
  OFFICE_PRO_PLUS_SUBSCRIPTION_SMBIZ = 'Office ProPlus'
  YAMMER_ENTERPRISE_STANDALONE = 'Yammer Enterprise'
  PROJECTONLINE_PLAN_2_STUDENT = 'Project Online for Students Plan 2'
  SHAREPOINTPARTNER = 'SharePoint Online Partner Access'
  VIDEO_INTEROP = 'Polycom Skype Meeting Video Interop for Skype for Business'
  SHAREPOINTLITE = 'SharePoint Online (Plan 1)'
  POWERAPPS_INDIVIDUAL_USER = 'Microsoft PowerApps and Logic flows'
  SHAREPOINTENTERPRISE_GOV = 'SharePoint Plan 2G'
  ProjectPremium = 'Project Online Premium'
  PROJECTONLINE_PLAN_1_FACULTY = 'Project Online for Faculty Plan 1'
  DYN365_ENTERPRISE_SALES = 'Dynamics Office 365 Enterprise Sales'
  DYN365_ENTERPRISE_TEAM_MEMBERS = 'Dynamics 365 For Team Members Enterprise Edition'
  RMS_S_ENTERPRISE = 'Azure Active Directory Rights Management'
  MCOPSTN1 = 'Skype for Business PSTN Domestic Calling Plan'
  MFA_PREMIUM = 'Azure Multi-Factor Authentication'
  BI_AZURE_P1 = 'Power BI Reporting and Analytics'
  PARATURE_FILESTORAGE_ADDON = 'Parature File Storage Addon'
  EXCHANGE_S_ENTERPRISE = 'Exchange Online (Plan 2)'
  SHAREPOINTENTERPRISE_EDU = 'SharePoint (Plan 2) for EDU'
  MCOVOICECONF = 'Lync Online (Plan 3)'
  ONEDRIVESTANDARD = 'OneDrive'
  EXCHANGE_S_ENTERPRISE_GOV = 'Exchange Plan 2G'
  EMSPREMIUM = 'ENTERPRISE MOBILITY + SECURITY E5'
  YAMMER_ENTERPRISE = 'Yammer Enterprise'
  POWER_BI_STANDALONE = 'Power BI Stand Alone'
  EXCHANGE_S_DESKLESS_GOV = 'Exchange Kiosk'
  SHAREPOINTWAC_GOV = 'Office Online for Government'
  NBPROFESSIONALFORCRM = 'Social Listening Professional'
  ENTERPRISEWITHSCAL_STUDENT = 'Office 365 (Plan A4) for Students'
  DYN365_FINANCIALS_BUSINESS_SKU = 'Dynamics 365 for Financials Business Edition'
  MCOPSTNC = 'Skype for Business Communication Credits - None?'
  OFFICESUBSCRIPTION_GOV = 'Office ProPlus'
  SPZA_IW = 'App Connect'
  POWER_BI_PRO = 'Power BI Pro'
  CRMPLAN2 = 'Dynamics CRM Online Basic'
  ECAL_SERVICES = 'ECAL'
  EXCHANGE_S_DESKLESS = 'Exchange Online Kiosk'
  DYN365_ENTERPRISE_PLAN1 = 'Dynamics 365 Customer Engagement Plan Enterprise Edition'
  BI_AZURE_P2 = 'Power BI Pro'
  STANDARDPACK_STUDENT = 'Office 365 (Plan A1) for Students'
  EXCHANGESTANDARD_STUDENT = 'Exchange Online (Plan 1) for Students'
  MCOPLUSCAL = 'Skype for Business Plus CAL'
  ENTERPRISEPACKLRG = 'Enterprise Plan E3'
  EOP_ENTERPRISE_FACULTY = 'Exchange Online Protection for Faculty'
  SHAREPOINTSTANDARD_YAMMER = 'Sharepoint Standard with Yammer'
  EOP_ENTERPRISE = 'Exchange Online Protection'
  ENTERPRISEPACK_B_PILOT = 'Office 365 (Enterprise Preview)'
  MCOLITE = 'Lync Online (Plan 1)'
  STANDARD_B_PILOT = 'Office 365 (Small Business Preview)'
  RIGHTSMANAGEMENT_ADHOC = 'Windows Azure Rights Management'
  POWER_BI_ADDON = 'Office 365 Power BI Addon'
  RMS_S_ENTERPRISE_GOV = 'Windows Azure Active Directory Rights Management'
  EXCHANGEENTERPRISE_GOV = 'Microsoft Office 365 Exchange Online (Plan 2) only for Government'
  EXCHANGE_S_STANDARD_MIDMARKET = 'Exchange Online (Plan 1)'
  SHAREPOINTENTERPRISE_MIDMARKET = 'SharePoint Online (Plan 1)'
  MCOIMP = 'Skype for Business Online (Plan 1)'
  EXCHANGE_L_STANDARD = 'Exchange Online (Plan 1)'
  PLANNERSTANDALONE = 'Planner Standalone'
  EXCHANGE_S_ARCHIVE_ADDON_GOV = 'Exchange Online Archiving'
  VISIO_CLIENT_SUBSCRIPTION = 'Visio Pro for Office 365'
  SHAREPOINTWAC_EDU = 'Office Online for Education'
  PROJECTCLIENT = 'Project Professional'
  STREAM = 'Stream'
  EXCHANGE_S_STANDARD = 'Exchange Online (Plan 2)'
  PARATURE_ENTERPRISE = 'Parature Enterprise'
  MCOSTANDARD_GOV = 'Lync Plan 2G'
  ENTERPRISEWITHSCAL_FACULTY = 'Office 365 (Plan A4) for Faculty'
  FLOW_P2 = 'Microsoft Flow Plan 2'
  AAD_BASIC = 'Azure Active Directory Basic'
  PROJECTONLINE_PLAN_1 = 'Project Online'
  EXCHANGEARCHIVE = 'Exchange Online Archiving'
  STANDARDWOFFPACKPACK_FACULTY = 'Office 365 (Plan A2) for Faculty'
  SHAREPOINT_PROJECT_EDU = 'Project Online for Education'
  INTUNE_A_VL = 'Intune (Volume License)'
  MICROSOFT_BUSINESS_CENTER = 'Microsoft Business Center'
  MCOEV = 'Microsoft Phone System'
  STANDARDWOFFPACK_IW_FACULTY = 'Office 365 Education for Faculty'
  DESKLESSWOFFPACK_GOV = 'Office 365 (Plan K2) for Government'
  WACSHAREPOINTSTD = 'Office Web Apps with SharePoint (Plan 1)'
  STANDARDWOFFPACK_FACULTY = 'Office 365 Education E1 for Faculty'
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
  "EXCHANGEDESKLESS", "EXCHANGETELCO",
  "ATP_ENTERPRISE", "THREAT_INTELLIGENCE", "FLOW_FREE_FLOW_P2_VIRAL"
)

# All licenses combined
$O365LicenseTypes = $O365LicenseTypes_Primary + $O365LicenseTypes_Secondary