package misc

//TCP
var (
	CommonTCPPorts = []int{21, 22, 23, 25, 53, 67, 69, 80, 88, 110, 111, 115, 135, 139, 143, 161, 389, 443, 445, 464, 993, 995, 1723, 3306, 3389, 5900, 8080, 8081, 8443}
)

//LDAP SIDS
var (
	DomainAdminsGroup          = [4]uint8{0, 2, 0, 0}  // S-1-5-domain-512 -> to hex -> to base 10 02 00
	EnterpriseAdminsGroup      = [4]uint8{7, 2, 0, 0}  // S-1-5-rootdomain-519
	BuiltInAdministratorsGroup = [4]uint8{32, 2, 0, 0} //"S-1-5-32-544"

	BuiltInAdministrator = [4]uint8{244, 1, 0, 0} //S-1-5-domain-500
	Krbtgt               = [4]uint8{246, 1, 0, 0} //S-1-5-domain-502
	Guest                = [4]uint8{245, 1, 0, 0}

	DomainControllersGroup = [4]uint8{4, 2, 0, 0} //S-1-5-domain-516
	DomainComputersGroup   = [4]uint8{3, 2, 0, 0} //S-1-5-domain-515

)

//LDAP search Queries
var (
	AllEntries = "(distinguishedName=*)"
)

//TODO COMPLETE THIS

//LDAP OID
const (
	OID_Domain               = 0x01
	OID_Top                  = 0x02
	OID_DomainDNS            = 0x04
	OID_User                 = 0x08
	OID_OrganizationalPerson = 0x10
	OID_Person               = 0x20
	OID_Computer             = 0x40
	OID_Group                = 0x80
	OID_PasswordPolicies     = 0x160
)

//LDAP OID Favourites
const (
	DomainControllerOID = 0x7A
)

//LDAP Object Catagory
const (
	OBJCAT_Person   = 0x01
	OBJCAT_Computer = 0x02
)

//LDAP AccountControl
const ( //https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
	UAC_SCRIPT                         = 0x0001
	UAC_ACCOUNTDISABLE                 = 0x0002
	UAC_HOMEDIR_REQUIRED               = 0x0008
	UAC_LOCKOUT                        = 0x0010
	UAC_PASSWD_NOTREQD                 = 0x0020
	UAC_PASSWD_CANT_CHANGE             = 0x0040
	UAC_ENCRYPTED_TEXT_PWD_ALLOWED     = 0x0080
	UAC_TEMP_DUPLICATE_ACCOUNT         = 0x0100
	UAC_NORMAL_ACCOUNT                 = 0x0200
	UAC_INTERDOMAIN_TRUST_ACCOUNT      = 0x0800
	UAC_WORKSTATION_TRUST_ACCOUNT      = 0x1000
	UAC_SERVER_TRUST_ACCOUNT           = 0x2000
	UAC_DONT_EXPIRE_PASSWORD           = 0x10000
	UAC_MNS_LOGON_ACCOUNT              = 0x20000
	UAC_SMARTCARD_REQUIRED             = 0x40000
	UAC_TRUSTED_FOR_DELEGATION         = 0x80000 //Unconstrained Delegation
	UAC_NOT_DELEGATED                  = 0x100000
	UAC_USE_DES_KEY_ONLY               = 0x200000
	UAC_DONT_REQ_PREAUTH               = 0x400000
	UAC_PASSWORD_EXPIRED               = 0x800000
	UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 // Constrained Delegation
	UAC_PARTIAL_SECRETS_ACCOUNT        = 0x04000000
)

const (
	OS_WindowsServer2019SE = 0x01
	OS_WindowServer2016SE  = 0x02
	OS_WindowServer2012SE  = 0x04
)

//Naming and Catches
var (
	AdminAccountName   = []string{"a", "adm", "admin", "administrator", "tech"}
	ServiceAccountName = []string{"svc", "service"}
	ITAccounts         = []string{"it", "info", "information", "tech"}
)
