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
	krbtgt               = [4]uint8{246, 1, 0, 0} //S-1-5-domain-502

	DomainControllersGroup = [4]uint8{4, 2, 0, 0} //S-1-5-domain-516
	DomainComputersGroup   = [4]uint8{3, 2, 0, 0} //S-1-5-domain-515

)

//LDAP search Queries
var (
	AllEntries = "(cn=*)"
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
)

//LDAP OID Favourites
const (
	DomainControllerOID = 0x7A
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
