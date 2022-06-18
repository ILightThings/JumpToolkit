package misc

//TCP
var (
	CommonTCPPorts = []int{21, 22, 23, 25, 53, 67, 69, 80, 88, 110, 111, 115, 135, 139, 143, 161, 389, 443, 445, 464, 993, 995, 1723, 3306, 3389, 5900, 8080, 8081, 8443}
)

//LDAP SIDS
var (
	DomainAdminsGroup          = "512" //S-1-5-domain-512
	EnterpriseAdminsGroup      = "519" //S-1-5-rootdomain-519
	BuiltInAdministratorsGroup = "S-1-5-32-544"

	BuiltInAdministrator = "500" //S-1-5-domain-500
	krbtgt               = "502" //S-1-5-domain-502

	DomainControllersGroup = "516" //S-1-5-domain-516
	DomainComputersGroup   = "515" //S-1-5-domain-515

)

//Naming and Catches
var (
	AdminAccountName   = []string{"a", "adm", "admin", "administrator", "tech"}
	ServiceAccountName = []string{"svc", "service"}
	ITAccounts         = []string{"it", "info", "information", "tech"}
)
