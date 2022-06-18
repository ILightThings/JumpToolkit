package jump_ldap_scanner

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

type options struct {
	username   string
	password   string
	LDAPIPaddr string
	LDAPPort   int
}

func main() {}

func dialLAP(opt *options) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", opt.LDAPIPaddr, opt.LDAPPort)
	return ldap.Dial("tcp", address)
}

//Test Unauthenticated Bind
func testAnonymousBind(conn *ldap.Conn) error {
	return conn.UnauthenticatedBind("Guest")
}

func authenticateToLDAP() {}

func extractAllEntries() {}

func getGPOs() {}

//Domain Admins, Built In Administrators, Enterprise Admins, show all items
func getHighValuesMembers() {}

func getDomainControllers() {}

//Property: operatingsystem
func getOutDatedOS() {}

// Property: serviceprincipalnames
func getSPNS() {}

func getDescriptions() {}
