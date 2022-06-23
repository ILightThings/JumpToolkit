package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"log"
	"os"
	"strings"
)

type SortedResults struct {
	DomainControllers   []*ldap.Entry
	Users               []*ldap.Entry
	Groups              []*ldap.Entry
	EntriesDescriptions []*ldap.Entry
	HighValueGroups     BuiltInHighValueGroups
	BuiltInAccounts     BuiltInAccounts
	EntriesWithSPN      []*ldap.Entry
}

type BuiltInHighValueGroups struct {
	DomainAdmins    *ldap.Entry
	BuiltInAdmins   *ldap.Entry
	EnterpriseAdmin *ldap.Entry
}

type BuiltInAccounts struct {
	Krbtgt        *ldap.Entry
	Administrator *ldap.Entry
	Guest         *ldap.Entry
}

type Group struct {
	Members []string
	Entry   *ldap.Entry
}

type Options struct {
	username string
	password string
	domain   string

	//"dc=example,dc=local" for exmaple.local
	domainCN     string
	LDAPIPaddr   string
	LDAPPort     int
	LDAPDomainDC string
	DomainSID    string
}

// example.local -> DC=example,DC=local
func (o *Options) BuildCN() {
	dcparts := strings.Split(strings.TrimSpace(o.domain), ".")
	o.LDAPDomainDC = dcparts[0]
	for i := range dcparts {
		dcparts[i] = fmt.Sprintf("dc=%s", dcparts[i])
	}
	o.domainCN = strings.Join(dcparts, ",")

}

func main() {
	parser := argparse.NewParser("jump_port_scan", "A quick, concurrent port scanner, that can be dropped onto a victim machine and ran.")

	usernamearg := parser.String("u", "username", &argparse.Options{Required: true})
	passwordarg := parser.String("p", "password", &argparse.Options{Required: true})
	ldapdomainarg := parser.String("d", "domain", &argparse.Options{Required: true, Help: "DNS name of domain. Example: paperproducts.local "})
	ldapiparg := parser.String("t", "ldap-server", &argparse.Options{Required: true, Help: "IP of LDAP Server"})
	ldapportarg := parser.Int("P", "port", &argparse.Options{Required: false, Default: 389})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	opt := Options{
		username:   *usernamearg,
		password:   *passwordarg,
		LDAPIPaddr: *ldapiparg,
		LDAPPort:   *ldapportarg,
		domain:     *ldapdomainarg,
	}
	opt.BuildCN()

	conn, err := DialLDAP(&opt)
	if err != nil {
		log.Fatal(err)
	}

	err = BindLDAP(conn, &opt)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	results, err := ExtractAllEntries(conn, &opt)
	if err != nil {
		log.Fatal(err)
	}

	sorted := SortResults(results.Entries)
	for x := range sorted.Users {
		fmt.Println(sorted.Users[x].DN)
	}

}

func DialLDAP(opt *Options) (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", opt.LDAPIPaddr, opt.LDAPPort)
	return ldap.Dial("tcp", address)
}

//Test Unauthenticated Bind
func AnonymousBind(conn *ldap.Conn) error {
	return conn.UnauthenticatedBind("Guest")
}

//Uses Display Name or CN for username
func BindLDAP(conn *ldap.Conn, opt *Options) error {
	err := conn.Bind(opt.username, opt.password)
	return err
}

//Build Search LDAP Object
func buildSearch(opt *Options, filter string) *ldap.SearchRequest {
	s := ldap.NewSearchRequest(
		opt.domainCN,
		ldap.ScopeWholeSubtree,
		0,
		0,
		0,
		false,
		filter,
		[]string{},
		nil,
	)
	return s
}

//Make LDAP Request for all items
func ExtractAllEntries(conn *ldap.Conn, opt *Options) (*ldap.SearchResult, error) {
	s := buildSearch(opt, misc.AllEntries)
	results, err := conn.SearchWithPaging(s, 100)
	return results, err
}

/*//Return Groups -- REPLACED
func GetGroupsFromResults(result []*ldap.Entry) []*ldap.Entry {
	var Groups []*ldap.Entry
	for _, x := range result {
		for _, y := range x.Attributes {
			if y.Name == "objectClass" {
				for _, z := range y.Values {
					if z == "group" {
						Groups = append(Groups, x)
						continue
					}

				}
			}
		}
	}
	return Groups

}*/

//Get Users from list of entries
func GetUsersFromResults(result []*ldap.Entry) []*ldap.Entry {
	var people []*ldap.Entry
	for _, x := range result {
		personClass := 0
		for _, y := range x.Attributes {
			switch y.Name {
			case "objectClass":
				for _, z := range y.Values {
					if z == "user" {
						personClass++
					}
				}
			case "objectCategory":
				for _, z := range y.Values {
					if strings.Contains(z, "CN=Person") {
						personClass++
					}
				}

			}

		}
		if personClass == 2 {
			people = append(people, x)
		}
	}
	return people
}

//Sort Entries into groups defined
func SortResults(result []*ldap.Entry) SortedResults {
	var results SortedResults
	for _, entry := range result {
		OID := 0
		OBJCat := 0

		for _, y := range entry.Attributes {
			switch y.Name {

			//Classify using Object SID
			case "objectSid":
				for _, sid := range y.ByteValues {
					//fmt.Printf("%s -- %+v\n", entry.DN, sid)

					var RID [4]uint8
					for b := range RID {
						RID[b] = sid[len(sid)-4+b]
					}
					switch RID {
					case misc.DomainAdminsGroup:
						results.HighValueGroups.DomainAdmins = entry

					case misc.EnterpriseAdminsGroup:
						results.HighValueGroups.EnterpriseAdmin = entry

					case misc.BuiltInAdministratorsGroup:
						results.HighValueGroups.BuiltInAdmins = entry

					case misc.BuiltInAdministrator:
						results.BuiltInAccounts.Administrator = entry
					}

				}

			//Find Results with Descriptions
			case "description":
				for _, descriptions := range y.Values {
					if descriptions != "" {
						results.EntriesDescriptions = append(results.EntriesDescriptions, entry)
						break
					}
				}
			case "objectCategory":
				for _, z := range y.Values {
					if strings.Contains(z, "CN=Person") {
						OBJCat = OBJCat + misc.OBJCAT_Person
					}
				}

			//
			case "servicePrincipalName":
				for _, spn := range y.Values {
					if spn != "" {
						results.EntriesWithSPN = append(results.EntriesWithSPN, entry)
						break
					}
				}

			case "objectClass":
				for _, z := range y.Values {
					switch z {
					case "domain":
						OID = OID + misc.OID_Domain
					case "top":
						OID = OID + misc.OID_Top
					case "domainDNS":
						OID = OID + misc.OID_DomainDNS
					case "user":
						OID = OID + misc.OID_User
					case "person":
						OID = OID + misc.OID_Person
					case "organizationalPerson":
						OID = OID + misc.OID_OrganizationalPerson
					case "computer":
						OID = OID + misc.OID_Computer
					case "group":
						OID = OID + misc.OID_Group
					}
				}
			}
		}

		//Get Domain Controllers
		if (OID & misc.DomainControllerOID) == misc.DomainControllerOID {
			results.DomainControllers = append(results.DomainControllers, entry)
		}
		if (OID & misc.OID_Group) == misc.OID_Group {
			results.Groups = append(results.Groups, entry)
		}

		if (OID&misc.OID_User) == misc.OID_User && (OBJCat&misc.OBJCAT_Person) == misc.OBJCAT_Person {

			results.Users = append(results.Users, entry)

		}
	}
	return results

}

//Return if Entry is user. For some reason, Domain Controllers have the same objectClasses as people.
func isTrueUser(entry *ldap.Entry) bool {
	for _, y := range entry.Attributes {
		switch y.Name {

		}
	}
	return false
}

//Extract members from group
func GetMembersOfGroup(entry *ldap.Entry) []string {
	var membersArray []string
	for attributes := range entry.Attributes {
		if entry.Attributes[attributes].Name == "member" {
			for members := range entry.Attributes[attributes].Values {
				membersArray = append(membersArray, entry.Attributes[attributes].Values[members])
			}
		}
	}
	return membersArray

}

func getGPOs() {}

//Domain Admins, Built In Administrators, Enterprise Admins, show all items
func getHighValuesMembers() {}

func getDomainControllers() {}

//Property: operatingsystem
func getOutDatedOS() {}

// Property: serviceprincipalnames
func getSPNS() {}
