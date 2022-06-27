package main

import (
	"github.com/akamensky/argparse"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/jump_ldap"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/printing"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/sorting"
	"log"
	"os"
)

type Group struct {
	Members []string
	Entry   *ldap.Entry
}

func main() {
	parser := argparse.NewParser("jump_port_scan", "A quick, concurrent port scanner, that can be dropped onto a victim machine and ran.")

	usernamearg := parser.String("u", "username", &argparse.Options{Required: true})
	passwordarg := parser.String("p", "password", &argparse.Options{Required: true})
	ldapdomainarg := parser.String("d", "domain", &argparse.Options{Required: true, Help: "DNS name of domain. Example: paperproducts.local "})
	ldapiparg := parser.String("t", "jump_ldap-server", &argparse.Options{Required: true, Help: "IP of LDAP Server"})
	ldapportarg := parser.Int("P", "port", &argparse.Options{Required: false, Default: 389})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	opt := jump_ldap.Options{
		Username:   *usernamearg,
		Password:   *passwordarg,
		LDAPIPaddr: *ldapiparg,
		LDAPPort:   *ldapportarg,
		Domain:     *ldapdomainarg,
	}
	opt.BuildCN()

	conn, err := jump_ldap.DialLDAP(&opt)
	if err != nil {
		log.Fatal(err)
	}

	err = jump_ldap.BindLDAP(conn, &opt)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()
	results, err := jump_ldap.ExtractAllEntries(conn, &opt)
	if err != nil {
		log.Fatal(err)
	}

	sorted := sorting.SortResults(results.Entries)
	printing.DisplayResults(&sorted)

}

/*//Return Groups -- REPLACED
func GetGroupsFromResults(result []*jump_ldap.Entry) []*jump_ldap.Entry {
	var Groups []*jump_ldap.Entry
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

//Return if Entry is user. For some reason, Domain Controllers have the same objectClasses as people. DEPERICATED
func isTrueUser(entry *ldap.Entry) bool {
	for _, y := range entry.Attributes {
		switch y.Name {

		}
	}
	return false
}

func getGPOs() {}

//Domain Admins, Built In Administrators, Enterprise Admins, show all items
func getHighValuesMembers() {}

func getDomainControllers() {}

//Property: operatingsystem
func getOutDatedOS() {}

// Property: serviceprincipalnames
func getSPNS() {}
