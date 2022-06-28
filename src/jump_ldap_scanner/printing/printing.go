package printing

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/sorting"
	"strings"
)

type PrettyPrint struct {
	DisplayName       string
	DistinguishedName string
	CN                string
	Description       string
	Properties        InterestingProperties
}

type InterestingProperties struct {
	User               bool
	Group              bool
	Machine            bool
	SPNs               bool
	NoPreAuth          bool
	HighValueMember    bool
	TrustedToDelegate  bool
	PasswordNoChange   bool
	PasswordNoRequired bool
	PasswordNoExpire   bool
}

func (p *PrettyPrint) Glance() string {
	var glance []string
	if p.Properties.HighValueMember {
		glance = append(glance, "[High Value]")
	}
	if p.Properties.User {
		glance = append(glance, "[User]")
	}
	if p.Properties.Group {
		glance = append(glance, "[Group]")
	}
	if p.Properties.Machine {
		glance = append(glance, "[Machine]")
	}
	glance = append(glance, p.CN)

	if p.Properties.User && p.Properties.SPNs {
		glance = append(glance, "[Kerberoastable]")
	}
	if p.Properties.User && p.Properties.NoPreAuth {
		glance = append(glance, "[AS-RepRoastable]")
	}
	if p.Properties.User && p.Properties.PasswordNoExpire {
		glance = append(glance, "[Pass not expire]")
	}
	if p.Properties.User && p.Properties.PasswordNoRequired {
		glance = append(glance, "[Pass not Required]")
	}
	if p.Properties.TrustedToDelegate {
		glance = append(glance, "[Trusted to Delegate")
	}

	return strings.Join(glance, " ")

}

//TODO computers in HV groups
func DisplayResults(r *sorting.SortedResults) {

	fmt.Println("---Members of High Value Groups---")
	fmt.Println("#DOMAIN ADMINS#")
	for _, p := range r.HighValueGroups.DomainAdminsMembers {
		p := ldapNicePrint(p, r)
		fmt.Println(p.Glance())
	}
	fmt.Println()

	fmt.Println("#Administrators#")
	for _, g := range r.HighValueGroups.BuiltInAdminMembers {
		p := ldapNicePrint(g, r)
		fmt.Println(p.Glance())
	}
	fmt.Println()

	fmt.Println("#Enterprise Admins#")
	for _, g := range r.HighValueGroups.EnterpriseAdminMembers {
		p := ldapNicePrint(g, r)
		fmt.Println(p.Glance())
	}

	/*fmt.Println() //Needs better parsing. Currently matches all machines
	fmt.Println("#Domain Controllers")
	for _, d := range r.DomainControllers {
		p := ldapNicePrint(d, r)
		fmt.Println(p.Glance())
	}*/

	fmt.Println()
	fmt.Println("---Exploitable Accounts---")
	fmt.Println("#Kerberoastable Users")
	for _, x := range r.EntriesWithSPN {
		if inList(x, r.Users) {
			p := ldapNicePrint(x, r)
			fmt.Println(p.Glance())
		}
	}
	fmt.Println()
	fmt.Println("#AS-Reproastable Users")
	for _, x := range r.PreAuthNotRequired {
		if inList(x, r.Users) {
			p := ldapNicePrint(x, r)
			fmt.Println(p.Glance())
		}
	}

	fmt.Println()
	fmt.Println("---Informational---")

	fmt.Println("#Users with passwords that don't expire")
	for _, x := range r.PasswordNoExpire {
		if inList(x, r.Users) {
			p := ldapNicePrint(x, r)
			fmt.Println(p.Glance())
		}
	}
	fmt.Println()
	fmt.Println("#Users with descriptions")
	for _, x := range r.EntriesDescriptions {
		if inList(x, r.Users) {
			p := ldapNicePrint(x, r)
			fmt.Printf("%s - %s\n", p.CN, p.Description)

		}
	}

	fmt.Println(len(r.Machines))

}

//Make a better Print
func ldapNicePrint(l *ldap.Entry, r *sorting.SortedResults) PrettyPrint {
	var p PrettyPrint
	p.DistinguishedName = l.DN
	for _, x := range l.Attributes {
		switch x.Name {
		case "displayName":
			p.DisplayName = x.Values[0]
		case "cn":
			p.CN = x.Values[0]
		case "description":
			p.Description = x.Values[0]
		}

	}
	p.Properties.User = inList(l, r.Users)
	p.Properties.Group = inList(l, r.Groups)
	p.Properties.SPNs = inList(l, r.EntriesWithSPN)
	p.Properties.NoPreAuth = inList(l, r.PreAuthNotRequired)
	p.Properties.PasswordNoExpire = inList(l, r.PasswordNoExpire)
	p.Properties.HighValueMember = inHighValue(l, r)
	p.Properties.Machine = inList(l, r.Machines)
	return p

}

func inList(l *ldap.Entry, r []*ldap.Entry) bool {
	for _, x := range r {
		if l == x {
			return true
		}
	}
	return false
}

func inHighValue(l *ldap.Entry, r *sorting.SortedResults) bool {

	if inList(l, r.HighValueGroups.BuiltInAdminMembers) {
		return true
	}
	if inList(l, r.HighValueGroups.DomainAdminsMembers) {
		return true
	}
	if inList(l, r.HighValueGroups.EnterpriseAdminMembers) {
		return true
	}
	return false

}
