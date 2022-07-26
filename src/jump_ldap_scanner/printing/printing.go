package printing

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/sorting"
	"log"
	"strconv"
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

//THERE IS A DIFFERENCE BETWEEN A PASSWORD POLICY AND A FINE GRAINED PASSWORD POLICY
type PassPol struct {
	PolicyName            string
	AppliesTo             string
	PasswordComplexity    bool //ms-DS-Password-Complexity-Enabled
	LockoutThreshold      int
	LockoutDuration       int //https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-lockoutduration
	MinimumPasswordLength int
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
		l := ldapNicePrint(p, r)
		fmt.Println(l.Glance())
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

	fmt.Println()
	fmt.Println("# Domain Objects with password policies")
	fmt.Println("---Fine Grained---")
	for _, x := range r.FineGrainedPasswordPolicies {
		PrintFineGrainedPasswordPolicy(x)

	}
	fmt.Println("---DC default policy (potentally default)---")
	for _, y := range r.LockoutPolicies {
		printPassPolicy(y)
	}

	fmt.Println(len(r.FineGrainedPasswordPolicies))

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

type PasswordPolicy struct {
	ObjectName             string
	passwordLength         string
	passwordMinAge         string
	passwordMaxAge         string
	lockoutDuration        string
	lockoutOberservation   string
	lockoutThreshold       string
	passwordComplexity     string
	passwordHistory        string
	passwordReverseAble    string
	PasswordPolicyPriority string
	PolicyAppliesTo        []string
}

func printPassPolicy(l *ldap.Entry) {
	var classPolicy PasswordPolicy
	for _, x := range l.Attributes {
		switch x.Name {
		case "distinguishedName":
			classPolicy.ObjectName = x.Values[0]
		case "lockoutDuration":
			classPolicy.lockoutDuration = x.Values[0]
		case "lockOutObservationWindow":
			classPolicy.lockoutOberservation = x.Values[0]
		case "lockoutThreshold":
			classPolicy.lockoutThreshold = x.Values[0]
		case "maxPwdAge":
			classPolicy.passwordMaxAge = x.Values[0]
		case "minPwdAge":
			classPolicy.passwordMinAge = x.Values[0]
		case "minPwdLength":
			classPolicy.passwordLength = x.Values[0]
		}

	}
	fmt.Printf(`%s
	Lockout Theshold: %d
	Lockout Duration: %d
	Lockout Observation: %d

	Password Minimum Length: %s
	Password Minimum Age: %d
	Password Maximum Age: %d

`,
		classPolicy.ObjectName,
		setVar(classPolicy.lockoutThreshold),
		setVar(classPolicy.lockoutDuration)/-600000000,
		setVar(classPolicy.lockoutOberservation)/-600000000,
		classPolicy.passwordLength,
		setVar(classPolicy.passwordMinAge)/-600000000/60/24,
		setVar(classPolicy.passwordMaxAge)/-600000000/60/24,
	)
}

func PrintFineGrainedPasswordPolicy(l *ldap.Entry) {
	var classPolicy PasswordPolicy
	for _, x := range l.Attributes {
		switch x.Name {
		case "distinguishedName":
			classPolicy.ObjectName = x.Values[0]
		case "msDS-LockoutDuration":
			classPolicy.lockoutDuration = x.Values[0]
		case "msDS-LockoutObservationWindow":
			classPolicy.lockoutOberservation = x.Values[0]
		case "msDS-LockoutThreshold":
			classPolicy.lockoutThreshold = x.Values[0]
		case "msDS-MaximumPasswordAge":
			classPolicy.passwordMaxAge = x.Values[0]
		case "msDS-MinimumPasswordAge":
			classPolicy.passwordMinAge = x.Values[0]
		case "msDS-MinimumPasswordLength":
			classPolicy.passwordLength = x.Values[0]
		case "msDS-PasswordComplexityEnabled":
			classPolicy.passwordComplexity = x.Values[0]
		case "msDS-PasswordHistoryLength":
			classPolicy.passwordHistory = x.Values[0]
		case "msDS-PasswordReversibleEncryptionEnabled":
			classPolicy.PasswordPolicyPriority = x.Values[0]
		case "msDS-PSOAppliesTo":
			classPolicy.PolicyAppliesTo = x.Values
		case "msDS-PasswordSettingsPrecedence":
			classPolicy.PasswordPolicyPriority = x.Values[0]
		}
	}
	fmt.Printf(`%s
	Lockout Theshold: %d
	Lockout Duration: %d
	Lockout Observation: %d

	Password Minimum Length: %d
	Password Minimum Age: %d
	Password Maximum Age: %d
	Password Complexity: %s
	
	Policy Priority: %d
	Policy Applies to:
`,
		classPolicy.ObjectName,
		setVar(classPolicy.lockoutThreshold),
		setVar(classPolicy.lockoutDuration)/-600000000,
		setVar(classPolicy.lockoutOberservation)/-600000000,
		setVar(classPolicy.passwordLength),
		setVar(classPolicy.passwordMinAge)/-600000000/60/24,
		setVar(classPolicy.passwordMaxAge)/-600000000/60/24,
		classPolicy.passwordComplexity,
		setVar(classPolicy.PasswordPolicyPriority),
	)
	for _, affected := range classPolicy.PolicyAppliesTo {
		fmt.Printf("\t\t%s\n", affected)
	}
	fmt.Println()

}

func setVar(s string) int {
	number, err := strconv.Atoi(s)
	if err != nil {
		log.Fatal(err)
	}
	return number
}
