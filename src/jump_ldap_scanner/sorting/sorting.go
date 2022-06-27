package sorting

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"strconv"
	"strings"
)

//Todo, add machine sorting
type SortedResults struct {
	DomainControllers    []*ldap.Entry
	Users                []*ldap.Entry
	Groups               []*ldap.Entry
	Machines             []*ldap.Entry
	EntriesDescriptions  []*ldap.Entry
	HighValueGroups      BuiltInHighValueGroups
	BuiltInAccounts      BuiltInAccounts
	EntriesWithSPN       []*ldap.Entry //Potential Kerberoast
	PreAuthNotRequired   []*ldap.Entry //AS-REPROAST
	TrustedForDelegation []*ldap.Entry
	TrustedToDelegate    []*ldap.Entry
	PasswordNoExpire     []*ldap.Entry
	PasswordNotRequired  []*ldap.Entry
	PasswordCannotChange []*ldap.Entry
	AccountDisabled      []*ldap.Entry
}

type BuiltInHighValueGroups struct {
	DomainAdmins           *ldap.Entry
	DomainAdminsMembers    []*ldap.Entry
	BuiltInAdmins          *ldap.Entry
	BuiltInAdminMembers    []*ldap.Entry
	EnterpriseAdmin        *ldap.Entry
	EnterpriseAdminMembers []*ldap.Entry
}

type BuiltInAccounts struct {
	Krbtgt        *ldap.Entry
	Administrator *ldap.Entry
	Guest         *ldap.Entry
}

func GetUsersFromResults(r *SortedResults, result []*ldap.Entry) {

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
			r.Users = append(r.Users, x)
		}
	}

}

//TODO set secondary function that gets the membersOf attribute with the DN of the detected High Value groups. Results are currently strings, not LDAP.Entry

//Sort Entries into groups defined
func SortResults(result []*ldap.Entry) SortedResults {
	var results SortedResults
	for _, entry := range result {
		OID := 0
		OBJCat := 0
		UAC := 0

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
					if strings.Contains(z, "CN=Computer") {
						OBJCat = OBJCat + misc.OBJCAT_Computer
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
			case "userAccountControl":
				for _, userAccountControlValue := range y.Values {
					resultingUAC, err := strconv.Atoi(userAccountControlValue)
					if err != nil {
						UAC = 0
						fmt.Println(err)
					}
					UAC = resultingUAC

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

		if (OID&misc.OID_Computer) == misc.OID_Computer && (OBJCat&misc.OBJCAT_Computer) == misc.OBJCAT_Computer {
			results.Machines = append(results.Machines, entry)
		}

		if (UAC & misc.UAC_DONT_REQ_PREAUTH) == misc.UAC_DONT_REQ_PREAUTH {
			results.PreAuthNotRequired = append(results.PreAuthNotRequired, entry)
		}

		if (UAC & misc.UAC_DONT_EXPIRE_PASSWORD) == misc.UAC_DONT_EXPIRE_PASSWORD {
			results.PasswordNoExpire = append(results.PasswordNoExpire, entry)
		}

		if (UAC & misc.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) == misc.UAC_TRUSTED_TO_AUTH_FOR_DELEGATION {
			results.TrustedToDelegate = append(results.TrustedToDelegate, entry)
		}

		if (UAC & misc.UAC_PASSWD_NOTREQD) == misc.UAC_PASSWD_NOTREQD {
			results.PasswordNotRequired = append(results.PasswordNotRequired, entry)
		}

		if (UAC & misc.UAC_DONT_EXPIRE_PASSWORD) == misc.UAC_DONT_EXPIRE_PASSWORD {
			results.PasswordNoExpire = append(results.PasswordNoExpire, entry)
		}

		if (UAC & misc.UAC_PASSWD_CANT_CHANGE) == misc.UAC_PASSWD_CANT_CHANGE {
			results.PasswordCannotChange = append(results.PasswordCannotChange, entry)
		}

		if (UAC & misc.UAC_ACCOUNTDISABLE) == misc.UAC_ACCOUNTDISABLE {
			results.AccountDisabled = append(results.AccountDisabled, entry)
		}

		/*
				PreAuthNotRequired   []*jump_ldap.Entry //AS-REPROAST
				TrustedForDelegation []*jump_ldap.Entry
				TrustedToDelegate    []*jump_ldap.Entry
				PasswordNoExpire     []*jump_ldap.Entry
				PasswordNotRequired  []*jump_ldap.Entry
			}
		*/

	}
	GetUsersFromResults(&results, result)
	GetMembersOfGroup(&results, result)
	return results

}

//Extract members from group. This is required because we cannot rely on the High Values groups always having the same DN. Either localization or Sneaky Admins my change the group. We can rely on the SID being conistant though.
func GetMembersOfGroup(r *SortedResults, l []*ldap.Entry) {
	for _, entry := range l {
		for _, attributes := range entry.Attributes {
			if attributes.Name == "memberOf" {
				for _, value := range attributes.Values {

					if value == r.HighValueGroups.BuiltInAdmins.DN {
						r.HighValueGroups.BuiltInAdminMembers = append(r.HighValueGroups.BuiltInAdminMembers, entry)
					}
					if value == r.HighValueGroups.DomainAdmins.DN {
						r.HighValueGroups.DomainAdminsMembers = append(r.HighValueGroups.DomainAdminsMembers, entry)
					}
					if value == r.HighValueGroups.EnterpriseAdmin.DN {
						r.HighValueGroups.EnterpriseAdminMembers = append(r.HighValueGroups.EnterpriseAdminMembers, entry)
					}

					/*switch value { //Does not take into account that objects could be in multiple groups.....
					case r.HighValueGroups.BuiltInAdmins.DN:
						r.HighValueGroups.BuiltInAdminMembers = append(r.HighValueGroups.BuiltInAdminMembers, entry)
					case r.HighValueGroups.DomainAdmins.DN:
						r.HighValueGroups.DomainAdminsMembers = append(r.HighValueGroups.DomainAdminsMembers, entry)
					case r.HighValueGroups.EnterpriseAdmin.DN:
						r.HighValueGroups.EnterpriseAdminMembers = append(r.HighValueGroups.EnterpriseAdminMembers, entry)*/
				}
			}
		}
	}
}
