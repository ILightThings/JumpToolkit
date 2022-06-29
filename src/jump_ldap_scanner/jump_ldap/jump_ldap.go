package jump_ldap

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"strings"
)

type Options struct {
	Username string
	Password string
	Domain   string

	//"dc=example,dc=local" for exmaple.local
	DomainCN     string
	LDAPIPaddr   string
	LDAPPort     int
	LDAPDomainDC string
	DomainSID    string
}

// example.local -> DC=example,DC=local
func (o *Options) BuildCN() {
	dcparts := strings.Split(strings.TrimSpace(o.Domain), ".")
	o.LDAPDomainDC = dcparts[0]
	for i := range dcparts {
		dcparts[i] = fmt.Sprintf("dc=%s", dcparts[i])
	}
	o.DomainCN = strings.Join(dcparts, ",")

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
	err := conn.Bind(opt.Username, opt.Password)
	return err
}

//Build Search LDAP Object
func buildSearch(opt *Options, filter string) *ldap.SearchRequest {
	s := ldap.NewSearchRequest(
		opt.DomainCN,
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
