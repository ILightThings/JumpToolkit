package main

import (
	"fmt"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"testing"
)

func GenOptions() Options {
	opt := Options{
		username:   misc.Ldapusername,
		password:   misc.Ldappassword,
		domain:     misc.LdapDNSDomain,
		LDAPIPaddr: misc.DCIPAddr,
		LDAPPort:   389,
	}

	return opt
}

func TestDialLDAP(t *testing.T) {
	opt := GenOptions()
	_, err := DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}

}

func TestAnonymousBind(t *testing.T) {
	opt := GenOptions()

	ldapconn, err := DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}
	err = AnonymousBind(ldapconn)
	if err != nil {
		t.Error(err)
	}

}

func TestBindLDAP(t *testing.T) {
	opt := GenOptions()
	opt.BuildCN()
	ldapconn, err := DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}

	err = BindLDAP(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}

}

func TestExtractAllEntries(t *testing.T) {
	opt := GenOptions()
	opt.BuildCN()
	ldapconn, err := DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}
	err = BindLDAP(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}

	results, err := ExtractAllEntries(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}
	p := GetUsersFromResults(results.Entries)

	for x := range p {
		fmt.Println(p[x].DN)
	}

	r := SortResults(results.Entries)

	for user := range r.Users {
		fmt.Println(r.Users[user].DN)
	}

}
