package main

import (
	"fmt"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/jump_ldap"
	"github.com/ilightthings/jumptoolkit/src/jump_ldap_scanner/sorting"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"testing"
)

func GenOptions() jump_ldap.Options {
	opt := jump_ldap.Options{
		Username:   misc.Ldapusername,
		Password:   misc.Ldappassword,
		Domain:     misc.LdapDNSDomain,
		LDAPIPaddr: misc.DCIPAddr,
		LDAPPort:   389,
	}

	return opt
}

func TestDialLDAP(t *testing.T) {
	opt := GenOptions()
	_, err := jump_ldap.DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}

}

func TestAnonymousBind(t *testing.T) {
	opt := GenOptions()

	ldapconn, err := jump_ldap.DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}
	err = jump_ldap.AnonymousBind(ldapconn)
	if err != nil {
		t.Error(err)
	}

}

func TestBindLDAP(t *testing.T) {
	opt := GenOptions()
	opt.BuildCN()
	ldapconn, err := jump_ldap.DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}

	err = jump_ldap.BindLDAP(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}

}

func TestExtractAllEntries(t *testing.T) {
	opt := GenOptions()
	opt.BuildCN()
	ldapconn, err := jump_ldap.DialLDAP(&opt)
	if err != nil {
		t.Fatal(err)
	}
	err = jump_ldap.BindLDAP(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}

	results, err := jump_ldap.ExtractAllEntries(ldapconn, &opt)
	if err != nil {
		t.Fatal(err)
	}
	var people sorting.SortedResults
	sorting.GetUsersFromResults(&people, results.Entries)

	r := sorting.SortResults(results.Entries)

	for user := range r.Users {
		fmt.Println(r.Users[user].DN)
	}

}
