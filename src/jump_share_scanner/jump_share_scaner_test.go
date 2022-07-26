package main

import (
	"testing"
)

func GenCred() Options {
	o := Options{
		Username:            "gogo",
		Password:            "123Admin123!!",
		TestWriteAccessName: "vumetric",
		Domain:              "light.local",
		Port:                445,
		Hosts:               []string{"192.168.1.178", "192.168.1.100", "192.168.1.159"},
	}
	return o
}

func TestAuthHost(t *testing.T) {
	o := GenCred()
	hosts := TestHosts(&o)
	PrettyPrint(hosts, &o)
}
