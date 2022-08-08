package main

import (
	"github.com/akamensky/argparse"
	"github.com/ilightthings/jumptoolkit/src/inputparse"
	"github.com/ilightthings/jumptoolkit/src/jump_share_scanner/jump_smb"
	"log"
	"os"
)

//TODO, set up levels of logging for debugging
//TODO, have a guest access check as well

func main() {
	//TODO Add option to not test Read/Write
	//TODO Add Multi Threading

	parser := argparse.NewParser("jump_share_scanner", "A share scanner that will detect and test network shares.")
	layTrapArg := parser.Flag("", "trap", &argparse.Options{Required: false, Help: "Drop a URL file that causes users to connect back to attacker machine"})
	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated"})
	portarg := parser.Int("P", "port", &argparse.Options{Required: false, Default: 445, Help: "Port to scan for SMB Shares"})
	usernamearg := parser.String("u", "username", &argparse.Options{Required: false, Default: "guest", Help: "Username to authenticate with"})
	passwordarg := parser.String("p", "password", &argparse.Options{Required: false, Default: "", Help: "Password to authenticate with"})
	domainarg := parser.String("d", "domain", &argparse.Options{Required: false, Default: ".", Help: "domain to authenticate with"})
	testfilearg := parser.String("f", "filename", &argparse.Options{Required: false, Default: ".msds_info", Help: "name of the test file to write to disk (Useful for logging)"})

	trapUrlarg := parser.String("", "trap-url", &argparse.Options{Required: false, Default: "https://google.com", Help: "URL for trap to link to"})
	trapAttacker := parser.String("", "trap-server", &argparse.Options{Required: false, Help: "IP address of the server the trap authenticates to"})
	trapFileName := parser.String("", "trap-filename", &argparse.Options{Required: false, Default: "@homepage", Help: "Filename of the url"})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	valHost, err := inputparse.ParseHost(*hostarg)
	if err != nil {
		log.Fatal(err)
	}
	UserOptions := jump_smb.Options{
		Hosts:               valHost,
		Username:            *usernamearg,
		Password:            *passwordarg,
		Domain:              *domainarg,
		TestWriteAccessName: *testfilearg,
		Port:                *portarg,
		LayTrap:             true,
		TrapFileName:        *trapFileName,
		TrapUrl:             *trapUrlarg,
		TrapAttackerIP:      *trapAttacker,
	}
	if *layTrapArg {
		jump_smb.ValidateTrap(&UserOptions)
	}

	Results := TestHosts(&UserOptions)
	jump_smb.PrettyPrint(Results, &UserOptions)

}

func TestHosts(options *jump_smb.Options) []*jump_smb.Host {
	var HostsList []*jump_smb.Host
	for _, hostEntry := range options.Hosts {
		newHost := &jump_smb.Host{IpAddr: hostEntry}
		HostsList = append(HostsList, newHost)

		//TCP Dial Host
		err := newHost.DialHost(options)
		if err != nil {
			continue
		}
		defer newHost.Connection.Close() // Defer closing the dial connection

		//SMB Autenticate to host
		err = newHost.AuthHost(options)
		if err != nil {
			continue
		}
		defer newHost.SMBSession.Logoff() // Defer closing the session

		//Get Shares
		err = newHost.GetShares(options)
		if err != nil {
			continue
		}

		//Test Share Access
		newHost.TestShareAccess(options)

	}
	return HostsList

}
