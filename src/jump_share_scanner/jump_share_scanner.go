package jump_share_scanner

import (
	"fmt"
	smb2 "github.com/LeakIX/go-smb2"
	"github.com/LeakIX/ntlmssp"
	"net"
	"os"
	"time"
)

const (
	ADMIN_SHARE        = "$ADMIN"
	INTERPROCESS_SHARE = "$IPC"
	C_SHARE            = "$C"
)

const (
	MOUNT_NO_ACCESS         = 0
	MOUNT_READ_ACCESS       = 1
	MOUNT_WRITE_ACCESS      = 2
	MOUNT_READ_WRITE_ACCESS = 3
	MOUNT_NOT_TESTED        = 4
)

type Options struct {
	Username            string
	Password            string
	NTLM_hash           string
	Domain              string
	Port                int
	Hosts               []string
	TestWriteAccessName string
}

type Host struct {
	IpAddr        string
	Shares        []ShareFolder
	TCPReachable  bool //Did the dialer Succeed
	Connection    net.Conn
	Authenticated bool //Were we able to autnenticate
	SMBSession    *smb2.Session
}

type ShareFolder struct {
	ShareName    string
	ReadAccess   bool
	WriteAccess  bool
	AccessResult int
}

func main() {}

func CreateHost(options *Options) []*Host {
	var HostsList []*Host
	for _, hostEntry := range options.Hosts {
		newHost := &Host{IpAddr: hostEntry}
		HostsList = append(HostsList, newHost)

		//TCP Dial Host
		err := newHost.DialHost(options)
		if err != nil {
			continue
		}
		defer newHost.Connection.Close()

		//SMB Autenticate to host
		err = newHost.AuthHost(options)
		if err != nil {
			continue
		}
		defer newHost.SMBSession.Logoff()

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

//TODO Add context for timing
//establish a TCP Connection to host.
func (h *Host) DialHost(options *Options) error {
	hostaddress := fmt.Sprintf("%s:%d", h.IpAddr, options.Port)
	conn, err := net.Dial("tcp", hostaddress)
	if err == nil {
		h.TCPReachable = true
	} else {
		fmt.Printf("Error Reaching Host %s\n", h.IpAddr)
	}
	h.Connection = conn
	return err
}

//Authenticate with SMB Service. Remeber to close when auth is fin.
func (h *Host) AuthHost(options *Options) error {

	ntlmclient, err := ntlmssp.NewClient(
		ntlmssp.SetCompatibilityLevel(2),
		ntlmssp.SetUserInfo(options.Username, options.Password),
		ntlmssp.SetDomain(options.Domain))
	if err != nil {
		return err
	}
	smbservice := &smb2.Dialer{
		Initiator: &smb2.NTLMSSPInitiator{
			NTLMSSPClient: ntlmclient,
		},
	}

	s, err := smbservice.Dial(h.Connection)
	if err == nil {
		h.Authenticated = true
	} else {
		fmt.Printf("Error Authenticating Host %s\n", h.IpAddr)
	}
	h.SMBSession = s
	return err

}

//Get list of shares from host
func (h *Host) GetShares(options *Options) error {
	FoundShares, err := h.SMBSession.ListSharenames()
	if err != nil {
		fmt.Printf("Error getting shares from host %s\n%s\n", h.IpAddr, err)
		return err
	}
	for _, sharename := range FoundShares {
		newShare := &ShareFolder{ShareName: sharename}
		h.Shares = append(h.Shares, *newShare)
	}
	return err
}

func (h *Host) TestShareAccess(options *Options) {
	for sharename := range h.Shares {
		result := MountShare(h, h.Shares[sharename].ShareName, options)

		if result&MOUNT_READ_ACCESS == MOUNT_READ_ACCESS {
			h.Shares[sharename].ReadAccess = true
		}
		if result&MOUNT_WRITE_ACCESS == MOUNT_WRITE_ACCESS {
			h.Shares[sharename].WriteAccess = true
		}
		h.Shares[sharename].AccessResult = result

	}

}

//Test Read Access
func MountShare(h *Host, Sharename string, options *Options) int {
	fs, err := h.SMBSession.Mount(Sharename)
	if err != nil {
		return MOUNT_NO_ACCESS
	}
	defer fs.Umount()

	if Sharename != "SYSVOL" {

		err = WriteToShare(fs, options)
		if err == nil {
			time.Sleep(time.Duration(1) * time.Second)
			err = DeleteWrite(fs, options)
			if err != nil {
				fmt.Printf("Error: Could not remove test director \"%s\" from \\\\%s\\%s. Manual deletion may be required.\n", options.TestWriteAccessName, h.IpAddr, Sharename)
			}
			return MOUNT_READ_WRITE_ACCESS
		} else {
			return MOUNT_READ_ACCESS
		}

	} else {
		return MOUNT_NOT_TESTED
	}

}

//Test Write Access
func WriteToShare(FileShare *smb2.Share, options *Options) error {
	err := FileShare.Mkdir(options.TestWriteAccessName, os.ModePerm)
	if err != nil {
		//fmt.Println(err.Error())
		return err
	}
	return nil

}

//Delete Written File
func DeleteWrite(FileShare *smb2.Share, options *Options) error {
	err := FileShare.RemoveAll(options.TestWriteAccessName)

	return err
}

//Pretty print
func PrettyPrint(hostresults []*Host, options *Options) {
	for x := range hostresults {
		if hostresults[x].TCPReachable == false {
			fmt.Printf("Host %s is unreachable\n\n", hostresults[x].IpAddr)
			continue
		}
		if hostresults[x].Authenticated == false {
			fmt.Printf("Host %s failed to authenticate with %s\\%s\n\n", options.Domain, options.Domain, options.Username)
			continue
		}

		fmt.Println(hostresults[x].IpAddr)
		for share := range hostresults[x].Shares {
			fmt.Printf("%-20s%s\n", hostresults[x].Shares[share].ShareName, NicePrint(hostresults[x].Shares[share].AccessResult))

		}
		fmt.Println()
	}
}

func NicePrint(access_int int) string {
	switch access_int {
	case MOUNT_NO_ACCESS:
		return "NO ACCESS"
	case MOUNT_READ_ACCESS:
		return "READ ACCESS"
	case MOUNT_READ_WRITE_ACCESS:
		return "READ/WRITE ACCESS"
	case MOUNT_NOT_TESTED:
		return "NOT TESTED"
	default:
		return "UNKNOWN ACCESS"
	}

}
