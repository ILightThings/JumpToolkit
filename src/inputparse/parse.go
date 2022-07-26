package inputparse

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-playground/validator"
)

//TODO add file parser

//Parse host from string. Input could be single host (10.0.0.0), CIDR Notation (172.16.0.0/16), or comma seperated (192.168.1.1,192.168.1.3,192.168.1.5)
func ParseHost(host string) ([]string, error) {

	v := validator.New()
	var p []string

	//Single Host
	err := v.Var(host, "ip")
	if err == nil {
		p = append(p, host)
		return p, nil
	}

	//Cidr
	err = v.Var(host, "cidr")
	if err == nil {
		p, err = cidr(host)
		if err != nil {
			return p, err
		}
		return p, nil
	}

	//TODO, logging
	//Comma seperated
	if strings.Contains(host, ",") {
		
		potentialTarget := strings.Split(host, ",")
		for ahost := range potentialTarget {
			potentialTarget[ahost] = strings.TrimSpace(potentialTarget[ahost])
			err = v.Var(potentialTarget[ahost], "ip4_addr")
			if err != nil {
				continue
			}
			p = append(p, potentialTarget[ahost])

		}
		return p, err
	}
	return p, errors.New("could not inputparse IP address")

}

func ParsePorts(ports string) ([]int, error) {
	var validports []int
	//v := validator.New()

	//Single Port
	IntVar, err := strconv.Atoi(ports)
	if err == nil {
		validports = append(validports, IntVar)
		return validports, nil
	}

	// Port range 1-500
	if strings.Contains(ports, "-") {
		rangePorts := strings.Split(ports, "-")
		if len(rangePorts) != 2 {
			return validports, errors.New("could not inputparse range between two numbers.")
		}
		minPort, err := strconv.Atoi(rangePorts[0])
		if err != nil {
			return validports, errors.New("could not inputparse int from port range")
		}
		maxPort, err := strconv.Atoi(rangePorts[1])
		if err != nil {
			return validports, errors.New("could not inputparse int from port range")
		}

		if minPort > maxPort {
			return validports, errors.New("error validating port range. first number should be smaller. ex. 1-100")
		}
		for i := minPort; i < maxPort+1; i++ {
			validports = append(validports, i)
		}
		if len(validports) == 0 {
			return validports, errors.New("port range is empty somehow")
		}
		return validports, nil
	}

	//Comma Seperated
	if strings.Contains(ports, ",") {
		portsComma := strings.Split(ports, ",")
		for x := range portsComma {
			portsComma[x] = strings.TrimSpace(portsComma[x])
			p, err := strconv.Atoi(portsComma[x])
			if err != nil {
				continue
			}
			validports = append(validports, p)
		}
		if len(validports) == 0 {
			return validports, errors.New("port range is empty somehow")
		}
		return validports, nil
	}
	return nil, errors.New(fmt.Sprintf("could not inputparse ports from argument for %s", ports))

}

//Return List of IPs from CIDR Notation
func cidr(cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
		ips = append(ips, addr)
	}

	var ipstring []string
	for ipClass := range ips {
		ipstring = append(ipstring, ips[ipClass].String())
	}

	return ipstring, nil
}
