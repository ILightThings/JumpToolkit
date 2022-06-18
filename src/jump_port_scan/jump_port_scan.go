package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/ilightthings/jumptoolkit/src/inputparse"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

//type port struct {
//	PortNumber int
//	PortStatus bool
//}

type targetHost struct {
	Ipaddr   string
	Hostname string
	Ports    []int
}

type options struct {
	hosts   []string
	ports   []int
	timeout int64 //Seconds
}

func main() {
	parser := argparse.NewParser("jump_port_scan", "A quick, concurrent port scanner, that can be dropped onto a victim machine and ran.")
	portarg := parser.String("p", "ports", &argparse.Options{Required: true, Help: "TCP ports to scan. Single port, range, comma seperated"})
	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated"})
	timeoutarg := parser.Int("T", "timeout", &argparse.Options{Required: false, Default: .5, Help: "Timeout in seconds"})
	err := parser.Parse(os.Args)

	valPorts, err := inputparse.ParsePorts(*portarg)
	if err != nil {
		log.Fatal(err)
	}
	valHost, err := inputparse.ParseHost(*hostarg)
	if err != nil {
		log.Fatal(err)
	}

	args := options{ports: valPorts,
		hosts:   valHost,
		timeout: int64(*timeoutarg)}

	startScan(&args)

}

func startScan(options *options) {
	var allhosts []targetHost
	var WAIT sync.WaitGroup

	for _, h := range options.hosts {

		WAIT.Add(1)
		go func(host string) {

			defer WAIT.Done()

			//fmt.Printf("starting host %s\n", host)
			th := scanTarget(host, options)
			allhosts = append(allhosts, th)
		}(h)

	}
	WAIT.Wait()

	for ahost := range allhosts {
		if len(allhosts[ahost].Ports) != 0 {
			fmt.Println(allhosts[ahost].Ipaddr)
			for p := range allhosts[ahost].Ports {
				fmt.Printf("\tPort %d Open\n", allhosts[ahost].Ports[p])
			}
		}
	}
	fmt.Printf("Scan Finished \n")

}

func scanTarget(host string, options *options) targetHost {
	var t targetHost
	t.Ipaddr = host
	var wg sync.WaitGroup
	for _, y := range options.ports {

		wg.Add(1)
		go func(port int) {

			defer wg.Done()
			status := scanport(port, host, options.timeout)
			if status {
				t.Ports = append(t.Ports, port)
			}
		}(y)

	}
	wg.Wait()
	return t
}

func scanport(port int, host string, timeout int64) bool {

	target := fmt.Sprintf("%s:%d", host, port)
	//fmt.Printf("Testing %s\n", target)

	_, err := net.DialTimeout("tcp", target, time.Duration(timeout)*time.Second)
	if err == nil {
		fmt.Printf("Found %s\n", target)
		return true
	}
	return false
}
