package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/ilightthings/jumptoolkit/src/inputparse"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

//type port struct {
//	PortNumber int
//	PortStatus bool
//}

type targetHost struct {
	Ipaddr string
	Ports  []int
}

type results struct {
	ip   string
	port int
}

type options struct {
	hosts      []string
	ports      []int
	maxConHost int
	maxConPort int
	timeout    int64 //Seconds
}

func main() {
	parser := argparse.NewParser("jump_port_scan", "A quick, concurrent port scanner, that can be dropped onto a victim machine and ran.")

	portarg := parser.String("p", "ports", &argparse.Options{Required: true, Help: "TCP ports to scan. Single port, range, comma seperated"})
	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated, if blank, use (29) common ports"})
	timeoutarg := parser.Int("T", "timeout", &argparse.Options{Required: false, Default: 3, Help: "TCP Timeout in seconds"})
	maxhostthreadarg := parser.Int("K", "host-threads", &argparse.Options{Required: false, Default: 100, Help: "Max concurrent hosts to scan"})
	maxportthreadarg := parser.Int("k", "port-threads", &argparse.Options{Required: false, Default: 1000, Help: "Max concurrent ports per host to scan"})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	var valPorts []int
	if *portarg == "" {
		valPorts, err = inputparse.ParsePorts(*portarg)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		valPorts = misc.CommonTCPPorts

	}

	valHost, err := inputparse.ParseHost(*hostarg)
	if err != nil {
		log.Fatal(err)
	}

	args := options{
		ports:      valPorts,
		hosts:      valHost,
		timeout:    int64(*timeoutarg),
		maxConHost: *maxhostthreadarg,
		maxConPort: *maxportthreadarg,
	}

	if len(args.ports) > 1024 && len(args.hosts) > 100 {

		totalTCPConnection := len(args.ports) * len(args.hosts)
		totalThreads := args.maxConPort * args.maxConHost
		fmt.Printf("Warning: %d TCP Connections will be attempted over a maximum of %d concurrent threads. Potentially inaccurate result. Ensure you have allocated the right resources for this scan.\n\n", totalTCPConnection, totalThreads)
	}
	printPreScanStats(&args)
	fmt.Println("Starting Scan....")
	startScan(&args)

}

//Print PreScan Stats
func printPreScanStats(options *options) {
	fmt.Printf("Extract Hosts: %d\nExtracted Ports: %d\n\nMax Concurrent Hosts: %d\nMax Concurrents Ports: %d\nMaximum Total Threads: %d\n\n", len(options.hosts), len(options.ports), options.maxConHost, options.maxConPort, options.maxConPort*options.maxConHost)

}

func startScan(options *options) {
	returnresultschan := make(chan results)
	hostschan := make(chan string)
	var WgHost sync.WaitGroup
	var threadcount int
	var resultwg sync.WaitGroup

	//Setup results Processor to handle multithread
	resultwg.Add(1)
	go processResults(returnresultschan, &resultwg)

	//Limit workers to only what is needed
	if len(options.hosts) < options.maxConHost {
		threadcount = len(options.hosts)
	} else {
		threadcount = options.maxConHost
	}

	//Prepare worker for host scan
	for t := 0; t != threadcount; t++ {
		WgHost.Add(1)
		go scanTarget(hostschan, &WgHost, options, returnresultschan)
	}

	//Send host to worker
	for _, h := range options.hosts {
		hostschan <- h
	}

	close(hostschan)
	WgHost.Wait()
	close(returnresultschan)
	resultwg.Wait()
	fmt.Printf("Scan Finished \n")

}

func scanTarget(hosts chan string, WgHost *sync.WaitGroup, options *options, returnresultschan chan results) {
	for host := range hosts {
		var WgPorts sync.WaitGroup
		ports := make(chan int)
		var maxthreadsPorts int

		//Limit workers to only what is needed
		if len(options.ports) < options.maxConPort {
			maxthreadsPorts = len(options.ports)
		} else {
			maxthreadsPorts = options.maxConPort
		}

		//Setup Worker to do work
		for o := 0; o < maxthreadsPorts; o++ {
			WgPorts.Add(1)
			go scanport(ports, host, &WgPorts, options, returnresultschan)
		}

		//Send Work to workers
		for _, p := range options.ports {
			ports <- p
		}

		//When all work is sent, close channel
		close(ports)

		//Wait for all workers to be finished
		WgPorts.Wait()

	}

	defer WgHost.Done()

}

func scanport(ports chan int, host string, WgPorts *sync.WaitGroup, options *options, returnresultschan chan results) {

	for port := range ports {
		target := fmt.Sprintf("%s:%d", host, port)
		_, err := net.DialTimeout("tcp", target, time.Duration(options.timeout)*time.Second)

		if err == nil {

			//Build a result object and send it to processing
			found := results{ip: host, port: port}
			returnresultschan <- found

			fmt.Printf("Found %s\n", target)
		}

	}
	WgPorts.Done()
}

func processResults(resultchan chan results, wg *sync.WaitGroup) {
	var tally []targetHost
	var aResult []results

	for r := range resultchan {
		//append result to result var to free up the channel quicker
		aResult = append(aResult, r)
	}

	//Process results and consolidate
	/*
		Before: []results
		{192.168.1.1 80}
		{192.168.1.88 80}
		{192.168.1.88 22}
		{192.168.1.6 80}
		{192.168.1.1 443}
		{192.168.1.35 80}
		{192.168.1.1 3389}

		After: []targetHost
		{192.168.1.1 [80 3389]}
		{192.168.1.88 [22 80]}

	*/
	for _, x := range aResult {
		found := false
		for y, _ := range tally {
			if x.ip == tally[y].Ipaddr {
				tally[y].Ports = append(tally[y].Ports, x.port)
				found = true

			}
		}

		if !found {
			z := targetHost{
				Ipaddr: x.ip,
				Ports:  []int{x.port},
			}
			tally = append(tally, z)

		}

	}

	//Sort IP Address
	sort.SliceStable(tally, func(i, j int) bool {
		return misc.IP4toInt(tally[i].Ipaddr) < misc.IP4toInt(tally[j].Ipaddr)
	})

	fmt.Printf("\n###TOTAL RESULTS (%d):\n", len(tally))
	for _, host := range tally {

		//Sort ports
		sort.SliceStable(host.Ports, func(i, j int) bool {
			return host.Ports[i] < host.Ports[j]
		})

		if len(host.Ports) != 0 {
			fmt.Printf("Host %s is up:\n", host.Ipaddr)
			for _, port := range host.Ports {
				fmt.Printf("\t%d/TCP open\n", port)
			}
		}
	}
	wg.Done()

}
