package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/ilightthings/jumptoolkit/src/inputparse"
	"github.com/ilightthings/jumptoolkit/src/misc"
	"sort"
	"strings"

	"log"
	"net"
	"os"
	"sync"
)

type ipHost struct {
	ipaddr  string
	dnsName []string
}

type ptrResult struct {
	IPAddr  string
	dnsName []string
}

type options struct {
	ipaddr     []string
	timeout    int //seconds
	maxThreads int
}

func main() {
	parser := argparse.NewParser("jump_ptr_scan", "A quick, concurrent Reverse DNS scanner. Used PTR records to discover and map the domain. that can be dropped onto a victim machine and ran. NOTE: Custom Resolvers will not work on windows. Golang will not be able to change the default resolver.")
	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated"})
	maxThreadsarg := parser.Int("k", "threads", &argparse.Options{Required: false, Default: 128, Help: "Maximum number of threads"})

	err := parser.Parse(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	valHost, err := inputparse.ParseHost(*hostarg)
	//(*hostarg)
	if err != nil {
		log.Fatal(err)
	}

	args := options{
		ipaddr:     valHost,
		maxThreads: *maxThreadsarg,
	}

	startScanNG(&args)
}

func startScan(opt *options) {

	var ipArray []ipHost
	var wg sync.WaitGroup

	for _, host := range opt.ipaddr {
		wg.Add(1)
		go func(query string) {
			ahost := ipHost{ipaddr: query}
			results, err := doLookup(query)
			if err == nil {

				ahost.dnsName = results
				ipArray = append(ipArray, ahost)
			}
			wg.Done()

		}(host)
	}
	wg.Wait()

	for r := range ipArray {
		if len(ipArray[r].dnsName) == 0 {
			continue
		}
		fmt.Printf("%s - ", ipArray[r].ipaddr)
		for dnsresult := range ipArray[r].dnsName {
			fmt.Printf("%s\n", ipArray[r].dnsName[dnsresult])
		}
	}

}

func startScanNG(options *options) {
	returnresultschan := make(chan ptrResult)
	ipAddrsChan := make(chan string)
	var WgIPAddr sync.WaitGroup
	var threadcount int
	var resultwg sync.WaitGroup

	resultwg.Add(1)
	go processResults(returnresultschan, &resultwg)

	//Limit workers to only what is needed
	if len(options.ipaddr) < options.maxThreads {
		threadcount = len(options.ipaddr)
	} else {
		threadcount = options.maxThreads
	}

	//Prepare worker for PTR Lookup
	for t := 0; t != threadcount; t++ {
		WgIPAddr.Add(1)
		go doLookupNG(ipAddrsChan, &WgIPAddr, options, returnresultschan)
	}

	//Send data to worker
	for _, p := range options.ipaddr {
		ipAddrsChan <- p
	}

	//Close channel
	close(ipAddrsChan)
	WgIPAddr.Wait()

	close(returnresultschan)
	resultwg.Wait()
	fmt.Printf("Scan Finished \n")

}

//Process and print results when finished
func processResults(resultchan chan ptrResult, wg *sync.WaitGroup) {
	var aResult []ptrResult

	for r := range resultchan {
		//append result to result var to free up the channel quicker
		aResult = append(aResult, r)
	}

	//Sort IP Addresses
	sort.SliceStable(aResult, func(i, j int) bool {
		return misc.IP4toInt(aResult[i].IPAddr) < misc.IP4toInt(aResult[j].IPAddr)
	})

	for _, x := range aResult {
		fmt.Printf("%s:\n", x.IPAddr)
		for _, y := range x.dnsName {
			fmt.Printf("%s\n", strings.ToLower(y))
		}
		fmt.Println()

	}
	wg.Done()

}

func doLookup(query string) ([]string, error) {
	ip, err := net.LookupAddr(query)
	return ip, err
}

//Do lookup and if result is not an err, send to result processor
func doLookupNG(ipAddrsChan chan string, WgIPAddr *sync.WaitGroup, options *options, returnresultschan chan ptrResult) {

	for ipAddrEntry := range ipAddrsChan {
		entries, err := net.LookupAddr(ipAddrEntry)
		if err == nil {
			result := ptrResult{
				IPAddr:  ipAddrEntry,
				dnsName: entries,
			}
			returnresultschan <- result
		}
	}
	WgIPAddr.Done()
}
