package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/ilightthings/jumptoolkit/src/inputparse"

	"log"
	"net"
	"os"
	"sync"
)

type ipHost struct {
	ipaddr  string
	dnsName []string
}

type options struct {
	resolverIP        string
	resolverPort      int
	useCustomResolver bool

	queries []string
	timeout int //seconds
}

func main() {
	parser := argparse.NewParser("jump_ptr_scan", "A quick, concurrent Reverse DNS scanner. Used PTR records to discover and map the domain. that can be dropped onto a victim machine and ran. NOTE: Custom Resolvers will not work on windows. Golang will not be able to change the default resolver.")

	hostarg := parser.String("t", "target", &argparse.Options{Required: true, Help: "IPv4 to target. Single, CIDR, comma seperated"})

	err := parser.Parse(os.Args)

	valHost, err := inputparse.ParseHost(*hostarg)
	//(*hostarg)
	if err != nil {
		log.Fatal(err)
	}

	args := options{
		queries: valHost}
	startScan(&args)
}

func startScan(opt *options) {

	var ipArray []ipHost
	var wg sync.WaitGroup

	for _, host := range opt.queries {
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

func doLookup(query string) ([]string, error) {
	ip, err := net.LookupAddr(query)
	return ip, err
}
