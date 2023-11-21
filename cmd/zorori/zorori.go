package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"

	"github.com/nna774/zorori/resolver"
	"github.com/nna774/zorori/resolver/doh"
	"github.com/nna774/zorori/resolver/udp"
)

func init() {
	rand.Seed(42)
}

var (
	mode         = flag.String("mode", "doh", "resolve mode")
	stub         = flag.Bool("stub", true, "stub resolve")
	fullResolver = flag.String("fullresolver", "8.8.8.8", "ip addr of full resolver")
	dohServer    = flag.String("doh", "https://dns.google/dns-query", "doh server")
)

func main() {
	flag.Parse()
	name := "www.jprs.co.jp"
	args := flag.Args()
	if len(args) >= 1 {
		name = args[0]
	}

	var resolver resolver.Resolver
	if *mode == "doh" {
		resolver = doh.NewDoHResolver(*dohServer)
	}
	if *mode == "udp" {
		if *stub {
			resolver = udp.NewUDPStubResolver(net.ParseIP(*fullResolver))
		} else {
			resolver = udp.NewUDPFullResolver()
		}
	}
	res, err := resolver.AResolve(name)
	if err != nil {
		fmt.Printf("bie %v", err)
		return
	}
	fmt.Printf("A: %v\n", res.IP())
}
