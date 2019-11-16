package main

import (
	"fmt"
	"os"

	"github.com/nna774/zorori/resolver"
)

func main() {
	name := "www.jprs.co.jp"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}

	//	resolver := resolver.NewDoHResolver("https://public.dns.iij.jp/dns-query")
	resolver := resolver.NewDoHResolver("https://dns.google/dns-query")
	res, err := resolver.AResolve(name)
	if err != nil {
		fmt.Printf("bie %v", err)
		return
	}
	fmt.Printf("A: %v\n", res.IP())
}
