package resolver

import "github.com/nna774/zorori/dns"

// Resolver is the interface of DNS resolver
type Resolver interface {
	AResolve(string) (dns.AResult, error)
}
