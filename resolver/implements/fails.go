package implements

import "github.com/nna774/zorori/dns"

// AFail create empty AResult and err
func AFail(err error) (dns.AResult, error) {
	return dns.AResult{}, err
}
