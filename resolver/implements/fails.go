package implements

import "github.com/nna774/zorori/dns"

// AFail create empty AResult and err
func AFail(err error) (dns.AResult, error) {
	return dns.AResult{}, err
}

// SVCBFail create empty SVCBResult and err
func SVCBFail(err error) (dns.SVCBResult, error) {
	return dns.SVCBResult{}, err
}
