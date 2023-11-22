package main_test

import (
	"net"
	"testing"

	"github.com/nna774/zorori/resolver/doh"
)

const ()

func TestDoHAResolve(t *testing.T) {
	DoHResolvers := []struct {
		name string
		uri  string
	}{
		{name: "google", uri: "https://dns.google/dns-query"},
		{name: "iij", uri: "https://public.dns.iij.jp/dns-query"},
	}
	for _, r := range DoHResolvers {
		domains := []struct {
			domain string
			ip     net.IP
		}{
			{domain: "example.com", ip: net.ParseIP("93.184.216.34")},
			{domain: "yukari.router.kitashirakawa.dark-kuins.net", ip: net.ParseIP("192.50.220.189")},
		}
		for _, d := range domains {
			t.Run(r.name+"-"+d.domain, func(t *testing.T) {
				resolver := doh.NewDoHResolver(r.uri)
				res, err := resolver.AResolve(d.domain)
				if err != nil {
					t.Errorf("err should be nil: %v", err)
				}
				if !d.ip.Equal(res.IP()) {
					t.Errorf("expect: %v, but got %v", d.ip, res.IP())
				}
			})
		}
	}
}
