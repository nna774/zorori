package udp

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/nna774/zorori/dns"
	"github.com/nna774/zorori/resolver"
	"github.com/nna774/zorori/resolver/implements"
	"github.com/pkg/errors"
)

var rootServers = []net.IP{
	net.ParseIP("198.41.0.4"),
}

type udpResolver struct {
	stub     bool
	resolver net.IP
}

// NewUDPStubResolver makes new stub resolver
func NewUDPStubResolver(fullResolver net.IP) resolver.Resolver {
	return &udpResolver{
		stub:     true,
		resolver: fullResolver,
	}
}

// NewUDPFullResolver makes new full resolver
func NewUDPFullResolver() resolver.Resolver {
	return &udpResolver{
		stub:     false,
		resolver: rootServers[0],
	}
}

func (t *udpResolver) AResolve(domain string) (dns.AResult, error) {
	query := dns.NewQuery(domain, dns.A)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, &query)
	if err != nil {
		return implements.AFail(errors.Wrap(err, "bieao"))
	}
	p := buf.Bytes()
	fmt.Printf("buf: %v(size: %v)\n", p, n)
	srv := net.UDPAddr{
		IP:   t.resolver,
		Port: 53,
	}
	conn, err := net.DialUDP("udp", nil, &srv)
	if err != nil {
		return implements.AFail(errors.Wrap(err, "bieeeee"))
	}
	m, err := conn.Write(p)
	if err != nil {
		return implements.AFail(errors.Wrap(err, "beee"))
	}
	body := make([]byte, 512)
	r, err := conn.Read(body)
	body = body[:r]
	if err != nil {
		return implements.AFail(errors.Wrap(err, "peoe"))
	}
	conn.Close()
	fmt.Printf("body: %v(size: %v, len: %v, read: %v)\n", body, m, len(body), r)
	fmt.Printf("bodys: %v\n", string(body))
	ans, err := dns.ParseAnswer(body)
	if err != nil {
		return implements.AFail(errors.Wrap(err, "poe"))
	}
	ret := dns.AResult{}
	searching := domain
	for _, a := range ans.Answers {
		// これだと順序が変わると引けなくなる。
		if dns.Same(searching, a.Name) {
			switch a.T {
			case dns.A:
				ip, _ := a.IP()
				ret = dns.NewAResult(ip)
				break
			case dns.CNAME:
				searching, _ = a.CNAMETO()
			}
		}
	}

	if !t.stub {
		// 再帰問い合わせをする。
		if len(ans.Authorities) > 0 {

		}
	}
	return ret, nil
}

func (t *udpResolver) SVCBResolve() (dns.SVCBResult, error) {
	query := dns.NewQuery("_dns.resolver.arpa", dns.SVCB)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, &query)
	if err != nil {
		return implements.SVCBFail(errors.Wrap(err, "bieao"))
	}
	p := buf.Bytes()
	fmt.Printf("buf: %v(size: %v)\n", p, n)
	srv := net.UDPAddr{
		IP:   t.resolver,
		Port: 53,
	}
	conn, err := net.DialUDP("udp", nil, &srv)
	if err != nil {
		return implements.SVCBFail(errors.Wrap(err, "bieeeee"))
	}
	m, err := conn.Write(p)
	if err != nil {
		return implements.SVCBFail(errors.Wrap(err, "beee"))
	}
	body := make([]byte, 512)
	r, err := conn.Read(body)
	body = body[:r]
	if err != nil {
		return implements.SVCBFail(errors.Wrap(err, "peoe"))
	}
	conn.Close()
	fmt.Printf("body: %v(size: %v, len: %v, read: %v)\n", body, m, len(body), r)
	fmt.Printf("bodys: %v\n", string(body))
	ans, err := dns.ParseAnswer(body)
	if err != nil {
		return implements.SVCBFail(errors.Wrap(err, "poe"))
	}
	ret := dns.SVCBResult{
		Target: ans.Answers[0].Name, // 大嘘 unused回避のため
	}

	return ret, nil

}
