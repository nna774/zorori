package doh

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/nna774/zorori/dns"
	"github.com/nna774/zorori/resolver"
	"github.com/pkg/errors"
)

// DoHResolver resolves by DoH
type DoHResolver struct {
	URL string
}

// NewDoHResolver makes new resolver
func NewDoHResolver(url string) resolver.Resolver {
	return &DoHResolver{URL: url}
}

func aFail(err error) (dns.AResult, error) {
	return dns.AResult{}, err
}

// AResolve resolves A
func (r *DoHResolver) AResolve(domain string) (dns.AResult, error) {
	query := dns.NewQuery(domain, dns.A)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, &query)
	if err != nil {
		return aFail(errors.Wrap(err, "bie"))
	}
	fmt.Printf("buf: %v\n", buf.Bytes())
	encoded := base64.RawURLEncoding.EncodeToString(buf.Bytes()[:n+1])
	q := r.URL + "?dns=" + encoded
	fmt.Printf("encoded: %v\n", encoded)
	res, err := http.Get(q)
	if err != nil {
		return aFail(errors.Wrap(err, "bie"))
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	fmt.Printf("body: %v\n", body)
	fmt.Printf("bodys: %v\n", string(body))
	ans, err := dns.ParseAnswer(body)
	if err != nil {
		return aFail(err)
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

	return ret, nil
}
