package resolver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/nna774/zorori/dns"
	"github.com/pkg/errors"
)

var empty = dns.AResult{}

// DoHResolver resolves by DoH
type DoHResolver struct {
	URL string
}

// NewDoHResolver makes new resolver
func NewDoHResolver(url string) Resolver {
	return &DoHResolver{URL: url}
}

// AResolve resolves A
func (r *DoHResolver) AResolve(domain string) (dns.AResult, error) {
	query := dns.NewQuery(domain, dns.A)
	query.Header.SetRD(true)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, &query)
	if err != nil {
		return empty, errors.Wrap(err, "bie")
	}
	fmt.Printf("buf: %v\n", buf.Bytes())
	encoded := base64.RawURLEncoding.EncodeToString(buf.Bytes()[:n+1])
	q := r.URL + "?dns=" + encoded
	fmt.Printf("encoded: %v\n", encoded)
	res, err := http.Get(q)
	if err != nil {
		return empty, errors.Wrap(err, "bie")
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	fmt.Printf("body: %v\n", body)
	fmt.Printf("bodys: %v\n", string(body))
	ans, err := dns.ParseAnswer(body)
	if err != nil {
		return empty, err
	}
	ret := dns.AResult{}
	searching := domain
	for _, a := range ans.Answers {
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
