package dns

import (
	"fmt"
	"net"
)

const (
	// A is RR type A
	A = 1
	// NS is RR type NS
	NS = 2
	// CNAME is RR type CNAME
	CNAME = 5
	// SOA is RR type SOA
	SOA = 6
	// AAAA is RR type AAAA
	AAAA = 28
	// SVCB is
	SVCB = 64
	// HTTPS is
	HTTPS = 65

	// IN is IN
	IN = 1
)

// QueryType is query type
type QueryType int

// Class is RR class
type Class int

// ShowQueryType returns query type
type ShowQueryType interface {
	Type() QueryType
}

// Result is interface of Resolve
type Result interface {
	ShowQueryType
}

// AResult is result of A
type AResult struct {
	ip net.IP
}

type SVCBResult struct {
	Priority int
	Target   string
	Params   map[int]string
}

func (q QueryType) String() string {
	switch q {
	case A:
		return "A"
	case NS:
		return "NS"
	case CNAME:
		return "CNAME"
	case SOA:
		return "SOA"
	case AAAA:
		return "AAAA"
	case SVCB:
		return "SVCB"
	case HTTPS:
		return "HTTPS"
	default:
		return fmt.Sprintf("unknown(%d)", q)
	}
}

func (c Class) String() string {
	switch c {
	case IN:
		return "IN"
	default:
		return fmt.Sprintf("unknown(%d)", c)
	}
}

// Type returns query type
func (a *AResult) Type() QueryType {
	return A
}

// IP returns result
func (a *AResult) IP() net.IP {
	return a.ip
}

// NewAResult is AResult ctor
func NewAResult(ip net.IP) AResult {
	return AResult{
		ip: ip,
	}
}
