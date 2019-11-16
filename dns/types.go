package dns

import "net"

const (
	// A is RR type A
	A = 1
	// NS is RR type NS
	NS = 2
	// CNAME is RR tyoe CNAME
	CNAME = 5
	// IN is IN
	IN = 1
)

// QueryType is query type
type QueryType int

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

// Type returns query type
func (a *AResult) Type() QueryType {
	return A
}

// IP returns result
func (a *AResult) IP() net.IP {
	return a.ip
}
