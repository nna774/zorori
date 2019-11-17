package dns_test

import (
	"testing"

	"github.com/nna774/zorori/dns"
)

func TestSame(t *testing.T) {
	sames := []struct {
		name string
		lhs string
		rhs string
	}{
		{"spaces", "", ""},
		{"space and dot", "", "."},
		{"space and dot", ".", ""},
		{"dots", ".", "."},
		{"example", "example.com", "example.com."},
		{"case", "jp", "JP."},
	}
	for _, v := range sames {
		t.Run(v.name, func(t *testing.T) {
			if !dns.Same(v.lhs, v.rhs) {
				t.Fatalf("%v and %v shold be same", v.lhs, v.rhs)
			}
		})
	}
}
func TestNotSame(t *testing.T) {
	diffs := []struct {
		name string
		lhs string
		rhs string
	}{
		{"root", "root", ""},
		{"root2", "root.", "."},
		{"jp", "jp.", "net."},
		{"example", "example.com", "example.com.com"},
		{"example2", "example.com", "example.com.com."},
		{"example3", "example.com.", "example.com.com"},
	}
	for _, v := range diffs {
		t.Run(v.name, func(t *testing.T) {
			if dns.Same(v.lhs, v.rhs) {
				t.Fatalf("%v and %v shold not be same", v.lhs, v.rhs)
			}
		})
	}
}
