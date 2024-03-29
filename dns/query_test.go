package dns

import (
	"testing"
)

func TestSame(t *testing.T) {
	sames := []struct {
		name string
		lhs  string
		rhs  string
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
			if !Same(v.lhs, v.rhs) {
				t.Fatalf("%v and %v shold be same", v.lhs, v.rhs)
			}
		})
	}
}
func TestNotSame(t *testing.T) {
	diffs := []struct {
		name string
		lhs  string
		rhs  string
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
			if Same(v.lhs, v.rhs) {
				t.Fatalf("%v and %v shold not be same", v.lhs, v.rhs)
			}
		})
	}
}

func TestReadName(t *testing.T) {
	names := []struct {
		name     []byte
		len      int
		expected string
	}{
		{[]byte{0}, 1, ""},
		{[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 13, "example.com"},
	}
	for _, v := range names {
		t.Run(v.expected, func(t *testing.T) {
			name, len := readName(v.name, 0)
			if !Same(name, v.expected) || len != v.len {
				t.Fatalf("expected (name, len): (%v, %v), but got (%v, %v).", v.expected, v.len, name, len)
			}
		})
	}
}

func TestReadNameWithCompression(t *testing.T) {
	names := []struct {
		name     []byte
		len      int
		begin    int
		expected string
	}{
		{[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}, 13, 0, "example.com"},
		{[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xc0, 0}, 2, 13, "example.com"},
		{[]byte{'p', 'a', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0xc0, 3}, 2, 16, "example.com"},
		{[]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 2, 'n', 's', 0xc0, 0}, 5, 13, "ns.example.com"},
		{[]byte{'p', 'a', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 2, 'n', 's', 0xc0, 3}, 5, 16, "ns.example.com"},
	}
	for _, v := range names {
		t.Run(v.expected, func(t *testing.T) {
			name, len := readName(v.name, v.begin)
			if !Same(name, v.expected) || len != v.len {
				t.Fatalf("expected (name, len): (%v, %v), but got (%v, %v).", v.expected, v.len, name, len)
			}
		})
	}
}

func TestNameIdentity(t *testing.T) {
	names := []struct {
		name string
	}{
		{"example.com"},
	}
	for _, v := range names {
		t.Run(v.name, func(t *testing.T) {
			buf := make([]byte, 1500)
			WriteName(buf, v.name)
			name, _ := readName(buf, 0)
			if !Same(name, v.name) {
				t.Fatalf("expected: %v, but got %v.", v.name, name)
			}
		})
	}
}
