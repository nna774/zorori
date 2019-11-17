package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
)

// Header is DNS header
type Header struct {
	c    headerContent
	done bool
}

type headerContent struct {
	ID      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

// Question is DNS question section
type Question struct {
	name string
	t    QueryType
	done bool
}

// Query is question from client
type Query struct {
	Header   Header
	Question Question
	done     bool
}

// ResourceRecord is type for Resource Record
type ResourceRecord struct {
	Name        string
	T           QueryType
	Class       Class
	TTL         uint32
	RdLength    uint16
	RdataOffset int
	Rdata       []byte
	head        []byte
}

// Answer is anser from server
type Answer struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
	head        []byte
}

func (r ResourceRecord) String() string {
	return fmt.Sprintf("{Name: %v, Type: %v, Class: %v, TTL: %d, RdLength: %d, Rdata: %v}",
		r.Name,
		r.TypeString(),
		r.ClassString(),
		r.TTL,
		r.RdLength,
		r.ShowRdata(r.T),
	)
}

// ClassString shows class
func (r *ResourceRecord) ClassString() string {
	if r.Class == IN {
		return "IN"
	}
	return fmt.Sprintf("unknown(%v)", r.Class)
}

// TypeString shows rr type
func (r *ResourceRecord) TypeString() string {
	switch r.T {
	case A:
		return "A"
	case NS:
		return "NS"
	case CNAME:
		return "CNAME"
	case SOA:
		return "SOA"
	default:
		return fmt.Sprintf("unknown(%v)", r.T)
	}
}

// ShowRdata shows rr rdata
func (r *ResourceRecord) ShowRdata(t QueryType) string {
	switch t {
	case A:
		return fmt.Sprintf("%d.%d.%d.%d", r.Rdata[0], r.Rdata[1], r.Rdata[2], r.Rdata[3])
	case CNAME:
		name, _ := readName(r.head, r.RdataOffset)
		return name
	case SOA:
		return "soasoa"
	default:
		return "unknown"
	}
}

// CNAMETO returns rr cname if it is cname
func (r *ResourceRecord) CNAMETO() (string, error) {
	if r.T != CNAME {
		return "", errors.New("not CNAME")
	}
	return r.ShowRdata(CNAME), nil
}

// IP returns ip addr if it is A
func (r *ResourceRecord) IP() (net.IP, error) {
	if r.T != A {
		return nil, errors.New("not A")
	}
	return net.IPv4(r.Rdata[0], r.Rdata[1], r.Rdata[2], r.Rdata[3]), nil
}

// NewHeader is ctor of Header
func NewHeader() Header {
	return Header{c: newHeaderContent()}
}

func newHeaderContent() headerContent {
	id := uint16(rand.Uint32())
	//fmt.Printf("id: %v\n", id)
	return headerContent{
		ID: id,
	}
}

func (h *Header) id() uint16 {
	return h.c.ID
}
func (h *Header) setID(id uint16) {
	h.c.ID = id
}

func (h *Header) setFlags(f uint16) {
	h.c.Flags = f
}

func (h *Header) qr() bool {
	return (h.c.Flags & 0x8000) != 0
}
func (h *Header) setQR(qr bool) {
	h.c.Flags = (h.c.Flags & 0x7fff)
	if qr {
		h.c.Flags = h.c.Flags | (1 << 15)
	}
}

func (h *Header) rd() bool {
	return (h.c.Flags & 0x100) != 0
}

func (h *Header) setRD(qr bool) {
	h.c.Flags = (h.c.Flags & 0xfeff)
	if qr {
		h.c.Flags = h.c.Flags | (1 << 8)
	}
}

func (h *Header) opCode() int {
	return int(h.c.Flags&0x7800) >> 11
}
func (h *Header) aa() bool {
	return (h.c.Flags & 0x0400) != 0
}
func (h *Header) tc() bool {
	return (h.c.Flags & 0x0200) != 0
}
func (h *Header) ra() bool {
	return (h.c.Flags & 0x80) != 0
}
func (h *Header) z() bool {
	return (h.c.Flags & 0x40) != 0
}
func (h *Header) ad() bool {
	return (h.c.Flags & 0x20) != 0
}
func (h *Header) cd() bool {
	return (h.c.Flags & 0x10) != 0
}
func (h *Header) rCode() int {
	return int(h.c.Flags & 0xf)
}

func (h *Header) setQDCount(qdCount uint16) {
	h.c.QdCount = qdCount
}
func (h *Header) setANCount(anCount uint16) {
	h.c.AnCount = anCount
}
func (h *Header) setNSCount(nsCount uint16) {
	h.c.NsCount = nsCount
}
func (h *Header) setARCount(arCount uint16) {
	h.c.ArCount = arCount
}
func (h *Header) qdCount() uint16 {
	return h.c.QdCount
}
func (h *Header) anCount() uint16 {
	return h.c.AnCount
}
func (h *Header) nsCount() uint16 {
	return h.c.NsCount
}
func (h Header) String() string {
	return fmt.Sprintf("{id: %v, qr: %v, opcode: %v, aa: %v, tc: %v, rd: %v, ra: %v, z: %v, ad: %v, cd: %v, rcode: %v, qdcount: %v, ancount: %v, nscount: %v, arcount: %v}",
		h.c.ID,
		h.qr(),
		h.opCode(),
		h.aa(),
		h.tc(),
		h.rd(),
		h.ra(),
		h.z(),
		h.ad(),
		h.cd(),
		h.rCode(),
		h.c.QdCount,
		h.c.AnCount,
		h.c.NsCount,
		h.c.ArCount,
	)
}

func (h *Header) Read(p []byte) (n int, err error) {
	if h.done {
		return 0, io.EOF
	}
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, h.c)
	if err != nil {
		return 0, err
	}
	h.done = true
	n, err = buf.Read(p)
	//fmt.Printf("read: %d\n", n)
	//fmt.Printf("p: %v\n", p[:n])
	return n, err
}

func (q *Question) Read(p []byte) (n int, err error) {
	if q.done {
		return 0, io.EOF
	}
	n = 0
	labels := strings.Split(q.name, ".")
	for _, label := range labels {
		len := len(label)
		p[n] = byte(len)
		n++
		for i := 0; i < len; i++ {
			p[n] = label[i]
			n++
		}
		p[n] = 0 // eos
		binary.BigEndian.PutUint16(p[n+1:], uint16(q.t))
		binary.BigEndian.PutUint16(p[n+3:], IN)
	}
	q.done = true
	return n + 5, nil
}

// NewQuery is ctor of Query
func NewQuery(domain string, t QueryType) Query {
	q := Query{
		Header:   NewHeader(),
		Question: Question{name: domain, t: t},
	}
	q.Header.setQDCount(1)
	q.Header.setRD(true)
	return q
}

func (q *Query) Read(p []byte) (n int, err error) {
	if q.done {
		return 0, io.EOF
	}
	hn, err := q.Header.Read(p)
	if err != nil {
		return hn, err
	}
	qn, err := q.Question.Read(p[hn:])
	if err != nil {
		return qn, err
	}
	q.done = true
	return hn + qn, nil
}

func parseHeader(p []byte) (Header, int, error) {
	h := headerContent{}
	r := bytes.NewReader(p)
	err := binary.Read(r, binary.BigEndian, &h)
	if err != nil {
		return Header{}, 12, err
	}
	return Header{c: h}, 12, nil
}

func readName(p []byte, begin int) (string, int) {
	n := 0
	name := ""
	l := int(p[begin])

	for l != 0 {
		//fmt.Printf("l: %v\n", l)
		if l > 64 {
			off := binary.BigEndian.Uint16(p[begin+n:]) - 0xC000
			//fmt.Printf("compression!(n: %d, offset: %d)\n", l, off)
			//fmt.Printf("p[begin:begin+2]: %v\n", p[begin+n:begin+n+2])
			//fmt.Printf("p[begin]: %v\n", int(p[begin+n]))
			//fmt.Printf("p[off]: %v\n", p[n+int(off):])
			suf, _ := readName(p, int(off))
			return name + suf, n + 2
		}

		label := string(p[begin+n+1 : begin+n+l+1])
		name = name + label + "."
		n = n + l + 1
		l = int(p[begin+n])
		//fmt.Printf("l: %v, n: %d, l: %d\n", label, n, l)
	}
	return name, n
}

func parseQuestion(p []byte) (Question, int, error) {
	name, n := readName(p, 0)
	return Question{name: name, t: QueryType(binary.BigEndian.Uint16(p[n+1:]))}, n + 5, nil
}

func parseResourceRecord(p []byte, begin int, head []byte) (ResourceRecord, int, error) {
	name, n := readName(p, begin)
	t := QueryType(binary.BigEndian.Uint16(p[begin+n:]))
	class := Class(binary.BigEndian.Uint16(p[begin+n+2:]))
	ttl := binary.BigEndian.Uint32(p[begin+n+4:])
	rdLength := binary.BigEndian.Uint16(p[begin+n+8:])
	//	fmt.Printf("name: %v, n: %d, type: %d, class: %d, ttl: %d, rdsize: %d\n", name, n, t, class, ttl, rdLength)
	//	fmt.Printf("A: %d.%d.%d.%d\n", p[begin+n+10], p[begin+n+11], p[begin+n+12], p[begin+n+13]) // A!
	return ResourceRecord{
		Name:        name,
		T:           t,
		Class:       class,
		TTL:         ttl,
		RdLength:    rdLength,
		RdataOffset: begin + n + 10,
		Rdata:       p[begin+n+10 : begin+n+10+int(rdLength)],
		head:        head,
	}, n + 10 + int(rdLength), nil
}

// ParseAnswer parses answer from server
func ParseAnswer(ans []byte) (Answer, error) {
	result := Answer{}
	h, _, err := parseHeader(ans)
	fmt.Printf("anser header: %v\n", h)
	if err != nil {
		return result, err
	}
	result.head = ans
	result.Header = h
	result.Questions = make([]Question, h.qdCount())
	result.Answers = make([]ResourceRecord, h.anCount())
	result.Authorities = make([]ResourceRecord, h.nsCount())
	qlen := 0
	for i := 0; i < int(h.qdCount()); i++ {
		q, qn, err := parseQuestion(ans[12+qlen:])
		fmt.Printf("answer question: %v(size: %v)\n", q, qn)
		if err != nil {
			return result, err
		}
		result.Questions[i] = q
		qlen = qlen + qn
	}
	alen := 0
	for i := 0; i < int(h.anCount()); i++ {
		//fmt.Printf("ans[12+qlen+alen:]: %v\n", ans[12+qlen+alen:])
		a, an, err := parseResourceRecord(ans, 12+qlen+alen, result.head)
		fmt.Printf("answer anser: %v(size: %v)\n", a, an)
		if err != nil {
			return result, err
		}
		result.Answers[i] = a
		alen = alen + an
	}
	nslen := 0
	for i := 0; i < int(h.nsCount()); i++ {
		n, nn, err := parseResourceRecord(ans, 12+qlen+alen+nslen, result.head)
		fmt.Printf("answer ns: %v(size: %v)\n", n, nn)
		if err != nil {
			return result, err
		}
		result.Authorities[i] = n
		nslen = nslen + nn
	}
	return result, err
}

// Same decides args is same domain
func Same(lhs, rhs string) bool {
	if lhs == rhs {
		return true
	}
	if lhs[len(lhs)-1] == '.' {
		if rhs[len(rhs)-1] != '.' {
			return lhs[:len(lhs)-1] == rhs
		}
		return false
	}
	if rhs[len(rhs)-1] == '.' {
		return lhs == rhs[:len(rhs)-1]
	}
	return false
}
