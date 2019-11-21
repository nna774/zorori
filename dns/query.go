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
	return r.Class.String()
}

// TypeString shows rr type
func (r *ResourceRecord) TypeString() string {
	return r.T.String()
}

// ShowRdata shows rr rdata
func (r *ResourceRecord) ShowRdata(t QueryType) string {
	switch t {
	case A, AAAA:
		return fmt.Sprintf("%v", net.IP(r.Rdata))
	case CNAME, NS:
		name, _ := readName(r.head, r.RdataOffset)
		return name
	case SOA:
		mname, mn := readName(r.head, r.RdataOffset)
		rname, rn := readName(r.head, r.RdataOffset+mn)
		serial := binary.BigEndian.Uint32(r.head[r.RdataOffset+mn+rn:])
		return fmt.Sprintf("{mname: %v, rname: %v, serial: %v}", mname, rname, serial)
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
func (h *Header) arCount() uint16 {
	return h.c.ArCount
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
	name := Normalize(q.name) //
	labels := strings.Split(name, ".")
	for _, label := range labels {
		len := len(label)
		p[n] = byte(len)
		n++
		for i := 0; i < len; i++ {
			p[n] = label[i]
			n++
		}
	}
	binary.BigEndian.PutUint16(p[n:], uint16(q.t))
	binary.BigEndian.PutUint16(p[n+2:], IN)
	q.done = true
	return n + 4, nil
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
	return name, n + 1
}

func parseQuestion(p []byte) (Question, int, error) {
	name, n := readName(p, 0)
	return Question{name: name, t: QueryType(binary.BigEndian.Uint16(p[n:]))}, n + 4, nil
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
	h, offset, err := parseHeader(ans)
	fmt.Printf("anser header: %v\n", h)
	if err != nil {
		return result, err
	}
	result.head = ans
	result.Header = h
	result.Questions = make([]Question, h.qdCount())
	result.Answers = make([]ResourceRecord, h.anCount())
	result.Authorities = make([]ResourceRecord, h.nsCount())
	result.Additionals = make([]ResourceRecord, h.arCount())
	for i := 0; i < int(h.qdCount()); i++ {
		q, qn, err := parseQuestion(ans[offset:])
		fmt.Printf("answer question: %v(size: %v)\n", q, qn)
		if err != nil {
			return result, err
		}
		result.Questions[i] = q
		offset += qn
	}
	for i := 0; i < int(h.anCount()); i++ {
		a, an, err := parseResourceRecord(ans, offset, result.head)
		fmt.Printf("answer anser: %v(size: %v)\n", a, an)
		if err != nil {
			return result, err
		}
		result.Answers[i] = a
		offset += an
	}
	for i := 0; i < int(h.nsCount()); i++ {
		n, nn, err := parseResourceRecord(ans, offset, result.head)
		fmt.Printf("answer ns: %v(size: %v)\n", n, nn)
		if err != nil {
			return result, err
		}
		result.Authorities[i] = n
		offset += nn
	}
	for i := 0; i < int(h.arCount()); i++ {
		a, an, err := parseResourceRecord(ans, offset, result.head)
		fmt.Printf("answer additional: %v(size: %v)\n", a, an)
		if err != nil {
			return result, err
		}
		result.Additionals[i] = a
		offset += an
	}
	return result, err
}

func sameImp(lhss, rhss []string) bool {
	// lhss のほうが長い。
	llen := len(lhss)
	rlen := len(rhss)
	if !(llen == rlen || llen == rlen+1) {
		return false
	}
	for i := 0; i < rlen; i++ {
		if lhss[i] != rhss[i] {
			return false
		}
	}
	if llen == rlen {
		return true
	}
	return lhss[llen-1] == ""
}

// Normalize normalize rr name
func Normalize(name string) string {
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}
	return name
}

// Same decides args is same domain
func Same(lhs, rhs string) bool {
	lhss := strings.Split(Normalize(lhs), ".")
	rhss := strings.Split(Normalize(rhs), ".")
	llen := len(lhss)
	rlen := len(rhss)

	if rlen > llen {
		return sameImp(rhss, lhss)
	}
	return sameImp(lhss, rhss)
}
