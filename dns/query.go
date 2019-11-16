package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"strings"
)

// Header is DNS header
type Header struct {
	c    HeaderContent
	done bool
}

type HeaderContent struct {
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

type Query struct {
	Header   Header
	Question Question
	done     bool
}

type ResourceRecord struct {
	name     string
	t        QueryType
	class    Class
	ttl      uint32
	rdLength uint16
	rdata    []byte
}

type Answer struct {
	Header      Header
	Questions   []Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

func NewHeader() Header {
	return Header{c: NewHeaderContent()}
}

func NewHeaderContent() HeaderContent {
	id := uint16(rand.Uint32())
	fmt.Printf("id: %v\n", id)
	return HeaderContent{
		ID: id,
	}
}

// ID is query ID
func (h *Header) ID() uint16 {
	return h.c.ID
}

func (h *Header) setFlags(f uint16) {
	h.c.Flags = f
}

func (h *Header) QR() bool {
	return (h.c.Flags & 1 << 15) != 0
}

func (h *Header) SetQR(qr bool) {
	h.c.Flags = (h.c.Flags & 0x7fff)
	if qr {
		h.c.Flags = h.c.Flags | (1 << 15)
	}
}

func (h *Header) RD() bool {
	return (h.c.Flags & 1 << 8) != 0
}

func (h *Header) SetRD(qr bool) {
	h.c.Flags = (h.c.Flags & 0xfeff)
	if qr {
		h.c.Flags = h.c.Flags | (1 << 8)
	}
}

func (h *Header) SetID(id uint16) {
	h.c.ID = id
}

func (h *Header) SetQDCount(qdCount uint16) {
	h.c.QdCount = qdCount
}
func (h *Header) SetANCount(anCount uint16) {
	h.c.AnCount = anCount
}
func (h *Header) SetNSCount(nsCount uint16) {
	h.c.NsCount = nsCount
}
func (h *Header) SetARCount(arCount uint16) {
	h.c.ArCount = arCount
}
func (h *Header) QdCount() uint16 {
	return h.c.QdCount
}
func (h *Header) AnCount() uint16 {
	return h.c.AnCount
}
func (h Header) String() string {
	return fmt.Sprintf("{id: %v, f, qdcount: %v, ancount: %v, nscount: %v, arcount: %v}",
		h.c.ID,
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
	fmt.Printf("read: %d\n", n)
	fmt.Printf("p: %v\n", p[:n])
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
		p[n] = 0                               // eos
		binary.BigEndian.PutUint16(p[n+1:], 1) // ! A
		binary.BigEndian.PutUint16(p[n+3:], 1) // IN
	}
	q.done = true
	return n + 5, nil
}

func NewQuery(domain string, t QueryType) Query {
	q := Query{
		Header:   NewHeader(),
		Question: Question{name: domain, t: t},
	}
	q.Header.SetQDCount(1)
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

func ParseHeader(p []byte) (Header, int, error) {
	h := HeaderContent{}
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
		if l > 64 {
			off := binary.BigEndian.Uint16(p[begin:]) - 0xC000
			fmt.Printf("compression enabled(n: %d, offset: %d)\n", l, off)
			fmt.Printf("p[off]: %v\n", p[off:])
			suf, _ := readName(p[off:], 0)
			return name + suf, n + 2
		}

		label := string(p[n : n+l+1])
		name = name + label + "."
		n = n + l + 1
		l = int(p[n])
		//fmt.Printf("l: %v, n: %d, l: %d\n", label, n, l)
	}
	return name, n
}

func ParseQuestion(p []byte) (Question, int, error) {
	name, n := readName(p, 0)
	return Question{name: name, t: QueryType(binary.BigEndian.Uint16(p[n+1:]))}, n + 5, nil
}

func ParseResourceRecord(p []byte, begin int) (ResourceRecord, int, error) {
	name, n := readName(p, begin)
	t := QueryType(binary.BigEndian.Uint16(p[begin+n:]))
	class := Class(binary.BigEndian.Uint16(p[begin+n+2:]))
	ttl := binary.BigEndian.Uint32(p[begin+n+4:])
	rdsize := binary.BigEndian.Uint16(p[begin+n+8:])
	fmt.Printf("name: %v, n: %d, type: %d, class: %d, ttl: %d, rdsize: %d\n", name, n, t, class, ttl, rdsize)
	fmt.Printf("A: %d.%d.%d.%d\n", p[begin+n+10], p[begin+n+11], p[begin+n+12], p[begin+n+13]) // A!
	return ResourceRecord{name: name}, n + 10 + int(rdsize), nil
}

func ParseAnswer(ans []byte) (Answer, error) {
	result := Answer{}
	h, _, err := ParseHeader(ans)
	fmt.Printf("anser header: %v\n", h)
	if err != nil {
		return result, err
	}
	result.Header = h
	result.Questions = make([]Question, h.QdCount())
	result.Answers = make([]ResourceRecord, h.AnCount())
	qlen := 0
	for i := 0; i < int(h.QdCount()); i++ {
		q, qn, err := ParseQuestion(ans[12+qlen:])
		fmt.Printf("anser question: %v(size: %v)\n", q, qn)
		if err != nil {
			return result, err
		}
		result.Questions[i] = q
		qlen = qlen + qn
	}
	alen := 0
	for i := 0; i < int(h.AnCount()); i++ {
		a, an, err := ParseResourceRecord(ans, 12+qlen+alen)
		fmt.Printf("anser anser: %v(size: %v)\n", a, an)
		if err != nil {
			return result, err
		}
		result.Answers[i] = a
		alen = alen + an
	}
	return result, err
}
