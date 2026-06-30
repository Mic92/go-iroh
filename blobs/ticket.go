package blobs

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const (
	// TicketKind is the string prefix for blob tickets.
	TicketKind  = "blob"
	wireVariant = 0

	// maxAddrs bounds ticket address allocations. It is a DoS guard, not a
	// wire-compatibility limit.
	maxAddrs = endpointticket.MaxAddrs
)

// Ticket is an iroh-blobs ticket.
type Ticket struct {
	addr   netaddr.EndpointAddr
	hash   Hash
	format BlobFormat
}

// NewTicket returns a blob ticket for addr, hash, and format.
func NewTicket(addr netaddr.EndpointAddr, hash Hash, format BlobFormat) Ticket {
	return Ticket{addr: addr, hash: hash, format: format}
}

// ParseTicket parses s as a blob ticket.
func ParseTicket(s string) (Ticket, error) { return DecodeString(s) }

// DecodeString parses s as a blob ticket.
func DecodeString(s string) (Ticket, error) {
	rest, ok := strings.CutPrefix(s, TicketKind)
	if !ok {
		return Ticket{}, &endpointticket.ParseError{
			Kind:     endpointticket.ParseErrorKindKind,
			Expected: TicketKind,
		}
	}
	b, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	if err != nil {
		return Ticket{}, &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindEncoding, Err: err}
	}
	return DecodeBytes(b)
}

// DecodeBytes decodes the postcard bytes of a blob ticket.
func DecodeBytes(b []byte) (Ticket, error) {
	p := parser{b: b}
	variant, err := p.varint()
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	if variant != wireVariant {
		return Ticket{}, verifyErr(fmt.Sprintf("unsupported variant %d", variant), nil)
	}
	idBytes, err := p.bytes(key.PublicKeySize)
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	id, err := key.EndpointIDFromSlice(idBytes)
	if err != nil {
		return Ticket{}, verifyErr("endpoint id", err)
	}
	addrs, err := p.addrInfo()
	if err != nil {
		return Ticket{}, err
	}
	f, err := p.varint()
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	format, err := verifyFormat(f)
	if err != nil {
		return Ticket{}, verifyErr(err.Error(), nil)
	}
	hashBytes, err := p.bytes(HashSize)
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	if !p.done() {
		return Ticket{}, wrapDecodeErr(endpointticket.ErrTrailingBytes)
	}
	var hash Hash
	copy(hash[:], hashBytes)
	return NewTicket(netaddr.NewEndpointAddr(id, addrs...), hash, format), nil
}

// Register registers the blob ticket decoder in r.
func Register(r *endpointticket.Registry) error {
	return r.Register(TicketKind, func(b []byte) (endpointticket.TicketCodec, error) {
		return DecodeBytes(b)
	})
}

// Addr returns the provider endpoint address.
func (t Ticket) Addr() netaddr.EndpointAddr { return t.addr }

// Short returns a ticket containing only the endpoint id and relay URLs.
func (t Ticket) Short() Ticket {
	return NewTicket(endpointticket.ShortAddr(t.addr), t.hash, t.format)
}

// Hash returns the blob hash.
func (t Ticket) Hash() Hash { return t.hash }

// Format returns the blob format.
func (t Ticket) Format() BlobFormat { return t.format }

// HashAndFormat returns the ticket's content identifier.
func (t Ticket) HashAndFormat() HashAndFormat {
	return HashAndFormat{Hash: t.hash, Format: t.format}
}

// Recursive reports whether this ticket requests a hash sequence.
func (t Ticket) Recursive() bool { return t.format.IsHashSeq() }

// Kind returns the ticket kind prefix.
func (t Ticket) Kind() string { return TicketKind }

// EncodeBytes returns the Rust-compatible postcard ticket payload.
func (t Ticket) EncodeBytes() []byte {
	var b []byte
	b = appendVarint(b, wireVariant)
	id := t.addr.ID.Bytes()
	b = append(b, id[:]...)
	b = appendAddrInfo(b, t.addr)
	b = appendVarint(b, uint64(t.format))
	return append(b, t.hash[:]...)
}

// EncodeString returns the canonical ticket string.
func (t Ticket) EncodeString() string {
	return TicketKind + strings.ToLower(base32NoPad.EncodeToString(t.EncodeBytes()))
}

// String returns the canonical ticket string.
func (t Ticket) String() string { return t.EncodeString() }

// MarshalText implements encoding.TextMarshaler.
func (t Ticket) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *Ticket) UnmarshalText(text []byte) error {
	tt, err := ParseTicket(string(text))
	if err != nil {
		return err
	}
	*t = tt
	return nil
}

func appendAddrInfo(b []byte, addr netaddr.EndpointAddr) []byte {
	relays := addr.RelayURLs()
	if len(relays) == 0 {
		b = appendVarint(b, 0)
	} else {
		b = appendVarint(b, 1)
		s := []byte(relays[0].String())
		b = appendVarint(b, uint64(len(s)))
		b = append(b, s...)
	}
	ips := addr.IPAddrs()
	slices.SortFunc(ips, netip.AddrPort.Compare)
	b = appendVarint(b, uint64(len(ips)))
	for _, ap := range ips {
		b = appendSocketAddr(b, ap)
	}
	return b
}

func appendSocketAddr(b []byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	if addr.Is4() {
		ip := addr.As4()
		b = appendVarint(b, 0)
		b = append(b, ip[:]...)
	} else {
		ip := addr.As16()
		b = appendVarint(b, 1)
		b = append(b, ip[:]...)
	}
	return appendVarint(b, uint64(ap.Port()))
}

func wrapDecodeErr(err error) error {
	if err == nil {
		return nil
	}
	return &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindPostcard, Err: err}
}

func verifyErr(msg string, err error) error {
	return &endpointticket.ParseError{
		Kind:    endpointticket.ParseErrorKindVerify,
		Message: msg,
		Err:     err,
	}
}

func appendVarint(b []byte, n uint64) []byte {
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	return append(b, byte(n))
}

type parser struct {
	b   []byte
	off int
}

func (p *parser) done() bool { return p.off == len(p.b) }

func (p *parser) bytes(n int) ([]byte, error) {
	if n < 0 || len(p.b)-p.off < n {
		return nil, endpointticket.ErrTruncated
	}
	out := p.b[p.off : p.off+n]
	p.off += n
	return out, nil
}

func (p *parser) varint() (uint64, error) {
	var x uint64
	var s uint
	for i := 0; ; i++ {
		if p.off >= len(p.b) {
			return 0, endpointticket.ErrTruncated
		}
		c := p.b[p.off]
		p.off++
		if c < 0x80 {
			if i > 9 || i == 9 && c > 1 {
				return 0, endpointticket.ErrVarintOverflow
			}
			return x | uint64(c)<<s, nil
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
}

func (p *parser) string() (string, error) {
	n, err := p.varint()
	if err != nil {
		return "", err
	}
	if n > uint64(len(p.b)-p.off) {
		return "", endpointticket.ErrTruncated
	}
	s := string(p.b[p.off : p.off+int(n)])
	p.off += int(n)
	return s, nil
}

func (p *parser) addrInfo() ([]netaddr.TransportAddr, error) {
	var addrs []netaddr.TransportAddr
	hasRelay, err := p.varint()
	if err != nil {
		return nil, wrapDecodeErr(err)
	}
	switch hasRelay {
	case 0:
	case 1:
		s, err := p.string()
		if err != nil {
			return nil, wrapDecodeErr(err)
		}
		u, err := netaddr.ParseRelayURL(s)
		if err != nil {
			return nil, verifyErr("relay url", err)
		}
		addrs = append(addrs, netaddr.RelayAddr{URL: u})
	default:
		return nil, verifyErr(fmt.Sprintf("unsupported relay option %d", hasRelay), nil)
	}
	n, err := p.varint()
	if err != nil {
		return nil, wrapDecodeErr(err)
	}
	if n > maxAddrs {
		return nil, verifyErr(fmt.Sprintf("too many addresses %d", n), nil)
	}
	for range n {
		ap, err := p.socketAddr()
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, netaddr.IPAddr{Addr: ap})
	}
	return addrs, nil
}

func (p *parser) socketAddr() (netip.AddrPort, error) {
	family, err := p.varint()
	if err != nil {
		return netip.AddrPort{}, wrapDecodeErr(err)
	}
	var addr netip.Addr
	switch family {
	case 0:
		ip, err := p.bytes(4)
		if err != nil {
			return netip.AddrPort{}, wrapDecodeErr(err)
		}
		var a [4]byte
		copy(a[:], ip)
		addr = netip.AddrFrom4(a)
	case 1:
		ip, err := p.bytes(16)
		if err != nil {
			return netip.AddrPort{}, wrapDecodeErr(err)
		}
		var a [16]byte
		copy(a[:], ip)
		addr = netip.AddrFrom16(a)
	default:
		return netip.AddrPort{}, verifyErr(fmt.Sprintf("unsupported IP family %d", family), nil)
	}
	port, err := p.varint()
	if err != nil {
		return netip.AddrPort{}, wrapDecodeErr(err)
	}
	if port > 65535 {
		return netip.AddrPort{}, verifyErr(fmt.Sprintf("invalid port %d", port), nil)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

var _ endpointticket.TicketCodec = Ticket{}
