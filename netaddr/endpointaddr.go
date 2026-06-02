package netaddr

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/tmc/go-iroh/key"
)

// TransportAddr is a network-level address at which an endpoint may be reached.
// It is one of [RelayAddr], [IPAddr], or [CustomAddr].
//
// The interface is closed: only the implementations in this package satisfy it.
type TransportAddr interface {
	// String renders the address in its "kind:value" form, e.g. "ip:127.0.0.1:9".
	String() string
	// Compare returns -1, 0, or +1 ordering this address against other. The
	// order matches the Rust reference's derived Ord on the TransportAddr enum:
	// by kind first (relay < ip < custom), then by value (relay URLs by their
	// normalized string, IP addresses numerically, custom by id then data).
	Compare(other TransportAddr) int
	isTransportAddr()
}

// transportKind is the kind ordinal used as the primary ordering key, matching
// the Rust enum variant order: Relay(0) < Ip(1) < Custom(2).
func transportKind(a TransportAddr) int {
	switch a.(type) {
	case RelayAddr:
		return 0
	case IPAddr:
		return 1
	case CustomAddr:
		return 2
	default:
		return 3
	}
}

// RelayAddr is a [TransportAddr] reachable via a relay server.
type RelayAddr struct{ URL RelayUrl }

// IPAddr is a [TransportAddr] reachable at an IP socket address.
type IPAddr struct{ Addr netip.AddrPort }

// CustomAddr is a custom transport address: a freely-chosen u64 transport id
// plus opaque, unvalidated address data.
//
// A registry of well-known transport ids is at
// https://github.com/n0-computer/iroh/blob/main/TRANSPORTS.md.
//
// String encoding ([CustomAddr.String], [ParseCustomAddr]): "<id>_<data>" where
// <id> is the transport id as lowercase hex (no "0x", no leading zeros) and
// <data> is the address bytes as lowercase hex.
//
// Binary encoding ([CustomAddr.MarshalBinary], [CustomAddrFromBytes]): 8-byte
// little-endian u64 id followed by the raw data bytes (minimum 8 bytes).
type CustomAddr struct {
	id   uint64
	data []byte
}

func (RelayAddr) isTransportAddr()  {}
func (IPAddr) isTransportAddr()     {}
func (CustomAddr) isTransportAddr() {}

func (a RelayAddr) String() string  { return "relay:" + a.URL.String() }
func (a IPAddr) String() string     { return "ip:" + a.Addr.String() }
func (a CustomAddr) String() string { return "custom:" + a.customString() }

// Compare orders relay addresses by their normalized URL string.
func (a RelayAddr) Compare(other TransportAddr) int {
	if b, ok := other.(RelayAddr); ok {
		return a.URL.Compare(b.URL)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// Compare orders IP addresses numerically (by [netip.AddrPort.Compare]).
func (a IPAddr) Compare(other TransportAddr) int {
	if b, ok := other.(IPAddr); ok {
		return a.Addr.Compare(b.Addr)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// Compare orders custom addresses by numeric transport id, then by data bytes.
func (a CustomAddr) Compare(other TransportAddr) int {
	if b, ok := other.(CustomAddr); ok {
		if c := cmp.Compare(a.id, b.id); c != 0 {
			return c
		}
		return bytes.Compare(a.data, b.data)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// NewCustomAddr creates a CustomAddr from a transport id and raw address data.
// The data is copied.
func NewCustomAddr(id uint64, data []byte) CustomAddr {
	return CustomAddr{id: id, data: slices.Clone(data)}
}

// Id returns the transport id.
func (a CustomAddr) Id() uint64 { return a.id }

// Data returns the opaque address data. The returned slice must not be mutated.
func (a CustomAddr) Data() []byte { return a.data }

func (a CustomAddr) customString() string {
	return strconv.FormatUint(a.id, 16) + "_" + hex.EncodeToString(a.data)
}

// String renders the custom address in its bare "<id>_<data>" form (without the
// "custom:" prefix used by the TransportAddr String).
func (a CustomAddr) BareString() string { return a.customString() }

// CustomAddr parse/encode errors.
var (
	ErrCustomAddrMissingSeparator = errors.New("missing '_' separator")
	ErrCustomAddrInvalidId        = errors.New("invalid id")
	ErrCustomAddrInvalidData      = errors.New("invalid data")
	ErrCustomAddrTooShort         = errors.New("data too short")
)

// ParseCustomAddr parses a CustomAddr from its "<id>_<data>" string form.
func ParseCustomAddr(s string) (CustomAddr, error) {
	idStr, dataStr, ok := strings.Cut(s, "_")
	if !ok {
		return CustomAddr{}, ErrCustomAddrMissingSeparator
	}
	id, err := strconv.ParseUint(idStr, 16, 64)
	if err != nil {
		return CustomAddr{}, ErrCustomAddrInvalidId
	}
	data, err := hex.DecodeString(dataStr)
	if err != nil {
		return CustomAddr{}, ErrCustomAddrInvalidData
	}
	return CustomAddr{id: id, data: data}, nil
}

// MarshalBinary implements encoding.BinaryMarshaler using the binary encoding
// described on [CustomAddr].
func (a CustomAddr) MarshalBinary() ([]byte, error) {
	out := make([]byte, 8+len(a.data))
	binary.LittleEndian.PutUint64(out[:8], a.id)
	copy(out[8:], a.data)
	return out, nil
}

// CustomAddrFromBytes parses a CustomAddr from its binary encoding.
func CustomAddrFromBytes(data []byte) (CustomAddr, error) {
	if len(data) < 8 {
		return CustomAddr{}, ErrCustomAddrTooShort
	}
	id := binary.LittleEndian.Uint64(data[:8])
	return CustomAddr{id: id, data: slices.Clone(data[8:])}, nil
}

// ParseTransportAddr parses a TransportAddr from its "kind:value" string form.
func ParseTransportAddr(s string) (TransportAddr, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok {
		return nil, fmt.Errorf("transport address %q: missing ':' separator", s)
	}
	switch kind {
	case "relay":
		u, err := ParseRelayUrl(value)
		if err != nil {
			return nil, err
		}
		return RelayAddr{URL: u}, nil
	case "ip":
		ap, err := netip.ParseAddrPort(value)
		if err != nil {
			return nil, fmt.Errorf("transport address %q: %w", s, err)
		}
		return IPAddr{Addr: ap}, nil
	case "custom":
		return ParseCustomAddr(value)
	default:
		return nil, fmt.Errorf("transport address %q: unknown kind %q", s, kind)
	}
}

// EndpointAddr combines an endpoint's [key.EndpointId] with the network-level
// addresses at which it may be reached.
//
// To establish a connection both the key.EndpointId and at least one path (a relay
// URL or a direct IP address) are needed; an EndpointAddr with no addresses is
// still usable together with an address-lookup service.
type EndpointAddr struct {
	// Id is the endpoint's identifier.
	Id key.EndpointId
	// addrs is the sorted, deduplicated set of transport addresses.
	addrs []TransportAddr
}

// NewEndpointAddr creates an EndpointAddr with the given id and no addresses.
func NewEndpointAddr(id key.EndpointId) EndpointAddr {
	return EndpointAddr{Id: id}
}

// EndpointAddrFromParts creates an EndpointAddr from an id and a set of
// transport addresses (deduplicated and sorted).
func EndpointAddrFromParts(id key.EndpointId, addrs ...TransportAddr) EndpointAddr {
	a := EndpointAddr{Id: id}
	return a.WithAddrs(addrs...)
}

// WithRelayURL returns a copy of a with the given relay URL added.
func (a EndpointAddr) WithRelayURL(u RelayUrl) EndpointAddr {
	return a.WithAddrs(RelayAddr{URL: u})
}

// WithIP returns a copy of a with the given IP address added.
func (a EndpointAddr) WithIP(ap netip.AddrPort) EndpointAddr {
	return a.WithAddrs(IPAddr{Addr: ap})
}

// WithAddrs returns a copy of a with the given addresses added. The result's
// address set is sorted and deduplicated.
func (a EndpointAddr) WithAddrs(addrs ...TransportAddr) EndpointAddr {
	merged := append(slices.Clone(a.addrs), addrs...)
	merged = sortDedupAddrs(merged)
	return EndpointAddr{Id: a.Id, addrs: merged}
}

// Addrs returns the sorted, deduplicated transport addresses. The returned
// slice must not be mutated.
func (a EndpointAddr) Addrs() []TransportAddr { return a.addrs }

// IsEmpty reports whether only the key.EndpointId is present.
func (a EndpointAddr) IsEmpty() bool { return len(a.addrs) == 0 }

// IPAddrs returns the IP socket addresses of this endpoint.
func (a EndpointAddr) IPAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	for _, addr := range a.addrs {
		if ip, ok := addr.(IPAddr); ok {
			out = append(out, ip.Addr)
		}
	}
	return out
}

// RelayURLs returns the relay URLs of this endpoint. In practice this is
// expected to be zero or one home relay.
func (a EndpointAddr) RelayURLs() []RelayUrl {
	var out []RelayUrl
	for _, addr := range a.addrs {
		if r, ok := addr.(RelayAddr); ok {
			out = append(out, r.URL)
		}
	}
	return out
}

func sortDedupAddrs(addrs []TransportAddr) []TransportAddr {
	slices.SortFunc(addrs, TransportAddr.Compare)
	return slices.CompactFunc(addrs, func(x, y TransportAddr) bool {
		return x.Compare(y) == 0
	})
}
