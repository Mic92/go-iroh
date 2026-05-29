package socket

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/tmc/go-iroh/base"
)

// Socket holds the magic socket's mapped-address tables: the bidirectional maps
// between transport addresses and the synthetic IPv6 ULAs that quic-go uses to
// address paths. It is the Go analog of the Rust Socket's mapped_addrs
// (iroh/src/socket.rs:332).
//
// A Socket is created by [NewSocket] and shared by a [MagicConn] and its
// [Transports]. It is safe for concurrent use. The zero Socket is not usable;
// use [NewSocket].
type Socket struct {
	// relayAddrs maps (relay url, endpoint id) pairs to relay mapped addresses.
	// The map key is the relay key's string form, because base.RelayUrl wraps a
	// pointer and is not reliably comparable across separately-parsed URLs.
	relayAddrs *AddrMap[string, RelayMappedAddr]
	// relayByKey recovers the original RelayKey from its string form.
	relayMu    sync.Mutex
	relayByKey map[string]RelayKey

	// customAddrs maps a custom address (by its string key) to a custom mapped
	// address.
	customAddrs *AddrMap[string, CustomMappedAddr]
	// customByKey recovers the original base.CustomAddr from its string key.
	customMu    sync.Mutex
	customByKey map[string]base.CustomAddr

	closed atomic.Bool
}

// relayKeyString renders a relay key as a stable map key. base.RelayUrl
// normalizes its string form, so equivalent URLs collapse to one key.
func relayKeyString(url base.RelayUrl, eid base.EndpointId) string {
	return url.String() + "|" + eid.String()
}

// RelayKey identifies a relay path: a relay URL together with the remote
// endpoint reached through it. It is the key type of the relay mapped-address
// table.
type RelayKey struct {
	URL base.RelayUrl
	EID base.EndpointId
}

// NewSocket returns a ready Socket with empty mapped-address tables.
func NewSocket() *Socket {
	return &Socket{
		relayAddrs: NewAddrMap[string, RelayMappedAddr](
			NewRelayMappedAddr,
			func(v RelayMappedAddr) netip.Addr { return v.Addr() },
		),
		relayByKey: make(map[string]RelayKey),
		customAddrs: NewAddrMap[string, CustomMappedAddr](
			NewCustomMappedAddr,
			func(v CustomMappedAddr) netip.Addr { return v.Addr() },
		),
		customByKey: make(map[string]base.CustomAddr),
	}
}

// Close marks the socket closed. Subsequent sends are dropped (blackholed) so
// quic-go's loss recovery handles in-flight datagrams rather than seeing a hard
// error. It is idempotent.
func (s *Socket) Close() { s.closed.Store(true) }

// IsClosed reports whether the socket has been closed.
func (s *Socket) IsClosed() bool { return s.closed.Load() }

// RelayMappedAddrFor returns the relay mapped address for the (url, eid) pair,
// allocating one on first use.
func (s *Socket) RelayMappedAddrFor(url base.RelayUrl, eid base.EndpointId) RelayMappedAddr {
	key := relayKeyString(url, eid)
	s.relayMu.Lock()
	s.relayByKey[key] = RelayKey{URL: url, EID: eid}
	s.relayMu.Unlock()
	return s.relayAddrs.Get(key)
}

// LookupRelay returns the (url, eid) pair for a relay mapped address, if known.
func (s *Socket) LookupRelay(m RelayMappedAddr) (RelayKey, bool) {
	key, ok := s.relayAddrs.Lookup(m.Addr())
	if !ok {
		return RelayKey{}, false
	}
	s.relayMu.Lock()
	rk, ok := s.relayByKey[key]
	s.relayMu.Unlock()
	return rk, ok
}

// CustomMappedAddrFor returns the custom mapped address for c, allocating one on
// first use and recording the reverse mapping back to c.
func (s *Socket) CustomMappedAddrFor(c base.CustomAddr) CustomMappedAddr {
	key := c.String()
	s.customMu.Lock()
	s.customByKey[key] = c
	s.customMu.Unlock()
	return s.customAddrs.Get(key)
}

// PathAddr classifies a QUIC connection's remote net.Addr into the magic
// socket's transport [Addr]: a real IP becomes an IP path; a relay or custom
// mapped ULA is reverse-looked-up through the mapped-address tables. An unknown
// mapped address (or one whose mapping has been forgotten) falls back to an IP
// path so the per-remote actor still tracks a stable address. remoteID is used
// for relay paths, which are keyed by (relay url, endpoint id).
func (s *Socket) PathAddr(remoteID base.EndpointId, ra net.Addr) Addr {
	ap, ok := addrPort(ra)
	if !ok {
		return Addr{}
	}
	switch Classify(ap.Addr()) {
	case KindRelay:
		if rk, ok := s.LookupRelay(RelayMappedAddrFromAddr(ap.Addr())); ok {
			return RelayAddr(rk.URL, rk.EID)
		}
		return IPAddr(ap)
	case KindCustom:
		if c, ok := s.LookupCustom(CustomMappedAddr{a: ap.Addr()}); ok {
			return CustomAddr(c)
		}
		return IPAddr(ap)
	default:
		return IPAddr(ap)
	}
}

// LookupCustom returns the custom address for a custom mapped address, if known.
func (s *Socket) LookupCustom(m CustomMappedAddr) (base.CustomAddr, bool) {
	key, ok := s.customAddrs.Lookup(m.Addr())
	if !ok {
		return base.CustomAddr{}, false
	}
	s.customMu.Lock()
	c, ok := s.customByKey[key]
	s.customMu.Unlock()
	return c, ok
}
