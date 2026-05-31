package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
)

// ErrNATTraversalNotNegotiated is returned by n0 QUIC NAT traversal operations
// when the n0_nat_traversal extension has not been negotiated. The current qng
// build has inert QNT wire codecs only; the operational state machine is not
// implemented yet, so these APIs fail closed.
var ErrNATTraversalNotNegotiated = errors.New("quic: n0 nat traversal not negotiated")

// ErrNATTraversalNotEnoughAddresses is returned when QNT is negotiated but a
// traversal round cannot start because either the local candidate set or the
// peer's ADD_ADDRESS set is empty.
var ErrNATTraversalNotEnoughAddresses = errors.New("quic: not enough nat traversal addresses")

// ErrNATTraversalRoundNotImplemented is returned when QNT preconditions are met
// but the probe-sending state machine is still absent.
var ErrNATTraversalRoundNotImplemented = errors.New("quic: nat traversal round not implemented")

// NATTraversalCandidate is a local address the application believes is worth
// advertising to the peer for n0 QUIC NAT traversal. qng owns address-family
// canonicalization before any address is put on the wire.
type NATTraversalCandidate struct {
	Addr netip.AddrPort
}

type qntLocalState struct {
	mu     sync.Mutex
	local  []netip.AddrPort
	remote []netip.AddrPort
}

var qntLocalStates sync.Map // map[*Conn]*qntLocalState

// AddNATTraversalAddress adds a local QNT candidate address.
func (c *Conn) AddNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if slices.Contains(st.local, addr) {
		return nil
	}
	st.local = append(st.local, addr)
	return nil
}

// RemoveNATTraversalAddress removes a local QNT candidate address.
func (c *Conn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.local = slices.DeleteFunc(st.local, func(a netip.AddrPort) bool {
		return a == addr
	})
	return nil
}

// InitiateNATTraversalRound starts one client-side QNT round. Once implemented,
// qng queues REACH_OUT frames, owns NAT probe retry scheduling, matches
// PATH_RESPONSE frames, and opens validated four-tuples as multipath paths. The
// returned addresses are informational; qng, not socket, owns probing.
func (c *Conn) InitiateNATTraversalRound(ctx context.Context) ([]netip.AddrPort, error) {
	if !c.qntAPINegotiated() {
		return nil, ErrNATTraversalNotNegotiated
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.local) == 0 || len(st.remote) == 0 {
		return nil, ErrNATTraversalNotEnoughAddresses
	}
	return slices.Clone(st.remote), ErrNATTraversalRoundNotImplemented
}

// NATTraversalAddresses returns the remote ADD_ADDRESS set known to qng.
func (c *Conn) NATTraversalAddresses() ([]netip.AddrPort, error) {
	if !c.qntAPINegotiated() {
		return nil, ErrNATTraversalNotNegotiated
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return slices.Clone(st.remote), nil
}

func (c *Conn) qntLocalState() *qntLocalState {
	st, _ := qntLocalStates.LoadOrStore(c, &qntLocalState{})
	return st.(*qntLocalState)
}

func (c *Conn) qntLocalNATTraversalAddresses() []netip.AddrPort {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return slices.Clone(st.local)
}

func (c *Conn) addRemoteNATTraversalAddress(addr netip.AddrPort) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	if slices.Contains(st.remote, addr) {
		return nil
	}
	st.remote = append(st.remote, addr)
	return nil
}

func canonicalNATTraversalAddr(addr netip.AddrPort) netip.AddrPort {
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func (c *Conn) qntAPINegotiated() bool {
	if c == nil || c.config == nil {
		return false
	}
	return c.qntNegotiated()
}
