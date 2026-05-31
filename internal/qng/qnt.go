package quic

import (
	"context"
	"errors"
	"net/netip"
)

// ErrNATTraversalNotNegotiated is returned by n0 QUIC NAT traversal operations
// when the n0_nat_traversal extension has not been negotiated. The current qng
// build has inert QNT wire codecs only; the operational state machine is not
// implemented yet, so these APIs fail closed.
var ErrNATTraversalNotNegotiated = errors.New("quic: n0 nat traversal not negotiated")

// NATTraversalCandidate is a local address the application believes is worth
// advertising to the peer for n0 QUIC NAT traversal. qng owns address-family
// canonicalization before any address is put on the wire.
type NATTraversalCandidate struct {
	Addr netip.AddrPort
}

// AddNATTraversalAddress adds a local QNT candidate address.
func (c *Conn) AddNATTraversalAddress(addr netip.AddrPort) error {
	return ErrNATTraversalNotNegotiated
}

// RemoveNATTraversalAddress removes a local QNT candidate address.
func (c *Conn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	return ErrNATTraversalNotNegotiated
}

// InitiateNATTraversalRound starts one client-side QNT round. Once implemented,
// qng queues REACH_OUT frames, owns NAT probe retry scheduling, matches
// PATH_RESPONSE frames, and opens validated four-tuples as multipath paths. The
// returned addresses are informational; qng, not socket, owns probing.
func (c *Conn) InitiateNATTraversalRound(ctx context.Context) ([]netip.AddrPort, error) {
	return nil, ErrNATTraversalNotNegotiated
}

// NATTraversalAddresses returns the remote ADD_ADDRESS set known to qng.
func (c *Conn) NATTraversalAddresses() ([]netip.AddrPort, error) {
	return nil, ErrNATTraversalNotNegotiated
}
