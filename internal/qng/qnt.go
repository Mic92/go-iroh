package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/tmc/go-iroh/internal/qng/internal/wire"
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

// ErrNATTraversalTooManyAddresses is returned when a QNT address set is full.
var ErrNATTraversalTooManyAddresses = errors.New("quic: too many nat traversal addresses")

// NATTraversalCandidate is a local address the application believes is worth
// advertising to the peer for n0 QUIC NAT traversal. qng owns address-family
// canonicalization before any address is put on the wire.
type NATTraversalCandidate struct {
	Addr netip.AddrPort
}

type qntLocalState struct {
	mu                    sync.Mutex
	remoteOnce            sync.Once
	local                 []qntLocalAddress
	nextLocalAddressSeqNo uint64
	remote                *qntRemoteAddressState
	round                 uint64
	pendingReachOut       []*wire.ReachOutFrame
	pendingProbes         []netip.AddrPort
	sentProbes            map[uint64]netip.AddrPort
}

type qntLocalAddress struct {
	addr netip.AddrPort
	seq  uint64
}

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
	if slices.ContainsFunc(st.local, func(a qntLocalAddress) bool {
		return a.addr == addr
	}) {
		return nil
	}
	if len(st.local) >= c.qntLocalAddressLimit() {
		return ErrNATTraversalTooManyAddresses
	}
	seq := st.nextLocalAddressSeqNo
	st.nextLocalAddressSeqNo++
	st.local = append(st.local, qntLocalAddress{addr: addr, seq: seq})
	c.queueLocalAddAddressFrame(seq, addr)
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
	i := slices.IndexFunc(st.local, func(a qntLocalAddress) bool {
		return a.addr == addr
	})
	if i < 0 {
		st.mu.Unlock()
		return nil
	}
	seq := st.local[i].seq
	st.local = slices.Delete(st.local, i, i+1)
	st.mu.Unlock()
	c.queueLocalRemoveAddressFrame(seq)
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
	remote := st.remote.addresses()
	if len(st.local) == 0 || len(remote) == 0 {
		return nil, ErrNATTraversalNotEnoughAddresses
	}
	st.round++
	st.pendingReachOut = st.pendingReachOut[:0]
	st.pendingProbes = append(st.pendingProbes[:0], remote...)
	clear(st.sentProbes)
	for _, local := range st.local {
		st.pendingReachOut = append(st.pendingReachOut, &wire.ReachOutFrame{
			Round: st.round,
			Addr:  local.addr.Addr(),
			Port:  local.addr.Port(),
		})
	}
	return remote, nil
}

// NATTraversalAddresses returns the remote ADD_ADDRESS set known to qng.
func (c *Conn) NATTraversalAddresses() ([]netip.AddrPort, error) {
	if !c.qntAPINegotiated() {
		return nil, ErrNATTraversalNotNegotiated
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.remote.addresses(), nil
}

func (c *Conn) qntLocalState() *qntLocalState {
	c.qnt.remoteOnce.Do(func() {
		c.qnt.remote = newQNTRemoteAddressState(c.qntRemoteAddressLimit())
	})
	return &c.qnt
}

func (c *Conn) qntLocalNATTraversalAddresses() []netip.AddrPort {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	addrs := make([]netip.AddrPort, 0, len(st.local))
	for _, a := range st.local {
		addrs = append(addrs, a.addr)
	}
	return addrs
}

func (c *Conn) qntPendingReachOutFrames() []*wire.ReachOutFrame {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return cloneReachOutFrames(st.pendingReachOut)
}

func (c *Conn) qntPendingProbeAddresses() []netip.AddrPort {
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	return slices.Clone(st.pendingProbes)
}

func (c *Conn) queueLocalAddAddressFrame(seq uint64, addr netip.AddrPort) {
	if c.framer == nil {
		return
	}
	c.queueControlFrame(&wire.AddAddressFrame{
		SeqNo: seq,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
}

func (c *Conn) queueLocalRemoveAddressFrame(seq uint64) {
	if c.framer == nil {
		return
	}
	c.queueControlFrame(&wire.RemoveAddressFrame{SeqNo: seq})
}

func cloneReachOutFrames(frames []*wire.ReachOutFrame) []*wire.ReachOutFrame {
	clones := make([]*wire.ReachOutFrame, len(frames))
	for i, frame := range frames {
		if frame == nil {
			continue
		}
		clone := *frame
		clones[i] = &clone
	}
	return clones
}

func (c *Conn) addRemoteNATTraversalAddress(addr netip.AddrPort) error {
	addr = canonicalNATTraversalAddr(addr)
	if !addr.IsValid() {
		return nil
	}
	return c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 0,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
}

func (c *Conn) handleAddAddressFrame(frame *wire.AddAddressFrame) error {
	return c.addRemoteNATTraversalAddressFrame(frame)
}

func (c *Conn) handleReachOutFrame(frame *wire.ReachOutFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	return ErrNATTraversalRoundNotImplemented
}

func (c *Conn) handleRemoveAddressFrame(frame *wire.RemoveAddressFrame) error {
	return c.removeRemoteNATTraversalAddressFrame(frame)
}

func (c *Conn) addRemoteNATTraversalAddressFrame(frame *wire.AddAddressFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	_, _, err := st.remote.add(frame)
	return err
}

func (c *Conn) removeRemoteNATTraversalAddressFrame(frame *wire.RemoveAddressFrame) error {
	if !c.qntAPINegotiated() {
		return ErrNATTraversalNotNegotiated
	}
	if frame == nil {
		return nil
	}
	st := c.qntLocalState()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.remote.remove(frame)
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

func (c *Conn) qntRemoteAddressLimit() uint8 {
	if c == nil || c.config == nil {
		return 0
	}
	if p := maxRemoteNATTraversalAddressesParam(c.config.MaxRemoteNATTraversalAddresses); p != nil {
		return *p
	}
	return 0
}

func (c *Conn) qntLocalAddressLimit() int {
	if c == nil || c.peerParams == nil || c.peerParams.MaxRemoteNATTraversalAddresses == nil {
		return 0
	}
	return int(*c.peerParams.MaxRemoteNATTraversalAddresses)
}
