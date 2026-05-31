package quic

import (
	"net/netip"
	"slices"

	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

var errQNTTooManyRemoteAddresses = ErrNATTraversalTooManyAddresses

type qntRemoteAddressState struct {
	max   int
	addrs map[uint64]netip.AddrPort
}

func newQNTRemoteAddressState(max uint8) *qntRemoteAddressState {
	return &qntRemoteAddressState{max: int(max), addrs: make(map[uint64]netip.AddrPort)}
}

func (s *qntRemoteAddressState) add(frame *wire.AddAddressFrame) (netip.AddrPort, bool, error) {
	addr := canonicalAddrPort(frame.Addr, frame.Port)
	if !addr.IsValid() || addr.Port() == 0 {
		return netip.AddrPort{}, false, nil
	}
	if old, ok := s.addrs[frame.SeqNo]; ok {
		if old == addr {
			return netip.AddrPort{}, false, nil
		}
		s.addrs[frame.SeqNo] = addr
		return addr, true, nil
	}
	if len(s.addrs) >= s.max {
		return netip.AddrPort{}, false, errQNTTooManyRemoteAddresses
	}
	s.addrs[frame.SeqNo] = addr
	return addr, true, nil
}

func (s *qntRemoteAddressState) remove(frame *wire.RemoveAddressFrame) (netip.AddrPort, bool) {
	addr, ok := s.addrs[frame.SeqNo]
	if !ok {
		return netip.AddrPort{}, false
	}
	delete(s.addrs, frame.SeqNo)
	return addr, true
}

func (s *qntRemoteAddressState) check(frame *wire.AddAddressFrame) bool {
	addr := canonicalAddrPort(frame.Addr, frame.Port)
	old, ok := s.addrs[frame.SeqNo]
	return !ok || old == addr
}

func (s *qntRemoteAddressState) addresses() []netip.AddrPort {
	seqs := make([]uint64, 0, len(s.addrs))
	for seq := range s.addrs {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	addrs := make([]netip.AddrPort, 0, len(s.addrs))
	for _, seq := range seqs {
		addrs = append(addrs, s.addrs[seq])
	}
	return addrs
}

func canonicalAddrPort(addr netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(addr.Unmap(), port)
}
