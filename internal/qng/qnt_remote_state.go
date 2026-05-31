package quic

import (
	"net/netip"

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
	addrs := make([]netip.AddrPort, 0, len(s.addrs))
	for _, addr := range s.addrs {
		addrs = append(addrs, addr)
	}
	return addrs
}

func canonicalAddrPort(addr netip.Addr, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(addr.Unmap(), port)
}
