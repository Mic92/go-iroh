package iroh

import (
	"time"

	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// PathCandidate is one path offered to a [PathSelector].
type PathCandidate struct {
	// Addr is the path's transport address.
	Addr netaddr.TransportAddr
	// RTT is the smoothed round-trip time observed on the path.
	RTT time.Duration
}

// PathSelector chooses the preferred path among candidates for a remote
// endpoint. Implementations must not block.
//
// Returning ok=false keeps the current selection unchanged. A nil current means
// no path is currently selected.
type PathSelector interface {
	Select(current netaddr.TransportAddr, candidates []PathCandidate) (selected netaddr.TransportAddr, ok bool)
}

// BiasedRttPathSelector is the default [PathSelector]. It sorts paths by
// (tier, biased RTT): direct IP and custom paths beat relay paths, and within a
// tier the lowest biased RTT wins. IPv6 paths receive a 3ms RTT advantage.
// Switching within a tier requires the candidate's biased RTT to be at least
// 5ms better than the current path.
//
// The zero value is ready to use.
type BiasedRttPathSelector struct{}

var _ PathSelector = BiasedRttPathSelector{}

// Select implements [PathSelector].
func (BiasedRttPathSelector) Select(current netaddr.TransportAddr, candidates []PathCandidate) (netaddr.TransportAddr, bool) {
	scandidates := make([]socket.PathCandidate, 0, len(candidates))
	for _, c := range candidates {
		addr, ok := socketAddrFromTransportAddr(c.Addr)
		if !ok {
			continue
		}
		scandidates = append(scandidates, socket.PathCandidate{Addr: addr, RTT: c.RTT})
	}
	var scurrent *socket.Addr
	if current != nil {
		if addr, ok := socketAddrFromTransportAddr(current); ok {
			scurrent = &addr
		}
	}
	selected, ok := socket.BiasedRttPathSelector{}.Select(scurrent, scandidates)
	if !ok {
		return nil, false
	}
	addr, _ := transportAddrFromSocket(selected)
	if addr == nil {
		return nil, false
	}
	return addr, true
}

type pathSelectorAdapter struct {
	selector PathSelector
}

func (a pathSelectorAdapter) Select(current *socket.Addr, candidates []socket.PathCandidate) (socket.Addr, bool) {
	publicCandidates := make([]PathCandidate, 0, len(candidates))
	socketCandidates := make([]socket.Addr, 0, len(candidates))
	for _, c := range candidates {
		addr, _ := transportAddrFromSocket(c.Addr)
		if addr == nil {
			continue
		}
		publicCandidates = append(publicCandidates, PathCandidate{Addr: addr, RTT: c.RTT})
		socketCandidates = append(socketCandidates, c.Addr)
	}
	var publicCurrent netaddr.TransportAddr
	if current != nil {
		publicCurrent, _ = transportAddrFromSocket(*current)
	}
	selected, ok := a.selector.Select(publicCurrent, publicCandidates)
	if !ok || selected == nil {
		return socket.Addr{}, false
	}
	for i, c := range publicCandidates {
		if c.Addr.Compare(selected) == 0 {
			return socketCandidates[i], true
		}
	}
	return socket.Addr{}, false
}

func socketAddrFromTransportAddr(addr netaddr.TransportAddr) (socket.Addr, bool) {
	switch a := addr.(type) {
	case netaddr.IPAddr:
		return socket.IPAddr(a.Addr), true
	case netaddr.RelayAddr:
		// The endpoint id is irrelevant for public selection policy; endpoint
		// adapters map selections back to the original socket candidates.
		return socket.RelayAddr(a.URL, key.EndpointID{}), true
	case netaddr.CustomAddr:
		return socket.CustomAddr(a), true
	default:
		return socket.Addr{}, false
	}
}
