package iroh

import (
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TransportAddrUsage reports whether a remote transport address is active.
type TransportAddrUsage int

const (
	// TransportAddrInactive means the address is known but not currently used.
	TransportAddrInactive TransportAddrUsage = iota
	// TransportAddrActive means the address is currently used.
	TransportAddrActive
)

// TransportAddrInfo is a remote transport address plus usage metadata.
type TransportAddrInfo struct {
	Addr  netaddr.TransportAddr
	Usage TransportAddrUsage
}

// RemoteInfo is a snapshot of known addressing information for a remote
// endpoint.
type RemoteInfo struct {
	ID    key.EndpointID
	Addrs []TransportAddrInfo
}

func remoteInfoFromSocket(info socket.RemoteInfo) RemoteInfo {
	addrs := make([]TransportAddrInfo, 0, len(info.Addrs))
	for _, a := range info.Addrs {
		addrs = append(addrs, TransportAddrInfo{
			Addr:  a.Addr,
			Usage: transportAddrUsageFromSocket(a.Usage),
		})
	}
	return RemoteInfo{ID: info.ID, Addrs: addrs}
}

func transportAddrUsageFromSocket(usage socket.TransportAddrUsage) TransportAddrUsage {
	if usage == socket.TransportAddrActive {
		return TransportAddrActive
	}
	return TransportAddrInactive
}
