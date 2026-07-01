//go:build js

package iroh

import (
	"net"
	"net/netip"
)

func bindPacketConn(c config, bind netip.AddrPort) (*net.UDPConn, error) {
	return nil, nil
}
