//go:build !js

package iroh

import (
	"net"
	"net/netip"
)

func bindPacketConn(c config, bind netip.AddrPort) (*net.UDPConn, error) {
	if c.disableIP {
		return nil, nil
	}
	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(bind))
}
