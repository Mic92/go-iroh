//go:build !darwin

package iroh

import "net"

func platformTransportInterfaceClass(name string) (TransportLinkClass, bool) {
	return "", false
}

func platformUsableTransportInterfaceAddr(name string, addr net.Addr) bool {
	return true
}
