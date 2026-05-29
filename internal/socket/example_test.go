package socket_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/tmc/go-iroh/internal/socket"
)

// ExampleNewMagicConn builds a magic socket over a UDP socket and uses it as a
// net.PacketConn, the way iroh hands it to a quic-go Transport.
func ExampleNewMagicConn() {
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		panic(err)
	}

	sock := socket.NewSocket()
	magic := socket.NewMagicConn(sock, udp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go magic.Serve(ctx)

	var pc net.PacketConn = magic
	defer pc.Close()

	fmt.Println(pc.LocalAddr().Network())
	// Output: udp
}
