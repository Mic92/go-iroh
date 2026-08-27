package iroh

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// oneWayProxy forwards datagrams to backend and drops everything coming
// back, so a handshake through it reaches the server but never completes.
func oneWayProxy(t *testing.T, backend netip.AddrPort) netip.AddrPort {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(backend))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close(); back.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			back.Write(buf[:n])
		}
	}()
	return front.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestAcceptNotBlockedByStalledHandshake checks that an incoming attempt that
// never finishes its handshake does not hold up Accept for later connections.
func TestAcceptNotBlockedByStalledHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const alpn = "iroh-stall/0"
	server := bindLocal(t, ctx, WithALPNs(alpn))
	staller := bindLocal(t, ctx)
	client := bindLocal(t, ctx)

	accepted := make(chan *Conn, 2)
	go func() {
		for {
			conn, err := server.Accept(ctx)
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	blackhole := oneWayProxy(t, server.LocalAddr())
	go staller.Connect(ctx, netaddr.NewEndpointAddr(server.ID(), netaddr.IPAddr{Addr: blackhole}), alpn)
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID(), netaddr.IPAddr{Addr: server.LocalAddr()}), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	select {
	case c := <-accepted:
		if !c.RemoteID().Equal(client.ID()) {
			t.Fatalf("accepted %s first, want the healthy client", c.RemoteID())
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("Accept took %v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept blocked behind a stalled handshake")
	}
}
