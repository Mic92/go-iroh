package iroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestEndpointDirectEcho is the slice-B gate: two endpoints connect over a
// direct loopback UDP address, exchange a bidi-stream echo and a datagram, and
// each observes the other's verified endpoint id.
func TestEndpointDirectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-echo/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	type srvResult struct {
		peer key.EndpointID
		mp   bool
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		// Echo one bidi stream.
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
		// Echo one datagram.
		dg, err := conn.ReadDatagram(ctx)
		if err == nil {
			conn.SendDatagram(dg)
		}
		done <- srvResult{peer: conn.RemoteID(), mp: conn.MultipathNegotiated()}
	}()

	// The server advertises its bound loopback address.
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.RemoteID().Equal(server.ID()) {
		t.Errorf("client saw server id %s, want %s", conn.RemoteID(), server.ID())
	}
	if conn.ALPN() != alpn {
		t.Errorf("client ALPN = %q, want %q", conn.ALPN(), alpn)
	}
	if !conn.MultipathNegotiated() {
		t.Error("client did not negotiate multipath")
	}
	if err := client.remotes.Actor(server.ID()).TriggerHolepunch(); err != nil &&
		!errors.Is(err, socket.ErrExtensionNotNegotiated) &&
		!errors.Is(err, quic.ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("TriggerHolepunch: %v", err)
	}

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello iroh"
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("stream echo = %q, want %q", got, msg)
	}

	// Datagram echo.
	const dmsg = "dgram"
	if err := conn.SendDatagram([]byte(dmsg)); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	dg, err := conn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if string(dg) != dmsg {
		t.Errorf("datagram echo = %q, want %q", dg, dmsg)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !res.peer.Equal(client.ID()) {
		t.Errorf("server saw client id %s, want %s", res.peer, client.ID())
	}
	if !res.mp {
		t.Error("server did not negotiate multipath")
	}
	if client.transport.ConnectionIDLength != 8 {
		t.Errorf("client transport ConnectionIDLength = %d, want 8", client.transport.ConnectionIDLength)
	}
	if server.transport.ConnectionIDLength != 8 {
		t.Errorf("server transport ConnectionIDLength = %d, want 8", server.transport.ConnectionIDLength)
	}
}

func TestEndpointDialNetConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-dial/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	done := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseWithError(0, "")
		c, err := conn.AcceptStreamConn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_, err = io.Copy(c, c)
		done <- err
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	c, err := client.Dial(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	var _ net.Conn = c
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", string(buf[:]))
	}
	c.Close()
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestEndpointAcceptIncoming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-accept-incoming/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	done := make(chan error, 1)
	go func() {
		in, err := server.AcceptIncoming(ctx)
		if err != nil {
			done <- err
			return
		}
		if _, ok := in.RemoteAddr().(*net.UDPAddr); !ok {
			done <- errors.New("incoming remote address is not UDP")
			return
		}
		if in.RemoteAddrValidated() {
			done <- errors.New("first incoming connection remote address unexpectedly validated")
			return
		}
		accepting, err := in.Accept()
		if err != nil {
			done <- err
			return
		}
		if got, err := accepting.ALPN(ctx); err != nil || got != alpn {
			done <- fmt.Errorf("accepting ALPN = %q, %v", got, err)
			return
		}
		conn, err := accepting.Connection(ctx)
		if err != nil {
			done <- err
			return
		}
		if conn.StableID() == 0 {
			done <- errors.New("connection StableID = 0")
			return
		}
		if !conn.RemoteID().Equal(client.ID()) {
			done <- fmt.Errorf("remote id = %s, want %s", conn.RemoteID(), client.ID())
			return
		}
		done <- nil
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointSourceAddressValidationRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-retry/0"

	srvKey, _ := key.GenerateSecretKey()
	var retryCalls atomic.Int32
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithSourceAddressValidation(func(net.Addr) bool {
			retryCalls.Add(1)
			return true
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	done := make(chan error, 1)
	go func() {
		in, err := server.AcceptIncoming(ctx)
		if err != nil {
			done <- err
			return
		}
		if !in.RemoteAddrValidated() {
			done <- errors.New("incoming remote address was not validated by retry")
			return
		}
		accepting, err := in.Accept()
		if err != nil {
			done <- err
			return
		}
		conn, err := accepting.Connection(ctx)
		if err != nil {
			done <- err
			return
		}
		_ = conn.CloseWithError(0, "")
		done <- nil
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if retryCalls.Load() == 0 {
		t.Fatal("source-address validation callback was not called")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointBinaryALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alpn := string([]byte{'i', 'r', 'o', 'h', '/', 0xff, 0x00, '/', '1'})

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	type srvResult struct {
		alpn string
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		done <- srvResult{alpn: conn.ALPN()}
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if conn.ALPN() != alpn {
		t.Errorf("client ALPN = % x, want % x", []byte(conn.ALPN()), []byte(alpn))
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if res.alpn != alpn {
		t.Errorf("server ALPN = % x, want % x", []byte(res.alpn), []byte(alpn))
	}
}

// TestEndpointSelfConnect checks dialing one's own id is rejected.
func TestEndpointSelfConnect(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithALPNs("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)
	_, err = ep.Connect(ctx, ep.Addr(), "x")
	if err != ErrSelfConnect {
		t.Errorf("Connect(self) err = %v, want ErrSelfConnect", err)
	}
}

// TestEndpointNoAddress checks dialing an addr with no direct IP fails clearly
// (relay dialing is not yet implemented).
func TestEndpointNoAddress(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)
	other, _ := key.GenerateSecretKey()
	_, err = ep.Connect(ctx, netaddr.NewEndpointAddr(other.Public()), "x")
	if err != ErrNoAddress {
		t.Errorf("Connect(no addr) err = %v, want ErrNoAddress", err)
	}
}
