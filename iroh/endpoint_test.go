package iroh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
)

// TestEndpointDirectEcho is the slice-B gate: two endpoints connect over a
// direct loopback UDP address, exchange a bidi-stream echo and a datagram, and
// each observes the other's verified endpoint id.
func TestEndpointDirectEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-echo/0"

	srvKey, _ := base.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
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
		peer base.EndpointId
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
	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	conn, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.RemoteID().Equal(server.ID()) {
		t.Errorf("client saw server id %s, want %s", conn.RemoteID(), server.ID())
	}
	if string(conn.ALPN()) != alpn {
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

	s, err := conn.OpenStream(ctx)
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

func TestEndpointAcceptIncoming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-accept-incoming/0"

	srvKey, _ := base.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
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
		if _, ok := in.RemoteAddr().AddrPort(); !ok {
			done <- errors.New("incoming remote address is not UDP")
			return
		}
		accepting, err := in.Accept()
		if err != nil {
			done <- err
			return
		}
		if got, err := accepting.ALPN(ctx); err != nil || string(got) != alpn {
			done <- fmt.Errorf("accepting ALPN = %q, %v", got, err)
			return
		}
		conn, err := accepting.Connection(ctx)
		if err != nil {
			done <- err
			return
		}
		if !conn.RemoteID().Equal(client.ID()) {
			done <- fmt.Errorf("remote id = %s, want %s", conn.RemoteID(), client.ID())
			return
		}
		done <- nil
	}()

	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestEndpointBinaryALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	alpn := []byte{'i', 'r', 'o', 'h', '/', 0xff, 0x00, '/', '1'}

	srvKey, _ := base.GenerateSecretKey()
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
		alpn []byte
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		done <- srvResult{alpn: append([]byte(nil), conn.ALPN()...)}
	}()

	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !bytes.Equal(conn.ALPN(), alpn) {
		t.Errorf("client ALPN = % x, want % x", conn.ALPN(), alpn)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !bytes.Equal(res.alpn, alpn) {
		t.Errorf("server ALPN = % x, want % x", res.alpn, alpn)
	}
}

// TestEndpointSelfConnect checks dialing one's own id is rejected.
func TestEndpointSelfConnect(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithALPNs([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)
	_, err = ep.Connect(ctx, ep.Addr(), []byte("x"))
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
	other, _ := base.GenerateSecretKey()
	_, err = ep.Connect(ctx, base.NewEndpointAddr(other.Public()), []byte("x"))
	if err != ErrNoAddress {
		t.Errorf("Connect(no addr) err = %v, want ErrNoAddress", err)
	}
}
