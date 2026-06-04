package iroh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/key"
)

// TestIrohTLSOverQUIC proves the iroh TLS configs work over the qng QUIC stack:
// a dialer that targets the server's endpoint id (via SNI) completes the RFC
// 7250 handshake, the server-identity check passes, and each side learns the
// other's true endpoint id. This is the connect/accept core the Endpoint builds
// on, minus the connectivity (address resolution / relay / hole-punching).
func TestIrohTLSOverQUIC(t *testing.T) {
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	const alpn = "iroh-test/0"

	serverTLS, err := serverTLSConfig(serverKey, []string{alpn})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, serverKey.Public().EndpointID(), []string{alpn}, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	ln, err := quic.Listen(serverUDP, serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		peer key.EndpointID
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		peer, err := peerEndpointID(conn.ConnectionState().TLS)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		if _, err := io.ReadAll(str); err != nil {
			serverDone <- result{err: err}
			return
		}
		str.Write([]byte("ok"))
		str.Close()
		serverDone <- result{peer: peer}
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	conn, err := quic.Dial(ctx, clientUDP, ln.Addr(), clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// Client must observe the server's endpoint id.
	serverPeer, err := peerEndpointID(conn.ConnectionState().TLS)
	if err != nil {
		t.Fatalf("client peer id: %v", err)
	}
	if !serverPeer.Equal(serverKey.Public().EndpointID()) {
		t.Errorf("client saw server id %s, want %s", serverPeer, serverKey.Public().EndpointID())
	}

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	str.Write([]byte("hi"))
	str.Close()
	if _, err := io.ReadAll(str); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !res.peer.Equal(clientKey.Public().EndpointID()) {
		t.Errorf("server saw client id %s, want %s", res.peer, clientKey.Public().EndpointID())
	}
}

func TestIrohTLSOverQUICSelectsServerPreferredBinaryALPN(t *testing.T) {
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	primary := []byte("iroh-primary/0")
	additional := []byte{'i', 'r', 'o', 'h', '/', 0xff, 0x00, '/', '1'}

	serverTLS, err := serverTLSConfig(serverKey, []string{string(additional), string(primary)})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, serverKey.Public().EndpointID(), []string{string(primary), string(additional)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	ln, err := quic.Listen(serverUDP, serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		alpn []byte
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		if _, err := io.ReadAll(str); err != nil {
			serverDone <- result{err: err}
			return
		}
		if _, err := str.Write([]byte("ok")); err != nil {
			serverDone <- result{err: err}
			return
		}
		if err := str.Close(); err != nil {
			serverDone <- result{err: err}
			return
		}
		alpn := []byte(conn.ConnectionState().TLS.NegotiatedProtocol)
		serverDone <- result{alpn: alpn}
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	conn, err := quic.Dial(ctx, clientUDP, ln.Addr(), clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	got := []byte(conn.ConnectionState().TLS.NegotiatedProtocol)
	if !bytes.Equal(got, additional) {
		t.Errorf("client ALPN = % x, want % x", got, additional)
	}
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(str); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !bytes.Equal(res.alpn, additional) {
		t.Errorf("server ALPN = % x, want % x", res.alpn, additional)
	}
}

// TestIrohTLSRejectsWrongServer ensures the SNI-derived server-identity check
// fails the handshake when the dialer targets an id the server does not hold.
func TestIrohTLSRejectsWrongServer(t *testing.T) {
	serverKey, _ := key.GenerateSecretKey()
	clientKey, _ := key.GenerateSecretKey()
	wrong, _ := key.GenerateSecretKey() // an id the server does NOT have

	const alpn = "iroh-test/0"
	serverTLS, _ := serverTLSConfig(serverKey, []string{alpn})
	clientTLS, _ := clientTLSConfig(clientKey, wrong.Public().EndpointID(), []string{alpn}, nil)

	serverUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	defer serverUDP.Close()
	ln, err := quic.Listen(serverUDP, serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go ln.Accept(ctx) //nolint: the accept may error when the client rejects

	clientUDP, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	defer clientUDP.Close()

	_, err = quic.Dial(ctx, clientUDP, ln.Addr(), clientTLS, &quic.Config{})
	if err == nil {
		t.Fatal("expected dial to fail: server presented an id the client did not target")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected an identity-mismatch rejection, got timeout: %v", err)
	}
}
