package iroh

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// TestIrohTLSOverQUIC proves the iroh TLS configs work over the qng QUIC stack:
// a dialer that targets the server's endpoint id (via SNI) completes the RFC
// 7250 handshake, the server-identity check passes, and each side learns the
// other's true endpoint id. This is the connect/accept core the Endpoint builds
// on, minus the connectivity (address resolution / relay / hole-punching).
func TestIrohTLSOverQUIC(t *testing.T) {
	serverKey, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}

	const alpn = "iroh-test/0"

	serverTLS, err := serverTLSConfig(serverKey, []string{alpn})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, serverKey.Public(), []string{alpn}, nil)
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
		peer base.EndpointId
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		peer, err := peerEndpointId(conn.ConnectionState().TLS)
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
	serverPeer, err := peerEndpointId(conn.ConnectionState().TLS)
	if err != nil {
		t.Fatalf("client peer id: %v", err)
	}
	if !serverPeer.Equal(serverKey.Public()) {
		t.Errorf("client saw server id %s, want %s", serverPeer, serverKey.Public())
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
	if !res.peer.Equal(clientKey.Public()) {
		t.Errorf("server saw client id %s, want %s", res.peer, clientKey.Public())
	}
}

// TestIrohTLSRejectsWrongServer ensures the SNI-derived server-identity check
// fails the handshake when the dialer targets an id the server does not hold.
func TestIrohTLSRejectsWrongServer(t *testing.T) {
	serverKey, _ := base.GenerateSecretKey()
	clientKey, _ := base.GenerateSecretKey()
	wrong, _ := base.GenerateSecretKey() // an id the server does NOT have

	const alpn = "iroh-test/0"
	serverTLS, _ := serverTLSConfig(serverKey, []string{alpn})
	clientTLS, _ := clientTLSConfig(clientKey, wrong.Public(), []string{alpn}, nil)

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
