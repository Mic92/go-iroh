package quic_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// TestQUICRawPublicKeyHandshake proves that the forked quic-go (internal/qng)
// drives the RFC 7250 raw-public-key TLS build (internal/itls/tls): a real QUIC
// connection completes over UDP with both peers presenting bare ed25519 SPKI
// certificates, and each side observes the other's public key through
// ConnectionState().TLS.PeerCertificates. This is the seam the iroh Endpoint
// builds on for wire-compatible P2P.
func TestQUICRawPublicKeyHandshake(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	serverCert, err := tls.MarshalRawPublicKeyCertificate(serverPub, serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := tls.MarshalRawPublicKeyCertificate(clientPub, clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	const alpn = "iroh"

	gotClientKey := make(chan ed25519.PublicKey, 1)
	serverTLS := &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		RawPublicKeys:          true,
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpn},
		ClientAuth:             tls.RequireAnyClientCert,
		InsecureSkipVerify:     true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("server: expected one peer certificate")
			}
			pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("server: peer key not ed25519")
			}
			gotClientKey <- pk
			return nil
		},
	}

	gotServerKey := make(chan ed25519.PublicKey, 1)
	clientTLS := &tls.Config{
		Certificates:           []tls.Certificate{clientCert},
		RawPublicKeys:          true,
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpn},
		ServerName:             "peer.iroh.invalid",
		InsecureSkipVerify:     true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("client: expected one peer certificate")
			}
			pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("client: peer key not ed25519")
			}
			gotServerKey <- pk
			return nil
		},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	ln, err := quic.Listen(udpConn, serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const ping, pong = "ping", "pong"

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		buf, err := io.ReadAll(str)
		if err != nil {
			serverDone <- err
			return
		}
		if string(buf) != ping {
			serverDone <- errors.New("server: bad ping payload")
			return
		}
		if _, err := str.Write([]byte(pong)); err != nil {
			serverDone <- err
			return
		}
		str.Close()
		serverDone <- nil
	}()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	conn, err := quic.Dial(ctx, clientConn, ln.Addr(), clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := str.Write([]byte(ping)); err != nil {
		t.Fatal(err)
	}
	// Signal end-of-request so the server's io.ReadAll completes; the server
	// then replies and closes its send side, which we read to EOF.
	str.Close()
	buf, err := io.ReadAll(str)
	if err != nil {
		select {
		case serr := <-serverDone:
			t.Fatalf("read pong: %v (server side: %v)", err, serr)
		default:
			t.Fatalf("read pong: %v", err)
		}
	}
	if string(buf) != pong {
		t.Fatalf("bad pong: %q", buf)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}

	// Each side must have observed the other's true ed25519 public key.
	select {
	case k := <-gotServerKey:
		if !k.Equal(serverPub) {
			t.Errorf("client saw wrong server key")
		}
	default:
		t.Error("client never verified server key")
	}
	select {
	case k := <-gotClientKey:
		if !k.Equal(clientPub) {
			t.Errorf("server saw wrong client key")
		}
	default:
		t.Error("server never verified client key")
	}
}
