package quic

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
)

// delayedPacketConn wraps a PacketConn and delays delivery of every inbound
// packet. It stretches the client's handshake RTT so the 0-RTT early window
// (DialEarly return until handshake completion) is wide enough to exercise
// concurrent stream opens.
type delayedPacketConn struct {
	net.PacketConn
	delay time.Duration
}

func (c *delayedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		time.Sleep(c.delay)
	}
	return n, addr, err
}

// zerorttTLSConfigs returns a resumption-capable raw-public-key TLS pair:
// tickets enabled on the server, an LRU session cache on the client.
func zerorttTLSConfigs(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
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

	const alpn = "iroh-0rtt-race"
	serverTLS = &tls.Config{
		Certificates:       []tls.Certificate{serverCert},
		RawPublicKeys:      true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
	}
	clientTLS = &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RawPublicKeys:      true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ServerName:         "peer.iroh.invalid",
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	return serverTLS, clientTLS
}

// TestZeroRTTOpenStreamDuringHandshake is a -race regression test for the
// handshake-vs-OpenStream data race: on a resumed 0-RTT connection, DialEarly
// returns as soon as the client derives its 0-RTT keys, and the application
// may open streams immediately. newFlowController then reads the restored
// peer transport parameters on the application goroutine while the run loop
// overwrites them with the server's authoritative parameters when the
// handshake flight arrives. The inbound delay stretches that early window so
// the concurrent accesses reliably overlap.
func TestZeroRTTOpenStreamDuringHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	serverTLS, clientTLS := zerorttTLSConfigs(t)

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	serverTr := &Transport{Conn: serverUDP}
	defer serverTr.Close()
	ln, err := serverTr.ListenEarly(serverTLS, &Config{Allow0RTT: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept every connection and drain every stream so client-side opens
	// never back up.
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go io.Copy(io.Discard, s)
				}
			}()
		}
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	clientTr := &Transport{Conn: &delayedPacketConn{PacketConn: clientUDP, delay: 3 * time.Millisecond}}
	defer clientTr.Close()

	// Prime the session cache with a full handshake.
	prime, err := clientTr.DialEarly(ctx, ln.Addr(), clientTLS, &Config{})
	if err != nil {
		t.Fatalf("priming dial: %v", err)
	}
	s, err := prime.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("priming stream: %v", err)
	}
	s.Write([]byte("prime"))
	s.Close()
	// The NewSessionTicket arrives asynchronously after the handshake.
	for {
		if _, ok := clientTLS.ClientSessionCache.Get(clientTLS.ServerName); ok {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no session ticket cached: %v", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	prime.CloseWithError(0, "")

	// Resume with 0-RTT and open streams for the whole early window.
	for range 5 {
		conn, err := clientTr.DialEarly(ctx, ln.Addr(), clientTLS, &Config{})
		if err != nil {
			t.Fatalf("0-RTT dial: %v", err)
		}
		hs := conn.HandshakeComplete()
		opened := 0
	open:
		for {
			select {
			case <-hs:
				break open
			default:
			}
			s, err := conn.OpenStream()
			if err != nil {
				if errors.Is(err, Err0RTTRejected) {
					t.Fatal("0-RTT rejected by our own server")
				}
				// Stream limit reached: keep spinning until the window closes.
				continue
			}
			s.Write([]byte("early"))
			s.Close()
			opened++
		}
		if !conn.ConnectionState().Used0RTT {
			t.Fatal("connection did not use 0-RTT; early window never existed")
		}
		if opened == 0 {
			t.Log("handshake completed before any stream opened; race window missed this round")
		}
		conn.CloseWithError(0, "")
	}
}
