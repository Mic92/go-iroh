package tls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"
)

// TestRawPublicKeyMutualHandshake proves a mutual RFC 7250 raw-public-key TLS 1.3
// handshake completes between two endpoints: both present a bare ed25519 SPKI as
// their certificate, and each verifies the other's public key via VerifyConnection.
func TestRawPublicKeyMutualHandshake(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	serverCert, err := MarshalRawPublicKeyCertificate(serverPub, serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := MarshalRawPublicKeyCertificate(clientPub, clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	var gotClientKey ed25519.PublicKey
	serverConf := &Config{
		Certificates:           []Certificate{serverCert},
		RawPublicKeys:          true,
		SessionTicketsDisabled: true,
		MinVersion:             VersionTLS13,
		ClientAuth:             RequireAnyClientCert,
		NextProtos:             []string{"iroh-test"},
		VerifyConnection: func(cs ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("server: expected one peer cert")
			}
			pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("server: peer key not ed25519")
			}
			gotClientKey = pk
			return nil
		},
	}

	var gotServerKey ed25519.PublicKey
	clientConf := &Config{
		Certificates:           []Certificate{clientCert},
		RawPublicKeys:          true,
		SessionTicketsDisabled: true,
		MinVersion:             VersionTLS13,
		ServerName:             "peer.iroh.invalid",
		NextProtos:             []string{"iroh-test"},
		InsecureSkipVerify:     true, // chain verification is replaced by VerifyConnection
		VerifyConnection: func(cs ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("client: expected one peer cert")
			}
			pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("client: peer key not ed25519")
			}
			gotServerKey = pk
			return nil
		},
	}

	ln, err := Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			srvErr <- err
			return
		}
		_, err = conn.Write(append([]byte("ack:"), buf...))
		srvErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := Client(raw, clientConf)
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer conn.Close()

	if conn.ConnectionState().Version != VersionTLS13 {
		t.Fatalf("not TLS 1.3")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 32)
	n, _ := conn.Read(out)
	if string(out[:n]) != "ack:ping" {
		t.Errorf("got %q, want ack:ping", out[:n])
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}

	// Both sides observed the other's real ed25519 public key.
	if !bytes.Equal(gotServerKey, serverPub) {
		t.Error("client did not observe the server's public key")
	}
	if !bytes.Equal(gotClientKey, clientPub) {
		t.Error("server did not observe the client's public key")
	}
}

func TestServerRawPublicKeyNegotiationRequiresMutualRawKeyOffers(t *testing.T) {
	conf := &Config{RawPublicKeys: true}
	hello := &clientHelloMsg{
		clientCertificateTypes: []uint8{certTypeRawPublicKey},
		serverCertificateTypes: []uint8{certTypeRawPublicKey},
	}
	if !serverNegotiatesRawPublicKeys(conf, hello) {
		t.Fatal("server raw public key negotiation rejected mutual raw-key offers")
	}

	hello = &clientHelloMsg{
		serverCertificateTypes: []uint8{certTypeRawPublicKey},
	}
	if serverNegotiatesRawPublicKeys(conf, hello) {
		t.Fatal("server raw public key negotiation accepted a missing client certificate type offer")
	}
	hello = &clientHelloMsg{
		clientCertificateTypes: []uint8{certTypeRawPublicKey},
	}
	if serverNegotiatesRawPublicKeys(conf, hello) {
		t.Fatal("server raw public key negotiation accepted a missing server certificate type offer")
	}
	if serverNegotiatesRawPublicKeys(&Config{}, &clientHelloMsg{serverCertificateTypes: []uint8{certTypeRawPublicKey}}) {
		t.Fatal("server raw public key negotiation ignored config opt-in")
	}
}

func TestEncryptedExtensionsRawPublicKeyCertificateTypes(t *testing.T) {
	msg := &encryptedExtensionsMsg{
		clientCertificateType:    certTypeRawPublicKey,
		clientCertificateTypeSet: true,
		serverCertificateType:    certTypeRawPublicKey,
		serverCertificateTypeSet: true,
	}
	data, err := msg.marshal()
	if err != nil {
		t.Fatal(err)
	}

	var got encryptedExtensionsMsg
	if !got.unmarshal(data) {
		t.Fatal("unmarshal encrypted extensions failed")
	}
	if !got.clientCertificateTypeSet || got.clientCertificateType != certTypeRawPublicKey {
		t.Fatalf("client certificate type = set:%t value:%d, want raw public key", got.clientCertificateTypeSet, got.clientCertificateType)
	}
	if !got.serverCertificateTypeSet || got.serverCertificateType != certTypeRawPublicKey {
		t.Fatalf("server certificate type = set:%t value:%d, want raw public key", got.serverCertificateTypeSet, got.serverCertificateType)
	}
}

// TestRawPublicKeyRejectsWrongKey ensures VerifyConnection can reject a peer.
func TestRawPublicKeyRejectsWrongKey(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverCert, _ := MarshalRawPublicKeyCertificate(serverPub, serverPriv)
	serverConf := &Config{
		Certificates: []Certificate{serverCert}, RawPublicKeys: true,
		SessionTicketsDisabled: true, MinVersion: VersionTLS13,
		ClientAuth:       RequireAnyClientCert,
		VerifyConnection: func(ConnectionState) error { return nil },
	}
	clientConf := &Config{
		RawPublicKeys: true, SessionTicketsDisabled: true, MinVersion: VersionTLS13,
		InsecureSkipVerify: true, ServerName: "peer.iroh.invalid",
		VerifyConnection: func(ConnectionState) error {
			return errors.New("rejected: wrong endpoint id")
		},
	}
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	cc, _ := MarshalRawPublicKeyCertificate(clientPub, clientPriv)
	clientConf.Certificates = []Certificate{cc}

	ln, _ := Listen("tcp", "127.0.0.1:0", serverConf)
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, _ := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	conn := Client(raw, clientConf)
	if err := conn.HandshakeContext(ctx); err == nil {
		t.Fatal("expected handshake rejection from VerifyConnection")
	}
}
