package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestVendoredHandshake proves the vendored, shimmed crypto/tls completes a real
// TLS 1.3 handshake (exercising the shimmed key schedule and AES-GCM AEAD).
func TestVendoredHandshake(t *testing.T) {
	cert := selfSigned(t)
	serverConf := &Config{Certificates: []Certificate{cert}, MinVersion: VersionTLS13}
	clientConf := &Config{InsecureSkipVerify: true, MinVersion: VersionTLS13}

	ln, err := Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := conn.Read(buf); err != nil {
			done <- err
			return
		}
		_, err = conn.Write([]byte("pong:" + string(buf)))
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := Client(raw, clientConf)
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if conn.ConnectionState().Version != VersionTLS13 {
		t.Fatalf("version = %x, want TLS1.3", conn.ConnectionState().Version)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 32)
	n, err := conn.Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[:n]) != "pong:hello" {
		t.Errorf("got %q, want pong:hello", out[:n])
	}
	conn.Close()
	if err := <-done; err != nil {
		t.Errorf("server: %v", err)
	}
}

func selfSigned(t *testing.T) Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
