package dns

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestDoTLookuperLookupTXT(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{testCertificate(t)},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		msg, err := readDNSMessage(conn)
		if err != nil {
			t.Errorf("read query: %v", err)
			return
		}
		name := parseQuestionName(t, msg)
		if name.String() != "_iroh.example." {
			t.Errorf("query name = %q", name.String())
		}
		if err := writeDNSMessage(conn, packTXTResponse(t, name, []string{"addr=127.0.0.1:1234"})); err != nil {
			t.Errorf("write response: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := (&DoTLookuper{
		Address: ln.Addr().String(),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Dialer: &net.Dialer{Timeout: time.Second},
	}).LookupTXT(ctx, "_iroh.example.")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(got) != 1 || got[0] != "addr=127.0.0.1:1234" {
		t.Fatalf("TXT = %q", got)
	}
	<-done
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}
