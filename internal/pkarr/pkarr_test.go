package pkarr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tmc/go-iroh/base"
	"golang.org/x/net/dns/dnsmessage"
)

func TestSignedPacketRoundTrip(t *testing.T) {
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"relay=https://example.com/", "addr=127.0.0.1:1234", "user-data=foobar"}
	pkt, err := FromTxtStrings(sk, "_iroh", values, 30)
	if err != nil {
		t.Fatalf("FromTxtStrings: %v", err)
	}

	// Parse + verify round-trips.
	pkt2, err := FromBytes(pkt.Bytes())
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	if !pkt2.PublicKey().Equal(sk.Public()) {
		t.Error("public key mismatch")
	}
	if pkt2.Timestamp() != pkt.Timestamp() {
		t.Error("timestamp mismatch")
	}

	// TXT records under _iroh come back, in insertion order.
	got := pkt2.TxtRecords("_iroh")
	if len(got) != len(values) {
		t.Fatalf("TxtRecords len = %d, want %d: %v", len(got), len(values), got)
	}
	for i := range values {
		if got[i] != values[i] {
			t.Errorf("TxtRecords[%d] = %q, want %q", i, got[i], values[i])
		}
	}
}

func TestSignedPacketWireLayout(t *testing.T) {
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	const value = "relay=https://example.com/"
	pkt, err := FromTxtStrings(sk, "_iroh", []string{value}, 30)
	if err != nil {
		t.Fatalf("FromTxtStrings: %v", err)
	}
	b := pkt.Bytes()
	if MaxBytes != 1104 {
		t.Fatalf("MaxBytes = %d, want 1104", MaxBytes)
	}
	if len(b) != headerSize+len(pkt.EncodedPacket()) {
		t.Fatalf("wire len = %d, want header %d + dns %d", len(b), headerSize, len(pkt.EncodedPacket()))
	}
	pub := sk.Public().Bytes()
	if !bytes.Equal(b[:32], pub[:]) {
		t.Fatal("public key is not the first 32 wire bytes")
	}
	sig := pkt.Signature().Bytes()
	if !bytes.Equal(sig[:], b[32:96]) {
		t.Fatal("signature is not stored at wire bytes 32:96")
	}
	if got := binary.BigEndian.Uint64(b[96:104]); got != pkt.Timestamp().Micros() {
		t.Fatalf("timestamp bytes = %d, want %d", got, pkt.Timestamp().Micros())
	}
	if !bytes.Equal(pkt.RelayPayload(), b[32:]) {
		t.Fatal("relay payload is not wire bytes after the public key")
	}

	var p dnsmessage.Parser
	if _, err := p.Start(pkt.EncodedPacket()); err != nil {
		t.Fatalf("parse DNS header: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	h, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("answer header: %v", err)
	}
	if h.Type != dnsmessage.TypeTXT {
		t.Fatalf("answer type = %v, want TXT", h.Type)
	}
	if h.TTL != 30 {
		t.Fatalf("answer TTL = %d, want 30", h.TTL)
	}
	if got, want := h.Name.String(), "_iroh."+sk.Public().Z32()+"."; got != want {
		t.Fatalf("answer name = %q, want %q", got, want)
	}
	txt, err := p.TXTResource()
	if err != nil {
		t.Fatalf("TXT resource: %v", err)
	}
	if got := joinTxt(txt.TXT); got != value {
		t.Fatalf("TXT value = %q, want %q", got, value)
	}
}

func TestSignedPacketVerifyRejectsTamper(t *testing.T) {
	sk, _ := base.GenerateSecretKey()
	pkt, err := FromTxtStrings(sk, "_iroh", []string{"addr=127.0.0.1:1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	b := pkt.Bytes()
	tampered := make([]byte, len(b))
	copy(tampered, b)
	tampered[len(tampered)-1] ^= 0xff // flip a byte in the DNS packet
	if _, err := FromBytes(tampered); !errors.Is(err, ErrSignature) && !errors.Is(err, ErrDNS) {
		t.Fatalf("expected signature or DNS error, got %v", err)
	}
}

func TestSignedPacketTooShort(t *testing.T) {
	if _, err := FromBytes(make([]byte, 10)); !errors.Is(err, ErrTooShort) {
		t.Fatalf("expected ErrTooShort, got %v", err)
	}
}

func TestRelayPayloadRoundTrip(t *testing.T) {
	sk, _ := base.GenerateSecretKey()
	pkt, err := FromTxtStrings(sk, "_iroh", []string{"addr=127.0.0.1:1"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	payload := pkt.RelayPayload()
	pkt2, err := FromRelayPayload(sk.Public(), payload)
	if err != nil {
		t.Fatalf("FromRelayPayload: %v", err)
	}
	if !pkt2.PublicKey().Equal(sk.Public()) {
		t.Error("public key mismatch after relay payload round-trip")
	}
}

func TestTimestampMonotonic(t *testing.T) {
	prev := Now()
	for range 1000 {
		cur := Now()
		if cur.Micros() <= prev.Micros() {
			t.Fatalf("timestamp not strictly increasing: %d <= %d", cur.Micros(), prev.Micros())
		}
		prev = cur
	}
}

func TestMoreRecentThan(t *testing.T) {
	sk, _ := base.GenerateSecretKey()
	older, _ := FromTxtStrings(sk, "_iroh", []string{"addr=127.0.0.1:1"}, 30)
	newer, _ := FromTxtStrings(sk, "_iroh", []string{"addr=127.0.0.1:2"}, 30)
	if !newer.MoreRecentThan(older) {
		t.Error("expected newer packet to be more recent")
	}
	if older.MoreRecentThan(newer) {
		t.Error("expected older packet not to be more recent")
	}
}

func TestSignablePrefix(t *testing.T) {
	// BEP-0044 format "3:seqi<ts>e1:v<len>:" + v.
	got := string(signable(42, []byte("hi")))
	want := "3:seqi42e1:v2:hi"
	if got != want {
		t.Errorf("signable = %q, want %q", got, want)
	}
}

func TestNormalizeName(t *testing.T) {
	origin := "ybndrfg" // stand-in z32 origin
	cases := []struct{ in, want string }{
		{"_iroh", "_iroh." + origin},
		{"_iroh.", "_iroh." + origin},
		{"@", origin},
		{"", origin},
		{origin, origin},
		{"_iroh." + origin, "_iroh." + origin},
	}
	for _, c := range cases {
		if got := normalizeName(origin, c.in); got != c.want {
			t.Errorf("normalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
