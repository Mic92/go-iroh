package relayproto

import (
	"testing"

	"github.com/tmc/go-iroh/key"
)

func TestClientAuthRoundTrip(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	var challenge ServerChallenge
	for i := range challenge.Challenge {
		challenge.Challenge[i] = byte(i)
	}
	auth := NewClientAuth(sk, challenge)
	encoded := auth.AppendTo(nil)
	parsed, err := ParseHandshakeFrame(encoded)
	if err != nil {
		t.Fatalf("ParseHandshakeFrame: %v", err)
	}
	got, ok := parsed.(*ClientAuth)
	if !ok {
		t.Fatalf("parsed type = %T, want *ClientAuth", parsed)
	}
	if !got.PublicKey.Equal(auth.PublicKey) {
		t.Error("public key mismatch")
	}
	if !got.Signature.Equal(auth.Signature) {
		t.Error("signature mismatch")
	}
	// The signature must verify against the challenge.
	if err := got.Verify(challenge); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestClientAuthVerifyRejectsWrongChallenge(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	c1 := ServerChallenge{Challenge: [16]byte{1, 2, 3}}
	c2 := ServerChallenge{Challenge: [16]byte{4, 5, 6}}
	auth := NewClientAuth(sk, c1)
	if err := auth.Verify(c2); err == nil {
		t.Error("expected verification failure against a different challenge")
	}
}

func TestServerChallengeRoundTrip(t *testing.T) {
	var c ServerChallenge
	for i := range c.Challenge {
		c.Challenge[i] = byte(0xa0 + i)
	}
	encoded := c.AppendTo(nil)
	// frame type 0 (1 varint byte) + 16 challenge bytes.
	if len(encoded) != 1+16 {
		t.Fatalf("encoded len = %d, want 17", len(encoded))
	}
	parsed, err := ParseHandshakeFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.(*ServerChallenge)
	if got.Challenge != c.Challenge {
		t.Error("challenge round-trip mismatch")
	}
}

func TestServerConfirmsAuthRoundTrip(t *testing.T) {
	encoded := ServerConfirmsAuth{}.AppendTo(nil)
	if len(encoded) != 1 { // just the frame type
		t.Fatalf("encoded len = %d, want 1", len(encoded))
	}
	parsed, err := ParseHandshakeFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ServerConfirmsAuth); !ok {
		t.Errorf("parsed type = %T, want *ServerConfirmsAuth", parsed)
	}
}

func TestServerDeniesAuthRoundTrip(t *testing.T) {
	d := ServerDeniesAuth{Reason: "not authorized"}
	encoded := d.AppendTo(nil)
	parsed, err := ParseHandshakeFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := parsed.(*ServerDeniesAuth)
	if got.Reason != d.Reason {
		t.Errorf("reason = %q, want %q", got.Reason, d.Reason)
	}
}

func TestClientAuthPostcardLayout(t *testing.T) {
	// Verify the exact postcard body layout: 32-byte pubkey, then varint(64)=0x40,
	// then 64 signature bytes. Frame type ClientAuth = 1 (one varint byte 0x01).
	sk := key.NewSecretKey([32]byte{1})
	auth := ClientAuth{PublicKey: sk.Public(), Signature: key.NewSignature([64]byte{})}
	encoded := auth.AppendTo(nil)
	wantLen := 1 + 32 + 1 + 64 // frametype + pubkey + varint(64) + sig
	if len(encoded) != wantLen {
		t.Fatalf("encoded len = %d, want %d", len(encoded), wantLen)
	}
	if encoded[0] != 0x01 {
		t.Errorf("frame type byte = %#x, want 0x01", encoded[0])
	}
	if encoded[1+32] != 0x40 {
		t.Errorf("serde_bytes length prefix = %#x, want 0x40 (64)", encoded[1+32])
	}
}
