package key

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPublicKeyFromStringHex(t *testing.T) {
	// A known-valid key from the Rust iroh-base test suite.
	const s = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
	k, err := ParsePublicKey(s)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if got := k.String(); got != s {
		t.Errorf("String() = %q, want %q", got, s)
	}
	want, _ := hex.DecodeString(s)
	b := k.Bytes()
	if !bytes.Equal(b[:], want) {
		t.Errorf("Bytes() = %x, want %x", b, want)
	}
}

func TestPublicKeyAllZeroIsValid(t *testing.T) {
	// The all-zero point is a valid (small-order) Ed25519 point and iroh
	// accepts it; from_bytes(&[0;32]) succeeds in the Rust impl.
	var zero [PublicKeyLength]byte
	if _, err := NewPublicKey(zero); err != nil {
		t.Fatalf("NewPublicKey(zero): %v", err)
	}
}

func TestParseEndpointIdRejectsGarbage(t *testing.T) {
	// Regression: "foobarbaz" must not panic and must error.
	if _, err := ParsePublicKey("foobarbaz"); err == nil {
		t.Fatal("expected error parsing garbage")
	}
}

func TestPublicKeyInvalidCurvePoint(t *testing.T) {
	// y = 2 does not lie on the Edwards curve, so it cannot be decompressed to
	// a valid point; this matches ed25519-dalek's VerifyingKey::from_bytes
	// rejecting it.
	var b [PublicKeyLength]byte
	b[0] = 2
	_, err := NewPublicKey(b)
	if !errors.Is(err, ErrInvalidKeyData) {
		t.Fatalf("err = %v, want ErrInvalidKeyData", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.Public()
	msg := []byte("hello world")
	sig := sk.Sign(msg)
	if err := pk.Verify(msg, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if err := pk.Verify([]byte("tampered"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(tampered) = %v, want ErrInvalidSignature", err)
	}
}

func TestSecretKeyStringRoundTrip(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	// hex form
	skBytes := sk.Bytes()
	hexForm := hex.EncodeToString(skBytes[:])
	sk2, err := ParseSecretKey(hexForm)
	if err != nil {
		t.Fatalf("ParseSecretKey(hex): %v", err)
	}
	if sk2.Bytes() != sk.Bytes() {
		t.Error("hex round-trip mismatch")
	}
	// public key string round-trips
	pk := sk.Public()
	pk2, err := ParsePublicKey(pk.String())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !pk2.Equal(pk) {
		t.Error("public key string round-trip mismatch")
	}
}

func TestPublicKeyJSON(t *testing.T) {
	var zero [PublicKeyLength]byte
	k, _ := NewPublicKey(zero)
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var k2 PublicKey
	if err := json.Unmarshal(data, &k2); err != nil {
		t.Fatal(err)
	}
	if !k2.Equal(k) {
		t.Errorf("JSON round-trip mismatch: %v != %v", k2, k)
	}
}

func TestPublicKeyBinary(t *testing.T) {
	sk, _ := GenerateSecretKey()
	k := sk.Public()
	data, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != PublicKeyLength {
		t.Errorf("MarshalBinary len = %d, want %d", len(data), PublicKeyLength)
	}
	var k2 PublicKey
	if err := k2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if !k2.Equal(k) {
		t.Error("binary round-trip mismatch")
	}
}

func TestZ32RoundTrip(t *testing.T) {
	sk, _ := GenerateSecretKey()
	k := sk.Public()
	z := k.Z32()
	k2, err := PublicKeyFromZ32(z)
	if err != nil {
		t.Fatalf("PublicKeyFromZ32: %v", err)
	}
	if !k2.Equal(k) {
		t.Error("z32 round-trip mismatch")
	}
	// z-base-32 of a 32-byte value is 52 chars.
	if len(z) != 52 {
		t.Errorf("z32 length = %d, want 52", len(z))
	}
}

func TestPublicKeyShort(t *testing.T) {
	const s = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
	k, _ := ParsePublicKey(s)
	if got, want := k.Short(), "ae58ff8833"; got != want {
		t.Errorf("Short() = %q, want %q", got, want)
	}
}

func TestPublicKeyCompareOrders(t *testing.T) {
	// Use valid keys (derived from seeds) and order them by raw bytes.
	k1 := NewSecretKey([SecretKeyLength]byte{0: 1}).Public()
	k2 := NewSecretKey([SecretKeyLength]byte{0: 2}).Public()
	lo, hi := k1, k2
	if lo.Compare(hi) > 0 {
		lo, hi = hi, lo
	}
	if lo.Compare(hi) >= 0 {
		t.Error("expected lo < hi")
	}
	if hi.Compare(lo) <= 0 {
		t.Error("expected hi > lo")
	}
	if lo.Compare(lo) != 0 {
		t.Error("expected lo == lo")
	}
}

func TestParseBase32UpperAndLower(t *testing.T) {
	sk, _ := GenerateSecretKey()
	k := sk.Public()
	// Build base32 form via stdBase32NoPad (uppercase). ParsePublicKey should
	// accept it (and its lowercase variant) since it is not 64 chars.
	b := k.Bytes()
	upper := stdBase32NoPad.EncodeToString(b[:])
	if len(upper) == PublicKeyLength*2 {
		t.Skip("base32 form collides with hex length")
	}
	k2, err := ParsePublicKey(upper)
	if err != nil {
		t.Fatalf("ParsePublicKey(base32 upper): %v", err)
	}
	if !k2.Equal(k) {
		t.Error("base32 upper round-trip mismatch")
	}
	k3, err := ParsePublicKey(strings.ToLower(upper))
	if err != nil {
		t.Fatalf("ParsePublicKey(base32 lower): %v", err)
	}
	if !k3.Equal(k) {
		t.Error("base32 lower round-trip mismatch")
	}
}
