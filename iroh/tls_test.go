package iroh

import (
	"testing"

	"github.com/tmc/go-iroh/base"
)

// TestServerNameSnapshot pins the SNI encoding to iroh's golden vector
// (iroh/src/tls/name.rs test_snapshot): the all-zero secret key's endpoint id
// must encode to this exact name, or a go-iroh dialer would address Rust peers
// with the wrong SNI and fail RFC 7250 server verification.
func TestServerNameSnapshot(t *testing.T) {
	sk := base.NewSecretKey([32]byte{})
	got := ServerName(sk.Public())
	const want = "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid"
	if got != want {
		t.Errorf("ServerName(zero) = %q, want %q", got, want)
	}
}

// TestServerNameRoundTrip checks ServerName and endpointIdFromServerName are
// inverses for arbitrary keys.
func TestServerNameRoundTrip(t *testing.T) {
	for i := 0; i < 16; i++ {
		var seed [32]byte
		seed[0] = byte(i)
		seed[31] = byte(i * 7)
		id := base.NewSecretKey(seed).Public()
		name := ServerName(id)
		got, ok := endpointIdFromServerName(name)
		if !ok {
			t.Fatalf("endpointIdFromServerName(%q) failed", name)
		}
		if !got.Equal(id) {
			t.Errorf("round-trip mismatch for seed %d: got %s want %s", i, got, id)
		}
	}
}

func TestEndpointIdFromServerNameRejects(t *testing.T) {
	bad := []string{
		"",
		"example.com",
		"7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.example.com",
		"sub.7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid",
		"zzz.iroh.invalid", // not valid base32hex of a 32-byte key
		".iroh.invalid",
	}
	for _, name := range bad {
		if _, ok := endpointIdFromServerName(name); ok {
			t.Errorf("endpointIdFromServerName(%q) = ok, want rejected", name)
		}
	}
}

// TestRawKeyCertificateMatchesKey checks the certificate's public key is the
// endpoint id of the secret key.
func TestRawKeyCertificateMatchesKey(t *testing.T) {
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := rawKeyCertificate(sk)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) != 1 {
		t.Fatalf("expected 1 cert entry, got %d", len(cert.Certificate))
	}
	// The leaf is the SPKI; its trailing 32 bytes are the raw ed25519 key.
	spki := cert.Certificate[0]
	pub := sk.Public().Bytes()
	if len(spki) < 32 || string(spki[len(spki)-32:]) != string(pub[:]) {
		t.Error("certificate SPKI does not carry the endpoint id public key")
	}
}
