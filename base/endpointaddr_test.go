package base

import (
	"errors"
	"net/netip"
	"testing"
)

func TestCustomAddrRoundTrip(t *testing.T) {
	// Mirrors iroh-base/src/endpoint_addr.rs test_custom_addr_roundtrip.
	cases := []struct {
		id   uint64
		data []byte
		want string
	}{
		{1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6}, "1_a1b2c3d4e5f6"},
		{42, bytesRepeat(0xab, 32), "2a_" + hexRepeat("ab", 32)},
		{0, []byte{}, "0_"},
		{0xdeadbeef, []byte{0x01, 0x02}, "deadbeef_0102"},
	}
	for _, c := range cases {
		a := NewCustomAddr(c.id, c.data)
		if got := a.BareString(); got != c.want {
			t.Errorf("BareString() = %q, want %q", got, c.want)
		}
		parsed, err := ParseCustomAddr(c.want)
		if err != nil {
			t.Fatalf("ParseCustomAddr(%q): %v", c.want, err)
		}
		if parsed.Id() != c.id || string(parsed.Data()) != string(c.data) {
			t.Errorf("parsed = (%d,%x), want (%d,%x)", parsed.Id(), parsed.Data(), c.id, c.data)
		}
	}
}

func TestCustomAddrParseErrors(t *testing.T) {
	// Mirrors test_custom_addr_parse_errors.
	for _, s := range []string{"abc123", "xyz_0102", "1_ghij", "1_abc"} {
		if _, err := ParseCustomAddr(s); err == nil {
			t.Errorf("ParseCustomAddr(%q): expected error", s)
		}
	}
	if _, err := ParseCustomAddr("abc123"); !errors.Is(err, ErrCustomAddrMissingSeparator) {
		t.Errorf("missing separator: got %v", err)
	}
}

func TestCustomAddrBinary(t *testing.T) {
	a := NewCustomAddr(0xdeadbeef, []byte{0x01, 0x02, 0x03})
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// 8-byte LE id + data.
	if len(b) != 11 {
		t.Fatalf("len = %d, want 11", len(b))
	}
	a2, err := CustomAddrFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if a2.Id() != a.Id() || string(a2.Data()) != string(a.Data()) {
		t.Errorf("binary round-trip mismatch")
	}
	if _, err := CustomAddrFromBytes([]byte{1, 2, 3}); !errors.Is(err, ErrCustomAddrTooShort) {
		t.Errorf("short bytes: got %v", err)
	}
}

func TestRelayUrlNormalization(t *testing.T) {
	// Rust url crate adds a trailing slash; we match that.
	u, err := ParseRelayUrl("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.com/"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got := u.Host(); got != "example.com" {
		t.Errorf("Host() = %q, want example.com", got)
	}
}

func TestRelayUrlEqualCompare(t *testing.T) {
	a, _ := ParseRelayUrl("https://a.example.com")
	b, _ := ParseRelayUrl("https://b.example.com")
	a2, _ := ParseRelayUrl("https://a.example.com/")
	if !a.Equal(a2) {
		t.Error("expected a == a2 after normalization")
	}
	if a.Compare(b) >= 0 {
		t.Error("expected a < b")
	}
}

func TestTransportAddrStringRoundTrip(t *testing.T) {
	relay, _ := ParseRelayUrl("https://relay.example.com")
	ip := netip.MustParseAddrPort("127.0.0.1:9")
	cases := []TransportAddr{
		RelayAddr{URL: relay},
		IPAddr{Addr: ip},
		NewCustomAddr(7, []byte{0xde, 0xad}),
	}
	for _, addr := range cases {
		s := addr.String()
		parsed, err := ParseTransportAddr(s)
		if err != nil {
			t.Fatalf("ParseTransportAddr(%q): %v", s, err)
		}
		if parsed.String() != s {
			t.Errorf("round-trip: %q != %q", parsed.String(), s)
		}
	}
}

func TestEndpointAddrSortDedup(t *testing.T) {
	sk, _ := GenerateSecretKey()
	id := sk.Public()
	ip1 := netip.MustParseAddrPort("127.0.0.1:1")
	ip2 := netip.MustParseAddrPort("127.0.0.1:2")
	a := NewEndpointAddr(id).
		WithIP(ip2).
		WithIP(ip1).
		WithIP(ip1) // duplicate
	addrs := a.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("len = %d, want 2 (deduped)", len(addrs))
	}
	// Sorted by compareKey: ip:127.0.0.1:1 < ip:127.0.0.1:2.
	if addrs[0].String() != "ip:127.0.0.1:1" || addrs[1].String() != "ip:127.0.0.1:2" {
		t.Errorf("not sorted: %v", []string{addrs[0].String(), addrs[1].String()})
	}
	if a.IsEmpty() {
		t.Error("should not be empty")
	}
	if got := a.IPAddrs(); len(got) != 2 {
		t.Errorf("IPAddrs len = %d, want 2", len(got))
	}
}

func TestEndpointAddrEmpty(t *testing.T) {
	sk, _ := GenerateSecretKey()
	a := NewEndpointAddr(sk.Public())
	if !a.IsEmpty() {
		t.Error("expected empty")
	}
	if len(a.RelayURLs()) != 0 || len(a.IPAddrs()) != 0 {
		t.Error("expected no addrs")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hexRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
