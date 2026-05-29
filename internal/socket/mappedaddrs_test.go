package socket

import (
	"net/netip"
	"testing"
)

// TestMappedAddrBytes pins the mapped-address byte scheme to the Rust
// implementation (iroh/src/socket/mapped_addrs.rs): ULA prefix 0xfd, n0 global
// id 15 07 0a 51 0b, subnet ids 00 00 / 00 01 / 00 03, and a big-endian u64
// counter. These are a local indirection (never on the wire) but matching the
// scheme keeps the two implementations cross-referenceable.
func TestMappedAddrBytes(t *testing.T) {
	tests := []struct {
		name    string
		subnet  [2]byte
		counter uint64
		want    string
	}{
		{"endpoint id #1", subnetEndpointID, 1, "fd15:70a:510b::1"},
		{"relay #1", subnetRelay, 1, "fd15:70a:510b:1::1"},
		{"custom #1", subnetCustom, 1, "fd15:70a:510b:3::1"},
		{"endpoint id #2", subnetEndpointID, 2, "fd15:70a:510b::2"},
		{"relay #258", subnetRelay, 258, "fd15:70a:510b:1::102"},
	}
	for _, tt := range tests {
		got := mappedAddr(tt.subnet, tt.counter)
		want := netip.MustParseAddr(tt.want)
		if got != want {
			t.Errorf("%s: mappedAddr = %s, want %s (bytes %x)", tt.name, got, want, got.As16())
		}
	}
}

// TestMappedAddrPrefixExact checks the literal first 8 bytes.
func TestMappedAddrPrefixExact(t *testing.T) {
	a := mappedAddr(subnetRelay, 1).As16()
	wantPrefix := []byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01}
	for i, b := range wantPrefix {
		if a[i] != b {
			t.Errorf("byte %d = 0x%02x, want 0x%02x", i, a[i], b)
		}
	}
	// Counter in the low 8 bytes, big-endian.
	for i := 8; i < 15; i++ {
		if a[i] != 0 {
			t.Errorf("byte %d = 0x%02x, want 0", i, a[i])
		}
	}
	if a[15] != 1 {
		t.Errorf("byte 15 = 0x%02x, want 1", a[15])
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		addr string
		want MappedKind
	}{
		{"fd15:70a:510b::1", KindEndpointID},
		{"fd15:70a:510b:1::1", KindRelay},
		{"fd15:70a:510b:3::1", KindCustom},
		{"fd15:70a:510b:2::1", KindIP},   // unused subnet -> treated as plain IP
		{"192.0.2.1", KindIP},            // real v4
		{"2001:db8::1", KindIP},          // real v6
		{"fd00::1", KindIP},              // ULA but not n0's
	}
	for _, tt := range tests {
		got := Classify(netip.MustParseAddr(tt.addr))
		if got != tt.want {
			t.Errorf("Classify(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

// TestClassifyRejectsMappedPort confirms the dummy port is 12345.
func TestMappedPort(t *testing.T) {
	if NewRelayMappedAddr().AddrPort().Port() != mappedPort || mappedPort != 12345 {
		t.Errorf("mapped port = %d, want 12345", mappedPort)
	}
}

func TestAddrMapRoundTrip(t *testing.T) {
	m := NewAddrMap[string, RelayMappedAddr](
		NewRelayMappedAddr,
		func(v RelayMappedAddr) netip.Addr { return v.Addr() },
	)
	a := m.Get("peer-a")
	b := m.Get("peer-b")
	if a == b {
		t.Fatal("distinct keys produced the same mapped addr")
	}
	if got := m.Get("peer-a"); got != a {
		t.Error("Get is not stable for the same key")
	}
	if k, ok := m.Lookup(a.Addr()); !ok || k != "peer-a" {
		t.Errorf("Lookup(a) = %q,%v, want peer-a,true", k, ok)
	}
	if _, ok := m.Lookup(netip.MustParseAddr("203.0.113.1")); ok {
		t.Error("Lookup of unknown addr should fail")
	}
}
