package dns

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/base"
)

func mustRelay(t *testing.T, s string) base.RelayUrl {
	t.Helper()
	u, err := base.ParseRelayUrl(s)
	if err != nil {
		t.Fatalf("ParseRelayUrl(%q): %v", s, err)
	}
	return u
}

// TestTxtAttrRoundTrip mirrors iroh-dns txt_attr_roundtrip.
func TestTxtAttrRoundTrip(t *testing.T) {
	ud, err := NewUserData("foobar")
	if err != nil {
		t.Fatal(err)
	}
	data := NewEndpointData(
		base.RelayAddr{URL: mustRelay(t, "https://example.com")},
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
	).WithUserData(ud)
	id, err := base.ParsePublicKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	want := EndpointInfoFromParts(id, data)
	attrs := want.toAttrs()
	got := endpointInfoFromAttrs(attrs)
	assertEndpointInfoEqual(t, got, want)
}

// TestTxtAttrRoundTripCustomAddr mirrors txt_attr_roundtrip_with_custom_addr.
func TestTxtAttrRoundTripCustomAddr(t *testing.T) {
	bt := base.NewCustomAddr(1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6})
	tor := base.NewCustomAddr(42, bytesRepeat(0xab, 32))
	data := NewEndpointData(
		base.RelayAddr{URL: mustRelay(t, "https://example.com")},
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
		bt,
		tor,
	)
	id, err := base.ParsePublicKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	want := EndpointInfoFromParts(id, data)
	got := endpointInfoFromAttrs(want.toAttrs())
	assertEndpointInfoEqual(t, got, want)
}

// TestSignedPacketRoundTrip mirrors signed_packet_roundtrip.
func TestSignedPacketRoundTrip(t *testing.T) {
	sk, err := base.ParseSecretKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	ud, _ := NewUserData("foobar")
	data := NewEndpointData(
		base.RelayAddr{URL: mustRelay(t, "https://example.com")},
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
	).WithUserData(ud)
	want := EndpointInfoFromParts(sk.Public(), data)
	packet, err := want.ToPkarrSignedPacket(sk, 30)
	if err != nil {
		t.Fatalf("ToPkarrSignedPacket: %v", err)
	}
	got, err := EndpointInfoFromPkarrSignedPacket(packet)
	if err != nil {
		t.Fatalf("EndpointInfoFromPkarrSignedPacket: %v", err)
	}
	assertEndpointInfoEqual(t, got, want)
}

// TestSignedPacketRoundTripCustomAddr mirrors signed_packet_roundtrip_with_custom_addr.
func TestSignedPacketRoundTripCustomAddr(t *testing.T) {
	sk, err := base.ParseSecretKey("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia")
	if err != nil {
		t.Fatal(err)
	}
	bt := base.NewCustomAddr(1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6})
	tor := base.NewCustomAddr(42, bytesRepeat(0xab, 32))
	ud, _ := NewUserData("foobar")
	data := NewEndpointData(
		base.RelayAddr{URL: mustRelay(t, "https://example.com")},
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
		bt, tor,
	).WithUserData(ud)
	want := EndpointInfoFromParts(sk.Public(), data)
	packet, err := want.ToPkarrSignedPacket(sk, 30)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EndpointInfoFromPkarrSignedPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	assertEndpointInfoEqual(t, got, want)
}

// TestFromTxtLookupMultiAddr mirrors test_from_hickory_lookup: more than one
// addr record must be parsed, and records with the wrong name are excluded.
func TestFromTxtLookupMultiAddr(t *testing.T) {
	id, err := base.ParsePublicKey("1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18")
	if err != nil {
		t.Fatal(err)
	}
	name := "_iroh." + id.Z32() + ".dns.iroh.link."
	values := []string{
		"addr=192.168.96.145:60165",
		"addr=213.208.157.87:60165",
		"relay=https://euw1-1.relay.iroh.network./",
	}
	got, err := EndpointInfoFromTxtLookup(name, values)
	if err != nil {
		t.Fatalf("EndpointInfoFromTxtLookup: %v", err)
	}
	want := NewEndpointInfo(id).
		WithRelayURL(mustRelay(t, "https://euw1-1.relay.iroh.network./")).
		WithIPAddrs(
			netip.MustParseAddrPort("192.168.96.145:60165"),
			netip.MustParseAddrPort("213.208.157.87:60165"),
		)
	assertEndpointInfoEqual(t, got, want)
}

func TestTxtStringsOrder(t *testing.T) {
	// Reference BTreeMap order is relay, addr, user-data (enum order), not lexical.
	ud, _ := NewUserData("x")
	info := EndpointInfoFromParts(testID(t), NewEndpointData(
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1")},
		base.RelayAddr{URL: mustRelay(t, "https://r.example.com")},
	).WithUserData(ud))
	got := info.ToTxtStrings()
	// relay first, then addr, then user-data.
	if len(got) != 3 || got[0][:6] != "relay=" || got[1][:5] != "addr=" || got[2][:10] != "user-data=" {
		t.Errorf("ToTxtStrings order wrong: %v", got)
	}
}

func TestTxtStringsGolden(t *testing.T) {
	ud, _ := NewUserData("foobar")
	info := EndpointInfoFromParts(testID(t), NewEndpointData(
		base.RelayAddr{URL: mustRelay(t, "https://example.com/")},
		base.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
		base.NewCustomAddr(1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6}),
	).WithUserData(ud))
	got := info.ToTxtStrings()
	want := []string{
		"relay=https://example.com/",
		"addr=127.0.0.1:1234",
		"addr=1_a1b2c3d4e5f6",
		"user-data=foobar",
	}
	if !slices.Equal(got, want) {
		t.Errorf("ToTxtStrings = %v, want %v", got, want)
	}
}

func TestTxtAttrsSplitLikeRust(t *testing.T) {
	id := testID(t)
	name := "_iroh." + id.Z32() + ".dns.iroh.link."
	got, err := EndpointInfoFromTxtLookup(name, []string{"user-data=a=b"})
	if err != nil {
		t.Fatalf("EndpointInfoFromTxtLookup: %v", err)
	}
	if got.UserData() == nil || got.UserData().String() != "a" {
		t.Fatalf("UserData = %v, want a", got.UserData())
	}
}

func TestUserDataTooLong(t *testing.T) {
	long := make([]byte, UserDataMaxLength+1)
	if _, err := NewUserData(string(long)); err == nil {
		t.Error("expected error for over-length user data")
	}
	ok := make([]byte, UserDataMaxLength)
	if _, err := NewUserData(string(ok)); err != nil {
		t.Errorf("unexpected error for max-length user data: %v", err)
	}
}

func testID(t *testing.T) base.EndpointId {
	t.Helper()
	id, err := base.ParsePublicKey("1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertEndpointInfoEqual(t *testing.T, got, want EndpointInfo) {
	t.Helper()
	if !got.Id.Equal(want.Id) {
		t.Errorf("id mismatch: %s != %s", got.Id, want.Id)
	}
	gotAddrs, wantAddrs := got.Data.Addrs(), want.Data.Addrs()
	if len(gotAddrs) != len(wantAddrs) {
		t.Fatalf("addr count: %d != %d (%v vs %v)", len(gotAddrs), len(wantAddrs), strs(gotAddrs), strs(wantAddrs))
	}
	// Compare as sets (order can differ between stored and reparsed).
	gs, ws := strs(gotAddrs), strs(wantAddrs)
	slices.Sort(gs)
	slices.Sort(ws)
	if !slices.Equal(gs, ws) {
		t.Errorf("addrs mismatch: %v != %v", gs, ws)
	}
	gu, wu := got.UserData(), want.UserData()
	switch {
	case gu == nil && wu == nil:
	case gu == nil || wu == nil:
		t.Errorf("user data presence mismatch: %v != %v", gu, wu)
	case gu.String() != wu.String():
		t.Errorf("user data: %q != %q", gu.String(), wu.String())
	}
}

func strs(addrs []base.TransportAddr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
