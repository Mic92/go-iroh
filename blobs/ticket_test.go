package blobs

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestTicketGolden(t *testing.T) {
	hash := mustParseHash(t, "0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	ticket := NewTicket(netaddr.NewEndpointAddr(id), hash, Raw)

	wantBytes, err := hex.DecodeString(
		"00" +
			"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" +
			"00" +
			"00" +
			"00" +
			"0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
	if err != nil {
		t.Fatal(err)
	}
	if got := ticket.EncodeBytes(); hex.EncodeToString(got) != hex.EncodeToString(wantBytes) {
		t.Fatalf("EncodeBytes = %x, want %x", got, wantBytes)
	}
	want := TicketKind + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(wantBytes))
	if got := ticket.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	got, err := DecodeString(want)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	assertTicketEqual(t, got, ticket)
}

func TestTicketRoundTrip(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	ticket := NewTicket(
		netaddr.NewEndpointAddr(id,
			netaddr.RelayAddr{URL: relay},
			netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
		),
		NewHash([]byte("hi there")),
		HashSeq,
	)
	got, err := DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	assertTicketEqual(t, got, ticket)
	if !got.Recursive() {
		t.Fatal("Recursive = false, want true")
	}
	if !strings.Contains(hex.EncodeToString(ticket.EncodeBytes()), "01007f000001d209") {
		t.Fatalf("direct address wire = %x, want postcard BTreeSet SocketAddr encoding", ticket.EncodeBytes())
	}
}

func TestTicketRoundTripManyAddrs(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addrs := make([]netaddr.TransportAddr, 2000)
	for i := range addrs {
		addrs[i] = netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(10000+i))}
	}
	ticket := NewTicket(netaddr.NewEndpointAddr(id, addrs...), NewHash([]byte("many addrs")), Raw)
	got, err := DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	assertTicketEqual(t, got, ticket)
}

func TestTicketShort(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	hash := NewHash([]byte("short blob"))
	ticket := NewTicket(
		netaddr.NewEndpointAddr(id,
			netaddr.RelayAddr{URL: relay},
			netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
			netaddr.NewCustomAddr(7, []byte("local")),
		),
		hash,
		HashSeq,
	)

	short := ticket.Short()
	want := NewTicket(netaddr.NewEndpointAddr(id, netaddr.RelayAddr{URL: relay}), hash, HashSeq)
	assertTicketEqual(t, short, want)
	if !short.Recursive() {
		t.Fatal("Recursive = false, want true")
	}
	got, err := DecodeString(short.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	assertTicketEqual(t, got, want)
}

func TestRegister(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	ticket := NewTicket(netaddr.NewEndpointAddr(id), EmptyHash, Raw)
	r := endpointticket.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	got, err := r.DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("Registry.DecodeString: %v", err)
	}
	blob, ok := got.(Ticket)
	if !ok {
		t.Fatalf("Registry.DecodeString returned %T, want Ticket", got)
	}
	assertTicketEqual(t, blob, ticket)
}

func TestDecodeErrors(t *testing.T) {
	if _, err := DecodeString("endpointabc"); !errors.Is(err, &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindKind}) {
		t.Fatalf("DecodeString wrong prefix error = %v", err)
	}
	if _, err := DecodeString(TicketKind + "!"); !errors.Is(err, endpointticket.ErrEncoding) {
		t.Fatalf("DecodeString encoding error = %v", err)
	}
	if _, err := DecodeString(TicketKind + "aa"); !errors.Is(err, endpointticket.ErrDecode) {
		t.Fatalf("DecodeString decode error = %v", err)
	}
}

func mustParseHash(t *testing.T, s string) Hash {
	t.Helper()
	h, err := ParseHash(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func assertTicketEqual(t *testing.T, got, want Ticket) {
	t.Helper()
	if !got.Addr().ID.Equal(want.Addr().ID) {
		t.Fatalf("id = %s, want %s", got.Addr().ID, want.Addr().ID)
	}
	if got.Hash() != want.Hash() {
		t.Fatalf("hash = %s, want %s", got.Hash(), want.Hash())
	}
	if got.Format() != want.Format() {
		t.Fatalf("format = %v, want %v", got.Format(), want.Format())
	}
	gotAddrs := got.Addr().Addrs()
	wantAddrs := want.Addr().Addrs()
	if len(gotAddrs) != len(wantAddrs) {
		t.Fatalf("addrs = %v, want %v", gotAddrs, wantAddrs)
	}
	for i := range gotAddrs {
		if gotAddrs[i].Compare(wantAddrs[i]) != 0 {
			t.Fatalf("addr[%d] = %v, want %v", i, gotAddrs[i], wantAddrs[i])
		}
	}
}
