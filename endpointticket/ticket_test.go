package endpointticket

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestGolden(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("http://derp.me./")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id,
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1024")},
	)
	wantBytes, err := hex.DecodeString(
		"00" +
			"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" +
			"02" +
			"00" +
			"10" +
			"687474703a2f2f646572702e6d652e2f" +
			"01" +
			"00" +
			"7f0000018008")
	if err != nil {
		t.Fatal(err)
	}
	want := prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(wantBytes))
	if got := Encode(addr); got != want {
		t.Fatalf("Encode = %q, want %q", got, want)
	}
	got, err := Decode(want)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestRoundTripCustomAddr(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id,
		netaddr.NewCustomAddr(1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6}),
		netaddr.NewCustomAddr(42, bytesRepeat(0xab, 32)),
	)
	got, err := Decode(Encode(addr))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestParseTicket(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id)
	ticket, err := Parse(Encode(addr))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertEndpointAddrEqual(t, ticket.Addr(), addr)
	if ticket.String() != Encode(addr) {
		t.Fatalf("Ticket.String = %q, want %q", ticket.String(), Encode(addr))
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{name: "missing prefix", in: "nodeabc", want: ErrMissingPrefix},
		{name: "truncated", in: prefix + "aa", want: ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("Decode error = %v, want %v", err, tt.want)
			}
		})
	}
}

func assertEndpointAddrEqual(t *testing.T, got, want netaddr.EndpointAddr) {
	t.Helper()
	if !got.ID.Equal(want.ID) {
		t.Fatalf("id = %s, want %s", got.ID, want.ID)
	}
	gotAddrs := got.Addrs()
	wantAddrs := want.Addrs()
	if len(gotAddrs) != len(wantAddrs) {
		t.Fatalf("addrs = %v, want %v", gotAddrs, wantAddrs)
	}
	for i := range gotAddrs {
		if gotAddrs[i].Compare(wantAddrs[i]) != 0 {
			t.Fatalf("addr[%d] = %v, want %v", i, gotAddrs[i], wantAddrs[i])
		}
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
