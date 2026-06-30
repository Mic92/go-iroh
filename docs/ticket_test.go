package docs

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestDocTicketRustVector(t *testing.T) {
	nodeID, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	var nsBytes [32]byte
	if _, err := hex.Decode(nsBytes[:], []byte("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")); err != nil {
		t.Fatal(err)
	}
	namespace := MustNamespaceID(nsBytes)
	ticket := NewTicket(NewReadCapability(namespace), []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(nodeID),
	})
	wantBytes, err := hex.DecodeString(
		"00" +
			"01" +
			"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" +
			"01" +
			"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" +
			"00")
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
	decoded, err := DecodeString(want)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if decoded.Capability().Kind() != CapabilityRead {
		t.Fatalf("capability kind = %v, want read", decoded.Capability().Kind())
	}
	if decoded.Capability().NamespaceID().String() != namespace.String() {
		t.Fatalf("namespace = %s, want %s", decoded.Capability().NamespaceID(), namespace)
	}
	if len(decoded.Nodes()) != 1 || !decoded.Nodes()[0].ID.Equal(nodeID) || len(decoded.Nodes()[0].Addrs()) != 0 {
		t.Fatalf("nodes = %+v, want one node with no addrs", decoded.Nodes())
	}
}

func TestDocTicketRegistry(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	ns := NewReadCapability(NamespaceID{id: sk.Public().EndpointID()})
	ticket := NewTicket(ns, []netaddr.EndpointAddr{netaddr.NewEndpointAddr(sk.Public().EndpointID())})
	var _ endpointticket.TicketCodec = ticket

	r := endpointticket.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	got, err := r.DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	doc, ok := got.(DocTicket)
	if !ok {
		t.Fatalf("DecodeString returned %T, want DocTicket", got)
	}
	if doc.Capability().NamespaceID().String() != ticket.Capability().NamespaceID().String() {
		t.Fatalf("namespace = %s, want %s", doc.Capability().NamespaceID(), ticket.Capability().NamespaceID())
	}
}

func TestDocTicketJSONRoundTrip(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	ticket := NewTicket(NewReadCapability(NamespaceID{id: id}), []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(id),
	})
	in := struct {
		Ticket DocTicket `json:"ticket"`
	}{Ticket: ticket}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `{"ticket":"`+ticket.String()+`"}` {
		t.Fatalf("Marshal = %s, want ticket string", data)
	}
	var out struct {
		Ticket DocTicket `json:"ticket"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Ticket.Capability().NamespaceID().String() != ticket.Capability().NamespaceID().String() {
		t.Fatalf("namespace = %s, want %s", out.Ticket.Capability().NamespaceID(), ticket.Capability().NamespaceID())
	}
	if len(out.Ticket.Nodes()) != 1 {
		t.Fatalf("nodes len = %d, want 1", len(out.Ticket.Nodes()))
	}
	assertEndpointAddrEqual(t, out.Ticket.Nodes()[0], ticket.Nodes()[0])
}

func TestDocTicketShort(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	capability := NewReadCapability(NamespaceID{id: id})
	ticket := NewTicket(capability, []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(id,
			netaddr.RelayAddr{URL: relay},
			netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")},
			netaddr.NewCustomAddr(7, []byte("local")),
		),
	})

	short := ticket.Short()
	if short.Capability().Kind() != CapabilityRead {
		t.Fatalf("capability kind = %v, want read", short.Capability().Kind())
	}
	if short.Capability().NamespaceID().String() != capability.NamespaceID().String() {
		t.Fatalf("namespace = %s, want %s", short.Capability().NamespaceID(), capability.NamespaceID())
	}
	wantAddr := netaddr.NewEndpointAddr(id, netaddr.RelayAddr{URL: relay})
	assertEndpointAddrEqual(t, short.Nodes()[0], wantAddr)

	decoded, err := DecodeString(short.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if decoded.Capability().NamespaceID().String() != capability.NamespaceID().String() {
		t.Fatalf("decoded namespace = %s, want %s", decoded.Capability().NamespaceID(), capability.NamespaceID())
	}
	assertEndpointAddrEqual(t, decoded.Nodes()[0], wantAddr)
}

func TestDocTicketRoundTripManyNodes(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	capability := NewReadCapability(NamespaceID{id: sk.Public().EndpointID()})
	nodes := make([]netaddr.EndpointAddr, 2000)
	for i := range nodes {
		var seed [32]byte
		seed[0] = byte(i)
		seed[1] = byte(i >> 8)
		id := key.NewSecretKey(seed).Public().EndpointID()
		nodes[i] = netaddr.NewEndpointAddr(id)
	}
	ticket := NewTicket(capability, nodes)
	got, err := DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if len(got.Nodes()) != len(nodes) {
		t.Fatalf("nodes len = %d, want %d", len(got.Nodes()), len(nodes))
	}
	for i := range nodes {
		assertEndpointAddrEqual(t, got.Nodes()[i], nodes[i])
	}
}

func TestDocTicketErrors(t *testing.T) {
	if _, err := DecodeString("blobabc"); !errors.Is(err, &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindKind}) {
		t.Fatalf("missing prefix error = %v", err)
	}
	if _, err := DecodeString(TicketKind + "!"); !errors.Is(err, endpointticket.ErrEncoding) {
		t.Fatalf("encoding error = %v", err)
	}
	if _, err := DecodeBytes([]byte{0, 1}); !errors.Is(err, endpointticket.ErrDecode) {
		t.Fatalf("decode error = %v", err)
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
