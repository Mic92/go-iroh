package docs

import (
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func FuzzDecodeTicketBytes(f *testing.F) {
	ticket := NewTicket(NewReadCapability(NewNamespaceSecret(fuzzRepeat32(0xb2)).ID()), []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(testEndpointID(), netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")}),
	})
	f.Add(ticket.EncodeBytes())
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBytes(data)
	})
}

func FuzzDecodeTicketString(f *testing.F) {
	ticket := NewTicket(NewReadCapability(NewNamespaceSecret(fuzzRepeat32(0xb2)).ID()), []netaddr.EndpointAddr{
		netaddr.NewEndpointAddr(testEndpointID(), netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")}),
	})
	f.Add(ticket.EncodeString())
	f.Add(TicketKind)
	f.Add("doc!")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeString(s)
	})
}

func fuzzRepeat32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func testEndpointID() key.EndpointID {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return key.NewSecretKey(seed).Public().EndpointID()
}
