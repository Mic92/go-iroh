package endpointticket

import (
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func FuzzDecodeBytes(f *testing.F) {
	ticket := New(netaddr.NewEndpointAddr(testEndpointID(), netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")}))
	f.Add(ticket.EncodeBytes())
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBytes(data)
	})
}

func FuzzDecodeString(f *testing.F) {
	ticket := New(netaddr.NewEndpointAddr(testEndpointID(), netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1234")}))
	f.Add(ticket.EncodeString())
	f.Add(Kind)
	f.Add("endpoint!")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeString(s)
	})
}

func testEndpointID() key.EndpointID {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return key.NewSecretKey(seed).Public().EndpointID()
}
