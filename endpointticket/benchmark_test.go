package endpointticket

import (
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

var benchmarkTicketSink Ticket

func benchmarkTicket(t testing.TB) Ticket {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example./")
	if err != nil {
		t.Fatal(err)
	}
	return New(netaddr.NewEndpointAddr(sk.Public().EndpointID(),
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:12345")},
		netaddr.NewCustomAddr(42, []byte("custom transport addr")),
	))
}

func BenchmarkTicketEncodeDecode(b *testing.B) {
	ticket := benchmarkTicket(b)
	encoded := ticket.String()
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if got := ticket.String(); got == "" {
				b.Fatal("empty ticket")
			}
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			got, err := Parse(encoded)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkTicketSink = got
		}
	})
}
