package iroh_test

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func ExampleBiasedRttPathSelector() {
	selector := iroh.BiasedRttPathSelector{}
	candidates := []iroh.PathCandidate{
		{Addr: netaddr.RelayAddr{URL: mustRelayURL("https://relay.example/")}, RTT: time.Millisecond},
		{Addr: netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1000")}, RTT: 20 * time.Millisecond},
	}
	selected, ok := selector.Select(nil, candidates)
	fmt.Println(ok, selected.Network())
	// Output:
	// true ip
}

func mustRelayURL(s string) netaddr.RelayURL {
	u, err := netaddr.ParseRelayURL(s)
	if err != nil {
		panic(err)
	}
	return u
}
