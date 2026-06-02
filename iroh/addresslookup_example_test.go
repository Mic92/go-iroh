package iroh_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// ExampleMemoryLookup resolves addressing information added out-of-band, such
// as from an endpoint ticket.
func ExampleMemoryLookup() {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()

	lookup := iroh.NewMemoryLookup()
	relay, _ := netaddr.ParseRelayURL("https://relay.example/")
	lookup.AddEndpointAddr(netaddr.NewEndpointAddr(id).WithRelayURL(relay))

	for item, err := range lookup.Resolve(context.Background(), id) {
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		fmt.Println("provenance:", item.Provenance())
		fmt.Println("relays:", item.Addr().RelayURLs())
	}
	// Output:
	// provenance: memory_lookup
	// relays: [https://relay.example/]
}

// ExampleAddressLookupServices combines several lookup services and resolves an
// endpoint id across all of them, acting on the first usable result.
func ExampleAddressLookupServices() {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	relay, _ := netaddr.ParseRelayURL("https://relay.example/")

	mem := iroh.NewMemoryLookup()
	mem.AddEndpointInfo(dns.EndpointInfo{
		ID:   id,
		Data: dns.NewEndpointData(netaddr.RelayAddr{URL: relay}),
	})

	var services iroh.AddressLookupServices
	services.AddResolver(mem)

	for item, err := range services.Resolve(context.Background(), id) {
		if err != nil {
			continue
		}
		fmt.Println(item.Addr().RelayURLs())
		break
	}
	// Output:
	// [https://relay.example/]
}
