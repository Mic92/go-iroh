package iroh_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// ExampleMemoryLookup resolves addressing information added out-of-band, such
// as from an endpoint ticket.
func ExampleMemoryLookup() {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()

	lookup := iroh.NewMemoryLookup()
	relay, _ := base.ParseRelayUrl("https://relay.example/")
	lookup.AddEndpointAddr(base.NewEndpointAddr(id).WithRelayURL(relay))

	for r := range lookup.Resolve(context.Background(), id) {
		if r.Err != nil {
			fmt.Println("error:", r.Err)
			continue
		}
		fmt.Println("provenance:", r.Item.Provenance())
		fmt.Println("relays:", r.Item.Addr().RelayURLs())
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
	relay, _ := base.ParseRelayUrl("https://relay.example/")

	mem := iroh.NewMemoryLookup()
	mem.AddEndpointInfo(dns.NewEndpointInfo(id).WithRelayURL(relay))

	var services iroh.AddressLookupServices
	services.Add(mem)

	for r := range services.Resolve(context.Background(), id) {
		if r.Err != nil {
			continue
		}
		fmt.Println(r.Item.Addr().RelayURLs())
		break
	}
	// Output:
	// [https://relay.example/]
}
