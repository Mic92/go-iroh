package mdns_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/iroh/mdns"
	"github.com/tmc/go-iroh/key"
)

func ExampleDiscovery() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sk, _ := key.GenerateSecretKey()
	discovery := mdns.New(sk.Public().EndpointID())
	go func() { _ = discovery.Start(ctx) }()

	var services iroh.AddressLookupServices
	services.AddPublisher(discovery)
	services.AddResolver(discovery)

	fmt.Println(discovery != nil)
	// Output:
	// true
}
