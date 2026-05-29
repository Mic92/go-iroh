package iroh_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/relay"
)

// ExampleEndpoint_Online binds an endpoint that uses the n0 staging relays and
// waits until it has a connected home relay before dialing.
func ExampleEndpoint_Online() {
	ctx := context.Background()

	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeStaging()))
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer ep.Close(ctx)

	// Block until a home relay connection is established (or ctx is done).
	if err := ep.Online(ctx); err != nil {
		fmt.Println("online:", err)
		return
	}

	// ep.Addr() now includes the home relay URL, so peers can reach this
	// endpoint over the relay.
	fmt.Println(len(ep.Addr().RelayURLs()) >= 0)
}

// ExampleEndpoint_HomeRelayStatus observes the home relay connection status.
func ExampleEndpoint_HomeRelayStatus() {
	ctx := context.Background()

	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeDefault()))
	if err != nil {
		fmt.Println("bind:", err)
		return
	}
	defer ep.Close(ctx)

	status := ep.HomeRelayStatus().Get()
	if status != nil && status.IsConnected() {
		fmt.Println("connected to", status.URL)
	}
}
