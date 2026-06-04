package iroh_test

import (
	"context"
	"fmt"
	"io"
	"net/netip"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
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
	defer ep.Shutdown(ctx)

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
	defer ep.Shutdown(ctx)

	status := ep.HomeRelayStatus().Current()
	if status != nil && status.IsConnected() {
		fmt.Println("connected to", status.URL)
	}
}

func echo(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	if _, err := io.Copy(s, s); err != nil {
		return err
	}
	return s.Close()
}

// ExampleRouter runs an echo protocol over a direct loopback connection: a
// server registers the echo handler via a Router, and a client connects, sends
// a message on a stream, and reads the echo back.
func ExampleRouter() {
	ctx := context.Background()
	const alpn = "iroh/echo/1"

	srvKey, _ := key.GenerateSecretKey()
	server, err := iroh.Bind(ctx, iroh.WithSecretKey(srvKey),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		fmt.Println("bind server:", err)
		return
	}

	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		alpn: iroh.ProtocolHandlerFunc(echo),
	}, nil)
	if err != nil {
		fmt.Println("router:", err)
		return
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		fmt.Println("bind client:", err)
		return
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	s, _ := conn.OpenStreamSync(ctx)
	s.Write([]byte("hello"))
	s.Close()
	got, _ := io.ReadAll(s)
	fmt.Printf("%s\n", got)
	// Output: hello
}
