package socket_test

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

func TestRelayOnlyQUICEchoNoUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ts := httptest.NewServer(relayserver.New())
	t.Cleanup(ts.Close)
	relayURL, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-socket-relay-only/0"
	serverKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	server, err := iroh.Bind(ctx,
		iroh.WithSecretKey(serverKey),
		iroh.WithALPNs(alpn),
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	if got := server.LocalAddr(); got.IsValid() {
		t.Fatalf("server LocalAddr = %v, want invalid without UDP", got)
	}

	client, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)
	if got := client.LocalAddr(); got.IsValid() {
		t.Fatalf("client LocalAddr = %v, want invalid without UDP", got)
	}

	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		buf, err := io.ReadAll(stream)
		if err != nil {
			errc <- err
			return
		}
		if _, err := stream.Write(buf); err != nil {
			errc <- err
			return
		}
		errc <- stream.Close()
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello over relay-only quic"
	if _, err := stream.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
}
