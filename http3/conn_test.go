package http3_test

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/http3"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestConnStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const alpn = "h3-iroh-test/1"
	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(alpn),
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Shutdown(ctx)

	accepted := make(chan *iroh.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	clientConn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer clientConn.CloseWithError(0, "")

	var serverConn *iroh.Conn
	select {
	case serverConn = <-accepted:
	case err := <-errc:
		t.Fatalf("accept: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverConn.CloseWithError(0, "")

	clientH3 := http3.NewConn(clientConn)
	serverH3 := http3.NewConn(serverConn)

	done := make(chan error, 1)
	go func() {
		s, err := serverH3.AcceptBidi(ctx)
		if err != nil {
			done <- err
			return
		}
		_, err = io.Copy(s, s)
		done <- err
	}()

	stream, err := clientH3.OpenBidi(ctx)
	if err != nil {
		t.Fatalf("open bidi: %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len("hello"))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q, want hello", buf)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server stream: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
