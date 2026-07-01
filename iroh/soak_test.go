package iroh

import (
	"context"
	"io"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestEndpointDirectEchoSoakNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	runtime.GC()
	beforeG := runtime.NumGoroutine()
	beforeFD, haveFD := openFDs()

	const iterations = 40
	for i := 0; i < iterations; i++ {
		runDirectEchoOnce(t)
	}

	deadline := time.Now().Add(5 * time.Second)
	var afterG int
	var afterFD int
	for {
		runtime.GC()
		afterG = runtime.NumGoroutine()
		if haveFD {
			afterFD, _ = openFDs()
		}
		if afterG <= beforeG+8 && (!haveFD || afterFD <= beforeFD+4) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if afterG > beforeG+8 {
		t.Fatalf("goroutines grew from %d to %d after %d direct echo iterations", beforeG, afterG, iterations)
	}
	if haveFD && afterFD > beforeFD+4 {
		t.Fatalf("open fds grew from %d to %d after %d direct echo iterations", beforeFD, afterFD, iterations)
	}
}

func runDirectEchoOnce(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const alpn = "iroh-soak-echo/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		server.Shutdown(ctx)
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)
	defer server.Shutdown(ctx)

	done := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		if _, err := io.Copy(stream, stream); err != nil {
			done <- err
			return
		}
		done <- stream.Close()
	}()

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		t.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatalf("write stream: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close stream: %v", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q, want hello", got)
	}
	if err := conn.CloseWithError(0, ""); err != nil {
		t.Fatalf("close conn: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server echo: %v", err)
	}
}

func openFDs() (int, bool) {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return 0, false
	}
	return len(entries), true
}
