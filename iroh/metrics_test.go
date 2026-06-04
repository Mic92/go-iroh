package iroh

import (
	"context"
	"encoding/json"
	"expvar"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestMetricsStringExpvar(t *testing.T) {
	var _ expvar.Var = Metrics{}
	m := Metrics{ConnectsStarted: 2, ConnectsAccepted: 1, ConnectsFailed: 1}
	var got map[string]uint64
	if err := json.Unmarshal([]byte(m.String()), &got); err != nil {
		t.Fatalf("Metrics.String is not JSON: %v", err)
	}
	if got["ConnectsStarted"] != 2 || got["ConnectsAccepted"] != 1 || got["ConnectsFailed"] != 1 {
		t.Fatalf("Metrics.String = %s", m.String())
	}
}

func TestEndpointMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-metrics/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err == nil {
			conn.CloseWithError(0, "")
		}
		accepted <- err
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}

	cm := client.Metrics()
	if cm.ConnectsStarted != 1 || cm.ConnectsAccepted != 1 || cm.ConnectsFailed != 0 {
		t.Fatalf("client Metrics = %+v, want one successful connect", cm)
	}
	sm := server.Metrics()
	if sm.AcceptsStarted != 1 || sm.AcceptsAccepted != 1 || sm.AcceptsFailed != 0 {
		t.Fatalf("server Metrics = %+v, want one successful accept", sm)
	}

	if _, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()), alpn); err == nil {
		t.Fatal("connect without address succeeded")
	}
	cm = client.Metrics()
	if cm.ConnectsStarted != 2 || cm.ConnectsAccepted != 1 || cm.ConnectsFailed != 1 {
		t.Fatalf("client Metrics after failure = %+v, want failed connect counted", cm)
	}
}
