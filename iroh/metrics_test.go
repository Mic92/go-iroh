package iroh

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestMetricsStringExpvar(t *testing.T) {
	var _ expvar.Var = Metrics{}
	m := Metrics{ConnectsStarted: 2, ConnectsAccepted: 1, ConnectsFailed: 1}
	var got struct {
		ConnectsStarted  uint64
		ConnectsAccepted uint64
		ConnectsFailed   uint64
		Socket           SocketMetrics
		NetReport        NetReportMetrics
	}
	if err := json.Unmarshal([]byte(m.String()), &got); err != nil {
		t.Fatalf("Metrics.String is not JSON: %v", err)
	}
	if got.ConnectsStarted != 2 || got.ConnectsAccepted != 1 || got.ConnectsFailed != 1 {
		t.Fatalf("Metrics.String = %s", m.String())
	}
}

func TestMetricsWriteOpenMetrics(t *testing.T) {
	m := Metrics{ConnectsStarted: 2, AcceptsFailed: 1}
	var buf bytes.Buffer
	if err := m.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"# TYPE endpoint_connects_started counter\nendpoint_connects_started_total 2\n",
		"# TYPE endpoint_accepts_failed counter\nendpoint_accepts_failed_total 1\n",
		"# EOF\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("OpenMetrics missing %q in %q", want, got)
		}
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
	if cm.Socket.SendIPv6 == 0 {
		t.Fatalf("client socket Metrics = %+v, want IP sends", cm.Socket)
	}
	if cm.Socket.PathsDirect == 0 || cm.Socket.NumConnsDirect == 0 || cm.Socket.NumConnsOpened == 0 {
		t.Fatalf("client socket path Metrics = %+v, want direct path counters", cm.Socket)
	}
	sm := server.Metrics()
	if sm.AcceptsStarted != 1 || sm.AcceptsAccepted != 1 || sm.AcceptsFailed != 0 {
		t.Fatalf("server Metrics = %+v, want one successful accept", sm)
	}
	if sm.Socket.RecvDataIPv6 == 0 || sm.Socket.RecvDatagrams == 0 {
		t.Fatalf("server socket Metrics = %+v, want IP receives", sm.Socket)
	}

	if _, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()), alpn); err == nil {
		t.Fatal("connect without address succeeded")
	}
	cm = client.Metrics()
	if cm.ConnectsStarted != 2 || cm.ConnectsAccepted != 1 || cm.ConnectsFailed != 1 {
		t.Fatalf("client Metrics after failure = %+v, want failed connect counted", cm)
	}
}

func TestEndpointNetReportMetrics(t *testing.T) {
	ctx := context.Background()
	ep := &Endpoint{
		netReport: func(context.Context) (*netreport.Report, error) {
			return &netreport.Report{Full: true}, nil
		},
	}
	if err := ep.refreshNetReport(ctx); err != nil {
		t.Fatal(err)
	}
	m := ep.Metrics()
	if m.NetReport.Reports != 1 || m.NetReport.ReportsFull != 1 || m.NetReport.ReportsFailed != 0 {
		t.Fatalf("net report Metrics = %+v, want one completed report", m.NetReport)
	}

	ep.netReport = func(context.Context) (*netreport.Report, error) {
		return nil, context.Canceled
	}
	if err := ep.refreshNetReport(ctx); err == nil {
		t.Fatal("refreshNetReport nil error, want wrapped failure")
	}
	m = ep.Metrics()
	if m.NetReport.Reports != 1 || m.NetReport.ReportsFull != 1 || m.NetReport.ReportsFailed != 1 {
		t.Fatalf("net report Metrics after failure = %+v", m.NetReport)
	}
}
