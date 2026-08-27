package iroh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

// qadRelay is an in-process relay over HTTPS with a QAD listener sharing the
// httptest certificate.
type qadRelay struct {
	mode    relay.Mode
	rootCAs *x509.CertPool
}

func newQADRelay(t testing.TB) qadRelay {
	t.Helper()
	rs := relayserver.New()
	ts := httptest.NewUnstartedServer(rs)
	ts.StartTLS()
	t.Cleanup(ts.Close)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rs.ServeQAD(ctx, udp, ts.TLS) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeQAD: %v", err)
		}
		udp.Close()
	})

	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	qport := uint16(udp.LocalAddr().(*net.UDPAddr).Port)
	m := relay.NewMap(relay.NewConfig(u, &relay.QUICConfig{Port: qport}))

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return qadRelay{mode: relay.ModeCustom(m), rootCAs: pool}
}

func (r qadRelay) bind(t testing.TB, ctx context.Context, opts ...Option) *Endpoint {
	t.Helper()
	opts = append([]Option{
		WithRelayMode(r.mode),
		WithRelayTLSConfig(&tls.Config{RootCAs: r.rootCAs}),
		WithNetReport(),
		WithBindAddr(netip.MustParseAddrPort("0.0.0.0:0")),
	}, opts...)
	ep, err := Bind(ctx, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ep.Shutdown(context.Background()) })
	return ep
}

// TestSelfHostedRelayQAD checks that an endpoint trusting a private CA learns
// its UDP address from a relayserver QAD listener, on its own socket.
func TestSelfHostedRelayQAD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := newQADRelay(t)
	ep := r.bind(t, ctx)
	want := waitQAD(t, ctx, ep)
	found := false
	for _, a := range ep.Addr().IPAddrs() {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("Addr() = %v, want to contain %v", ep.Addr(), want)
	}
}

// waitQAD waits until net-report learned the endpoint's own loopback mapping
// from the relay's QAD listener and returns it.
func waitQAD(t testing.TB, ctx context.Context, ep *Endpoint) netip.AddrPort {
	t.Helper()
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ep.LocalAddr().Port())
	for {
		rep, ok := ep.NetReport()
		if ok && rep.UDPv4 && rep.GlobalV4 == want {
			return want
		}
		select {
		case <-ctx.Done():
			t.Fatalf("NetReport = %+v (ok=%v), want UDPv4 with GlobalV4=%v", rep, ok, want)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestSelfHostedRelayDirectPath checks that two wildcard-bound endpoints that
// only share a self-hosted relay upgrade to a direct path using the
// QAD-discovered addresses.
func TestSelfHostedRelayDirectPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := newQADRelay(t)
	const alpn = "qad-test/0"
	a := r.bind(t, ctx, WithALPNs(alpn))
	b := r.bind(t, ctx)
	for _, ep := range []*Endpoint{a, b} {
		waitQAD(t, ctx, ep)
	}
	go func() {
		c, err := a.Accept(ctx)
		if err != nil {
			return
		}
		<-c.Context().Done()
	}()
	conn, err := b.Connect(ctx, netaddr.EndpointAddr{ID: a.ID()}.WithRelayURL(a.Addr().RelayURLs()[0]), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	for {
		for _, p := range conn.Paths() {
			if p.HasAddr && !p.Relayed {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no direct path; paths=%+v a=%v b=%v", conn.Paths(), a.Addr(), b.Addr())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
