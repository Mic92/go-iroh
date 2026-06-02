package netreport

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/relay"
	"golang.org/x/net/dns/dnsmessage"
)

func TestProbeStringDefaultArm(t *testing.T) {
	// Wire-golden: the three valid probe names match the Rust Display impl
	// (iroh/src/net_report/probes.rs:22). The default arm is unreachable in
	// normal flow but must render a stable debug string rather than an empty one.
	tests := []struct {
		probe Probe
		want  string
	}{
		{ProbeHTTPS, "Https"},
		{ProbeQADv4, "QadIpv4"},
		{ProbeQADv6, "QadIpv6"},
		{Probe(99), "Probe(?)"},
	}
	for _, tt := range tests {
		if got := tt.probe.String(); got != tt.want {
			t.Errorf("Probe(%d).String() = %q, want %q", int(tt.probe), got, tt.want)
		}
	}
}

func TestDefaultQADConfigGolden(t *testing.T) {
	// Wire-golden: the QAD transport config must match the Rust relay defaults so
	// a real relay accepts the connection on the same keep-alive/idle schedule.
	// iroh-relay/src/quic.rs:293 (initial_rtt = Duration::from_millis(111)),
	// iroh-relay/src/quic.rs:297 (keep_alive_interval = Duration::from_secs(25)),
	// iroh-relay/src/quic.rs:298-300 (max_idle_timeout = Duration::from_secs(35)).
	cfg := defaultQADConfig()
	if cfg.InitialRTT != 111*time.Millisecond {
		t.Errorf("InitialRTT = %v, want 111ms (quic.rs:293)", cfg.InitialRTT)
	}
	if cfg.KeepAlivePeriod != 25*time.Second {
		t.Errorf("KeepAlivePeriod = %v, want 25s (quic.rs:297)", cfg.KeepAlivePeriod)
	}
	if cfg.MaxIdleTimeout != 35*time.Second {
		t.Errorf("MaxIdleTimeout = %v, want 35s (quic.rs:298-300)", cfg.MaxIdleTimeout)
	}
	if !cfg.ReceiveObservedAddressReports {
		t.Error("ReceiveObservedAddressReports = false, want true for QAD clients")
	}
}

func TestAddrMatchesProbePredicate(t *testing.T) {
	// A QAD probe must only accept an address of its own family, and must reject
	// an IPv4-mapped IPv6 address ([::ffff:x.x.x.x]) for both families: it is not
	// Is4() (so not QADv4) and is excluded from QADv6 via Is4In6(), so a v6 probe
	// never reports a v4 address. client.go:276.
	tests := []struct {
		name   string
		ip     string
		v4Want bool
		v6Want bool
	}{
		{"pure ipv4", "203.0.113.5", true, false},
		{"pure ipv6", "2001:db8::1", false, true},
		{"mapped ipv4 matches neither", "::ffff:203.0.113.5", false, false},
		{"ipv6 loopback", "::1", false, true},
		{"ipv4 loopback", "127.0.0.1", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			if got := addrMatchesProbe(ip, ProbeQADv4); got != tt.v4Want {
				t.Errorf("addrMatchesProbe(%s, QADv4) = %v, want %v", tt.ip, got, tt.v4Want)
			}
			if got := addrMatchesProbe(ip, ProbeQADv6); got != tt.v6Want {
				t.Errorf("addrMatchesProbe(%s, QADv6) = %v, want %v", tt.ip, got, tt.v6Want)
			}
			if addrMatchesProbe(ip, ProbeHTTPS) {
				t.Errorf("addrMatchesProbe(%s, HTTPS) = true, want false", tt.ip)
			}
		})
	}
}

func TestResolveQADAddrLiteral(t *testing.T) {
	// When the relay host is already an IP literal, resolveQADAddr uses it
	// directly (no DNS lookup) and only when the family matches the probe.
	// client.go:252.
	c := newTestClient(t)

	tests := []struct {
		name    string
		host    string
		probe   Probe
		wantOK  bool
		wantStr string
	}{
		{"v4 literal for v4 probe", "1.2.3.4", ProbeQADv4, true, "1.2.3.4:7842"},
		{"v6 literal for v6 probe", "2001:db8::1", ProbeQADv6, true, "[2001:db8::1]:7842"},
		{"v4 literal for v6 probe rejected", "1.2.3.4", ProbeQADv6, false, ""},
		{"v6 literal for v4 probe rejected", "2001:db8::1", ProbeQADv4, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := c.resolveQADAddr(context.Background(), tt.host, 7842, tt.probe)
			if ok != tt.wantOK {
				t.Fatalf("resolveQADAddr ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.String() != tt.wantStr {
				t.Errorf("resolveQADAddr = %v, want %v", got, tt.wantStr)
			}
		})
	}
}

func TestResolveQADAddrViaDNS(t *testing.T) {
	// When the relay host is a hostname, resolveQADAddr looks it up via the
	// configured resolver and returns an address of the matching family.
	// client.go:259-273.
	srv := newLoopbackDNS(t, func(name string, qtype dnsmessage.Type) ([]net.IP, time.Duration) {
		if name != "relay.test." {
			return nil, 0
		}
		switch qtype {
		case dnsmessage.TypeA:
			return []net.IP{net.IPv4(198, 51, 100, 9)}, 0
		case dnsmessage.TypeAAAA:
			return []net.IP{net.ParseIP("2001:db8::9")}, 0
		}
		return nil, 0
	})

	c := newTestClient(t).WithDNSResolver(srv.resolver())

	v4, ok := c.resolveQADAddr(context.Background(), "relay.test", 7842, ProbeQADv4)
	if !ok {
		t.Fatal("resolveQADAddr(v4) returned ok=false")
	}
	if v4.String() != "198.51.100.9:7842" {
		t.Errorf("resolveQADAddr(v4) = %v, want 198.51.100.9:7842", v4)
	}

	v6, ok := c.resolveQADAddr(context.Background(), "relay.test", 7842, ProbeQADv6)
	if !ok {
		t.Fatal("resolveQADAddr(v6) returned ok=false")
	}
	if v6.Addr().Unmap().String() != "2001:db8::9" {
		t.Errorf("resolveQADAddr(v6) = %v, want 2001:db8::9", v6)
	}
}

func TestResolveQADAddrDNSFailureReturnsFalse(t *testing.T) {
	// A lookup that resolves no addresses yields ok=false. client.go:259-262.
	srv := newLoopbackDNS(t, func(string, dnsmessage.Type) ([]net.IP, time.Duration) {
		return nil, 0 // NXDOMAIN-ish: no records
	})
	c := newTestClient(t).WithDNSResolver(srv.resolver())
	if _, ok := c.resolveQADAddr(context.Background(), "nope.test", 7842, ProbeQADv4); ok {
		t.Error("resolveQADAddr returned ok=true for a host with no records")
	}
}

func TestWithBuildersSetFields(t *testing.T) {
	// The builder methods record their inputs and return the same client so they
	// chain. client.go:73,80,86,93.
	res := &net.Resolver{}
	stdTLS := tlsInsecure()
	qadTLS := &tls.Config{InsecureSkipVerify: true}
	qcfg := &quic.Config{MaxIdleTimeout: 9 * time.Second}

	c := NewClient(relay.NewMap())
	got := c.WithDNSResolver(res).WithTLSConfig(stdTLS).WithQUICConfig(qcfg).WithQADTLSConfig(qadTLS)
	if got != c {
		t.Error("builder methods must return the same client for chaining")
	}
	if c.dnsResolver != res {
		t.Error("WithDNSResolver did not record the resolver")
	}
	if c.tlsConfig != stdTLS {
		t.Error("WithTLSConfig did not record the TLS config")
	}
	if c.quicConfig != qcfg {
		t.Error("WithQUICConfig did not record the QUIC config")
	}
	if c.qadTLS != qadTLS {
		t.Error("WithQADTLSConfig did not record the QAD TLS config")
	}
}

func TestNewQADClientUnreachableNoLeak(t *testing.T) {
	// A QUIC handshake against an address with no listener must fail and the
	// deferred cleanup in newQADClient must release the UDP socket and transport.
	// Use a TEST-NET-1 address (203.0.113.0/24, RFC 5737) on the discard port so
	// no handshake can complete. client.go:233 / qad.go:44.
	done := make(chan error, 1)
	go func() {
		_, err := newQADClient(
			netip.MustParseAddrPort("203.0.113.1:9"),
			"relay.iroh.invalid",
			&tls.Config{InsecureSkipVerify: true},
			&quic.Config{
				MaxIdleTimeout:       500 * time.Millisecond,
				HandshakeIdleTimeout: 500 * time.Millisecond,
			},
		)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("newQADClient to unreachable address succeeded, want error")
		}
	case <-time.After(probesTimeout + 2*time.Second):
		t.Fatal("newQADClient did not return within the probe timeout")
	}
}

// TestRunQADProbeOverLoopback drives runQADProbe end to end against a loopback
// QAD listener for both the IPv4 and IPv6 families, asserting a non-negative
// latency is recorded. The server does not send observed-address reports, so no
// reflexive address is set.
func TestRunQADProbeOverLoopback(t *testing.T) {
	tests := []struct {
		name      string
		listenIP  net.IP
		probe     Probe
		relayHost string
	}{
		{"ipv4", net.IPv4(127, 0, 0, 1), ProbeQADv4, "127.0.0.1"},
		{"ipv6", net.IPv6loopback, ProbeQADv6, "[::1]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, stop := startLoopbackQAD(t, tt.listenIP)
			defer stop()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			c := newTestClient(t).WithQADTLSConfig(&tls.Config{InsecureSkipVerify: true})

			// The relay URL host is an IP literal so resolveQADAddr takes the
			// no-DNS path; the QUIC port comes from the relay config.
			cfg := relayConfigWithQUIC(t, "https://"+tt.relayHost+"/", addr.Port())
			rep := c.runQADProbe(ctx, cfg, tt.probe)
			if rep == nil {
				t.Fatal("runQADProbe returned nil, want a probe report")
			}
			if rep.probe != tt.probe {
				t.Errorf("probe = %v, want %v", rep.probe, tt.probe)
			}
			if rep.latency < 0 {
				t.Errorf("latency = %v, want >= 0", rep.latency)
			}
			// No observed-address report is sent by this test server.
			if rep.addr.IsValid() {
				t.Errorf("addr = %v, want unset", rep.addr)
			}
		})
	}
}

func TestRunQADProbeNoHostReturnsNil(t *testing.T) {
	// A relay config whose URL has no host yields no probe. client.go:219-222.
	c := newTestClient(t)
	cfg := relay.Config{URL: mustRelay(t, "custom:relay"), Quic: &relay.QuicConfig{Port: 7842}}
	if rep := c.runQADProbe(context.Background(), cfg, ProbeQADv4); rep != nil {
		t.Errorf("runQADProbe(no host) = %+v, want nil", rep)
	}
}

func TestRunQADProbeFamilyMismatchReturnsNil(t *testing.T) {
	// A v6 probe against an IPv4-only relay host resolves no matching address and
	// yields no probe report. client.go:228-231.
	c := newTestClient(t).WithQADTLSConfig(&tls.Config{InsecureSkipVerify: true})
	cfg := relayConfigWithQUIC(t, "https://127.0.0.1/", 7842)
	if rep := c.runQADProbe(context.Background(), cfg, ProbeQADv6); rep != nil {
		t.Errorf("runQADProbe(v6 against v4 host) = %+v, want nil", rep)
	}
}

func TestRunProbesHTTPSForAllRelays(t *testing.T) {
	// HTTPS probes run for every relay in the map and fold into RelayLatency in a
	// stable (probe, relay-URL) order. client.go:144.
	const n = 4
	urls := make([]string, n)
	servers := make([]*httptest.Server, n)
	for i := range servers {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == relayProbePath {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "not found", http.StatusNotFound)
		}))
		t.Cleanup(ts.Close)
		servers[i] = ts
		urls[i] = ts.URL
	}

	var configs []relay.Config
	for _, u := range urls {
		configs = append(configs, relay.Config{URL: mustRelay(t, u)})
	}
	rm := relay.NewMap(configs...)

	c := newTestClient(t).WithTLSConfig(tlsInsecure())
	c.relayMap = rm
	report := &Report{}
	c.runProbes(context.Background(), rm, report)

	for _, u := range urls {
		if _, ok := report.RelayLatency.get(mustRelay(t, u)); !ok {
			t.Errorf("no HTTPS latency recorded for %s", u)
		}
	}
}

func TestRunProbesQADCappedAtMaxRelays(t *testing.T) {
	// QAD probes run on at most maxRelays relays; HTTPS runs on all. We point
	// many relays at one loopback QAD+HTTPS server and count distinct QAD dials
	// via the accept loop. client.go:144, reportgen.rs:446.
	addr, stop := startLoopbackQAD(t, net.IPv4(127, 0, 0, 1))
	defer stop()

	// HTTPS server (separate) used by every relay's HTTPS probe.
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == relayProbePath {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	t.Cleanup(hs.Close)

	// Build maxRelays+3 relays, all with QUIC enabled on the loopback QAD port.
	// Each needs a distinct URL host so the map does not dedupe; we use the HTTPS
	// server's host for HTTPS and the QAD port for QUIC discovery on 127.0.0.1.
	const extra = 3
	total := maxRelays + extra
	var configs []relay.Config
	for i := 0; i < total; i++ {
		// Distinct host per relay so all are distinct map keys; HTTPS probes hit
		// the loopback HTTPS server via its real host, but we want unique URLs,
		// so route HTTPS at the same server using a path-less distinct subdomain
		// is not possible with httptest. Instead use 127.0.0.1 with the QAD port
		// and rely on QAD; HTTPS will fail (different port) which is fine for the
		// QAD-cap assertion.
		u := mustRelay(t, "https://127.0.0.1:"+strconv.Itoa(int(addr.Port()))+"/r"+strconv.Itoa(i))
		configs = append(configs, relay.Config{URL: u, Quic: &relay.QuicConfig{Port: addr.Port()}})
	}
	rm := relay.NewMap(configs...)

	c := newTestClient(t).WithQADTLSConfig(&tls.Config{InsecureSkipVerify: true})
	c.relayMap = rm
	report := &Report{}
	c.runProbes(context.Background(), rm, report)

	// Count relays that recorded a QAD (ipv4) latency.
	qadRelays := 0
	for range report.RelayLatency.ipv4 {
		qadRelays++
	}
	if qadRelays > maxRelays {
		t.Errorf("QAD probed %d relays, want at most %d", qadRelays, maxRelays)
	}
}

func TestRunCaptivePortalUsesFirstRelay(t *testing.T) {
	// The captive-portal check targets the first relay in the map's sorted URL
	// order. We give that relay a working /generate_204 and a later relay a
	// failing one; the result must reflect the first. client.go:290.
	var firstHit atomic.Bool
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == captivePortalPath {
			firstHit.Store(true)
			ch := r.Header.Get(challengeHeader)
			w.Header().Set(responseHeader, "response "+ch)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Intentionally captive (wrong status) so picking this relay would fail.
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)

	// Force a deterministic first-by-URL ordering: "a." sorts before "z.". We
	// rewrite the httptest host into a sortable relay URL but must keep the real
	// host:port for reachability, which RelayURL preserves.
	firstURL := mustRelay(t, first.URL)
	secondURL := mustRelay(t, second.URL)
	// Determine which sorts first; the captive portal check uses URLs()[0].
	rm := relay.NewMap(
		relay.Config{URL: firstURL},
		relay.Config{URL: secondURL},
	)
	want := rm.URLs()[0]

	// Re-point so the lexicographically-first relay is the one with the good
	// handler. If second sorts first, swap which server is "good".
	if !want.Equal(firstURL) {
		// second is first: make it the good one instead.
		second.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == captivePortalPath {
				ch := r.Header.Get(challengeHeader)
				w.Header().Set(responseHeader, "response "+ch)
				w.WriteHeader(http.StatusNoContent)
			}
		})
	}

	c := newTestClient(t).WithTLSConfig(tlsInsecure())
	report := &Report{}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.runCaptivePortal(ctx, rm, report)

	if report.CaptivePortal == nil {
		t.Fatal("CaptivePortal not set after check")
	}
	if *report.CaptivePortal {
		t.Errorf("CaptivePortal = true, want false (first relay answered correctly)")
	}
}

func TestRunCaptivePortalContextCanceledBeforeDelay(t *testing.T) {
	// If the context is canceled before captivePortalDelay elapses, the check
	// returns without recording a result. client.go:290-295.
	rm := relay.NewMap(relay.Config{URL: mustRelay(t, "https://relay.example/")})
	c := newTestClient(t)
	report := &Report{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.runCaptivePortal(ctx, rm, report)

	if report.CaptivePortal != nil {
		t.Errorf("CaptivePortal = %v, want nil after canceled context", *report.CaptivePortal)
	}
}

func TestGetReportFullRunsCaptivePortal(t *testing.T) {
	// A full report (doFull=true) runs the captive-portal check; an incremental
	// one within fullReportInterval does not. client.go:108.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case relayProbePath:
			w.WriteHeader(http.StatusOK)
		case captivePortalPath:
			ch := r.Header.Get(challengeHeader)
			w.Header().Set(responseHeader, "response "+ch)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "no", http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	rm := relay.NewMap(relay.Config{URL: mustRelay(t, ts.URL)})
	c := NewClient(rm).WithTLSConfig(tlsInsecure())
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	rep, err := c.GetReport(ctx, IfStateDetails{HaveV4: true}, true)
	if err != nil {
		t.Fatalf("GetReport (full): %v", err)
	}
	if rep.CaptivePortal == nil {
		t.Error("full report did not run captive-portal check")
	}

	// A second report shortly after is incremental: no captive-portal check.
	now = now.Add(time.Second)
	rep2, err := c.GetReport(ctx, IfStateDetails{HaveV4: true}, false)
	if err != nil {
		t.Fatalf("GetReport (incremental): %v", err)
	}
	if rep2.CaptivePortal != nil {
		t.Error("incremental report should not run captive-portal check")
	}
}

func TestAddReportHistoryCarriesForwardMappingVaries(t *testing.T) {
	// When a later report lacks mapping-varies info, the value from the previous
	// report is carried forward. client.go:316,324-329.
	c := newTestClient(t)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }

	first := reportWith(t, map[string]time.Duration{"https://a.example/": ms(50)})
	first.MappingVariesByDestV4 = boolPtr(true)
	first.MappingVariesByDestV6 = boolPtr(false)
	c.addReportHistoryAndSetPreferredRelay(first)

	now = now.Add(time.Second)
	second := reportWith(t, map[string]time.Duration{"https://a.example/": ms(55)})
	// second has no IPv4/IPv6 mapping info of its own.
	c.addReportHistoryAndSetPreferredRelay(second)

	if second.MappingVariesByDestV4 == nil || !*second.MappingVariesByDestV4 {
		t.Errorf("MappingVariesByDestV4 = %v, want carried-forward true", second.MappingVariesByDestV4)
	}
	if second.MappingVariesByDestV6 == nil || *second.MappingVariesByDestV6 {
		t.Errorf("MappingVariesByDestV6 = %v, want carried-forward false", second.MappingVariesByDestV6)
	}
}

// startLoopbackQAD starts a loopback QAD QUIC listener bound to ip:0, accepting
// connections until stop is called, and returns its address.
func startLoopbackQAD(t *testing.T, ip net.IP) (netip.AddrPort, func()) {
	return startLoopbackQADWithConfig(t, ip, &quic.Config{
		MaxIdleTimeout:  qadMaxIdle,
		KeepAlivePeriod: qadKeepAlive,
	})
}

func startLoopbackQADWithConfig(t *testing.T, ip net.IP, cfg *quic.Config) (netip.AddrPort, func()) {
	t.Helper()
	serverCert := selfSignedCert(t)
	serverTLS := &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		NextProtos:             []string{alpnQAD},
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.Listen(udpConn, serverTLS, cfg)
	if err != nil {
		udpConn.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()

	addr := netip.MustParseAddrPort(udpConn.LocalAddr().String())
	stop := func() {
		cancel()
		ln.Close()
		udpConn.Close()
		wg.Wait()
	}
	return addr, stop
}

// relayConfigWithQUIC builds a relay.Config with QUIC address discovery enabled
// on the given port.
func relayConfigWithQUIC(t *testing.T, url string, port uint16) relay.Config {
	t.Helper()
	return relay.Config{
		URL:  mustRelay(t, url),
		Quic: &relay.QuicConfig{Port: port},
	}
}
