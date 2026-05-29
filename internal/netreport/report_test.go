package netreport

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
)

func mustRelay(t *testing.T, s string) base.RelayUrl {
	t.Helper()
	u, err := base.ParseRelayUrl(s)
	if err != nil {
		t.Fatalf("parse relay url %q: %v", s, err)
	}
	return u
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestRelayLatenciesUpdateRelayKeepsMin(t *testing.T) {
	url := mustRelay(t, "https://relay.example/")
	var rl RelayLatencies

	rl.updateRelay(url, ms(100), ProbeHTTPS)
	rl.updateRelay(url, ms(50), ProbeHTTPS) // faster, should replace
	rl.updateRelay(url, ms(80), ProbeHTTPS) // slower, should not replace

	got, ok := rl.get(url)
	if !ok {
		t.Fatal("get: relay not found")
	}
	if got != ms(50) {
		t.Errorf("get = %v, want %v", got, ms(50))
	}
}

func TestRelayLatenciesGetMinAcrossProbes(t *testing.T) {
	url := mustRelay(t, "https://relay.example/")
	var rl RelayLatencies
	rl.updateRelay(url, ms(90), ProbeHTTPS)
	rl.updateRelay(url, ms(40), ProbeQADv4)
	rl.updateRelay(url, ms(70), ProbeQADv6)

	got, ok := rl.get(url)
	if !ok {
		t.Fatal("get: relay not found")
	}
	if got != ms(40) {
		t.Errorf("get = %v, want %v (min across probes)", got, ms(40))
	}
}

func TestRelayLatenciesMergeMinSemantics(t *testing.T) {
	url := mustRelay(t, "https://relay.example/")
	var a, b RelayLatencies
	a.updateRelay(url, ms(100), ProbeHTTPS)
	b.updateRelay(url, ms(60), ProbeHTTPS) // faster
	b.updateRelay(url, ms(30), ProbeQADv4)

	a.merge(&b)

	if got, _ := a.get(url); got != ms(30) {
		t.Errorf("after merge get = %v, want %v", got, ms(30))
	}
	if got := a.https[url.String()]; got != ms(60) {
		t.Errorf("after merge https = %v, want %v", got, ms(60))
	}
}

func TestReportUpdateProbeShape(t *testing.T) {
	urlA := mustRelay(t, "https://a.example/")
	urlB := mustRelay(t, "https://b.example/")

	tests := []struct {
		name   string
		probes []*probeReport
		check  func(t *testing.T, r *Report)
	}{
		{
			name: "https only records latency, no udp",
			probes: []*probeReport{
				{probe: ProbeHTTPS, relay: urlA, latency: ms(50)},
			},
			check: func(t *testing.T, r *Report) {
				if r.HasUDP() {
					t.Error("HasUDP = true, want false for HTTPS-only")
				}
				if r.GlobalV4.IsValid() || r.GlobalV6.IsValid() {
					t.Error("global addr set without QAD observed address")
				}
				if got, ok := r.RelayLatency.get(urlA); !ok || got != ms(50) {
					t.Errorf("latency = %v ok=%v, want 50ms", got, ok)
				}
			},
		},
		{
			name: "qad without observed addr is latency only (degraded)",
			probes: []*probeReport{
				{probe: ProbeQADv4, relay: urlA, latency: ms(20)}, // addr zero
			},
			check: func(t *testing.T, r *Report) {
				if r.UDPv4 {
					t.Error("UDPv4 = true, want false without observed-address extension")
				}
				if r.GlobalV4.IsValid() {
					t.Error("GlobalV4 set without observed address")
				}
				if got, ok := r.RelayLatency.get(urlA); !ok || got != ms(20) {
					t.Errorf("qad latency = %v ok=%v, want 20ms", got, ok)
				}
			},
		},
		{
			name: "qad with observed v4 addr sets global and udp",
			probes: []*probeReport{
				{probe: ProbeQADv4, relay: urlA, latency: ms(20),
					addr: netip.MustParseAddrPort("203.0.113.5:7842")},
			},
			check: func(t *testing.T, r *Report) {
				if !r.UDPv4 {
					t.Error("UDPv4 = false, want true with observed v4 addr")
				}
				if r.GlobalV4 != netip.MustParseAddrPort("203.0.113.5:7842") {
					t.Errorf("GlobalV4 = %v, want 203.0.113.5:7842", r.GlobalV4)
				}
			},
		},
		{
			name: "qad v4 observed addr canonicalizes mapped v6",
			probes: []*probeReport{
				{probe: ProbeQADv4, relay: urlA, latency: ms(20),
					addr: netip.MustParseAddrPort("[::ffff:203.0.113.9]:7842")},
			},
			check: func(t *testing.T, r *Report) {
				want := netip.MustParseAddrPort("203.0.113.9:7842")
				if r.GlobalV4 != want {
					t.Errorf("GlobalV4 = %v, want %v (canonicalized)", r.GlobalV4, want)
				}
			},
		},
		{
			name: "qad v4 mapping varies across relays",
			probes: []*probeReport{
				{probe: ProbeQADv4, relay: urlA, latency: ms(20),
					addr: netip.MustParseAddrPort("203.0.113.5:1")},
				{probe: ProbeQADv4, relay: urlB, latency: ms(25),
					addr: netip.MustParseAddrPort("198.51.100.7:2")},
			},
			check: func(t *testing.T, r *Report) {
				if r.MappingVariesByDestV4 == nil || !*r.MappingVariesByDestV4 {
					t.Errorf("MappingVariesByDestV4 = %v, want true", r.MappingVariesByDestV4)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Report{}
			for _, p := range tt.probes {
				r.update(p)
			}
			tt.check(t, r)
		})
	}
}

func TestCanonicalAddrPort(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"[::ffff:1.2.3.4]:99", "1.2.3.4:99"},
		{"1.2.3.4:99", "1.2.3.4:99"},
		{"[2001:db8::1]:99", "[2001:db8::1]:99"},
	}
	for _, tt := range tests {
		got := canonicalAddrPort(netip.MustParseAddrPort(tt.in))
		if got.String() != tt.want {
			t.Errorf("canonicalAddrPort(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}
