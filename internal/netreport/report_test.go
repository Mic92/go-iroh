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

func TestReportUpdateRejectsFamilyMismatch(t *testing.T) {
	// A QAD probe must reject an observed address of the wrong family rather
	// than record it: an IPv4 QAD that observes IPv6 (and vice versa) is a relay
	// or path bug and must not set UDPvN or GlobalvN. report.rs:68.
	urlA := mustRelay(t, "https://a.example/")

	tests := []struct {
		name  string
		probe Probe
		addr  string
	}{
		{"v4 probe rejects v6 addr", ProbeQADv4, "[2001:db8::1]:7842"},
		{"v6 probe rejects v4 addr", ProbeQADv6, "203.0.113.5:7842"},
		{"v6 probe rejects mapped v4 addr", ProbeQADv6, "[::ffff:203.0.113.5]:7842"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Report{}
			r.update(&probeReport{
				probe:   tt.probe,
				relay:   urlA,
				latency: ms(20),
				addr:    netip.MustParseAddrPort(tt.addr),
			})
			if r.UDPv4 {
				t.Error("UDPv4 = true, want false after family-mismatched probe")
			}
			if r.UDPv6 {
				t.Error("UDPv6 = true, want false after family-mismatched probe")
			}
			if r.GlobalV4.IsValid() {
				t.Errorf("GlobalV4 = %v, want unset after family mismatch", r.GlobalV4)
			}
			if r.GlobalV6.IsValid() {
				t.Errorf("GlobalV6 = %v, want unset after family mismatch", r.GlobalV6)
			}
			// Latency is still recorded even when the address is rejected.
			if got, ok := r.RelayLatency.get(urlA); !ok || got != ms(20) {
				t.Errorf("latency = %v ok=%v, want 20ms recorded", got, ok)
			}
		})
	}
}

func TestReportUpdateV6ObservedAddr(t *testing.T) {
	// Mirror of the v4 happy path in TestReportUpdateProbeShape for the v6 arm,
	// which is otherwise unexercised. report.rs:94.
	urlA := mustRelay(t, "https://a.example/")
	urlB := mustRelay(t, "https://b.example/")

	r := &Report{}
	r.update(&probeReport{probe: ProbeQADv6, relay: urlA, latency: ms(20),
		addr: netip.MustParseAddrPort("[2001:db8::1]:7842")})
	if !r.UDPv6 {
		t.Error("UDPv6 = false, want true with observed v6 addr")
	}
	if r.GlobalV6 != netip.MustParseAddrPort("[2001:db8::1]:7842") {
		t.Errorf("GlobalV6 = %v, want 2001:db8::1", r.GlobalV6)
	}
	if r.MappingVariesByDestV6 != nil {
		t.Errorf("MappingVariesByDestV6 = %v, want nil after a single relay", r.MappingVariesByDestV6)
	}

	// Same address from a second relay: mapping does not vary.
	r.update(&probeReport{probe: ProbeQADv6, relay: urlB, latency: ms(25),
		addr: netip.MustParseAddrPort("[2001:db8::1]:7842")})
	if r.MappingVariesByDestV6 == nil || *r.MappingVariesByDestV6 {
		t.Errorf("MappingVariesByDestV6 = %v, want false (same addr)", r.MappingVariesByDestV6)
	}

	// A different address from a third relay flips it to varying.
	urlC := mustRelay(t, "https://c.example/")
	r.update(&probeReport{probe: ProbeQADv6, relay: urlC, latency: ms(30),
		addr: netip.MustParseAddrPort("[2001:db8::2]:7842")})
	if r.MappingVariesByDestV6 == nil || !*r.MappingVariesByDestV6 {
		t.Errorf("MappingVariesByDestV6 = %v, want true (differing addr)", r.MappingVariesByDestV6)
	}
}

func TestRelayLatenciesMergeAcrossRelaysAndProbes(t *testing.T) {
	// merge keeps the per-(relay,probe) minimum across two RelayLatencies, for
	// every probe bucket and for relays present in only one side. report.rs:155.
	urlA := mustRelay(t, "https://a.example/")
	urlB := mustRelay(t, "https://b.example/")

	var a, b RelayLatencies
	a.updateRelay(urlA, ms(100), ProbeHTTPS)
	a.updateRelay(urlA, ms(80), ProbeQADv4)
	a.updateRelay(urlA, ms(90), ProbeQADv6)

	b.updateRelay(urlA, ms(60), ProbeHTTPS) // faster https
	b.updateRelay(urlA, ms(95), ProbeQADv4) // slower v4 (keep a's 80)
	b.updateRelay(urlA, ms(50), ProbeQADv6) // faster v6
	b.updateRelay(urlB, ms(40), ProbeHTTPS) // only in b

	a.merge(&b)

	if got := a.https[urlA.String()]; got != ms(60) {
		t.Errorf("merged https[A] = %v, want 60ms", got)
	}
	if got := a.ipv4[urlA.String()]; got != ms(80) {
		t.Errorf("merged ipv4[A] = %v, want 80ms (kept minimum)", got)
	}
	if got := a.ipv6[urlA.String()]; got != ms(50) {
		t.Errorf("merged ipv6[A] = %v, want 50ms", got)
	}
	if got := a.https[urlB.String()]; got != ms(40) {
		t.Errorf("merged https[B] = %v, want 40ms (relay only in other)", got)
	}
}

func TestRelayLatenciesRelaysDeduplicates(t *testing.T) {
	// relays() returns each relay once even when it has latencies under several
	// probe buckets. report.rs:189.
	urlA := mustRelay(t, "https://a.example/")
	urlB := mustRelay(t, "https://b.example/")

	var rl RelayLatencies
	rl.updateRelay(urlA, ms(10), ProbeHTTPS)
	rl.updateRelay(urlA, ms(20), ProbeQADv4) // same relay, different bucket
	rl.updateRelay(urlA, ms(30), ProbeQADv6) // same relay, third bucket
	rl.updateRelay(urlB, ms(40), ProbeHTTPS)

	relays := rl.relays()
	if len(relays) != 2 {
		t.Fatalf("relays() returned %d entries, want 2 (deduplicated): %v", len(relays), relays)
	}
	seen := map[string]int{}
	for _, u := range relays {
		seen[u.String()]++
	}
	if seen[urlA.String()] != 1 {
		t.Errorf("relay A appears %d times, want once", seen[urlA.String()])
	}
	if seen[urlB.String()] != 1 {
		t.Errorf("relay B appears %d times, want once", seen[urlB.String()])
	}
}

func TestRelayLatenciesBucketDefault(t *testing.T) {
	// An unknown probe constant falls back to the https bucket rather than
	// panicking or returning nil. report.rs:204 (default case).
	var rl RelayLatencies
	unknown := Probe(99)

	m := rl.bucket(unknown, true)
	if m == nil {
		t.Fatal("bucket(unknown, create) returned nil, want the https map")
	}
	m["k"] = ms(1)
	if rl.https["k"] != ms(1) {
		t.Error("default bucket is not the https bucket")
	}
}

func TestRelayLatenciesIsEmpty(t *testing.T) {
	var rl RelayLatencies
	if !rl.isEmpty() {
		t.Error("zero RelayLatencies should be empty")
	}
	rl.updateRelay(mustRelay(t, "https://a.example/"), ms(10), ProbeHTTPS)
	if rl.isEmpty() {
		t.Error("RelayLatencies with an entry should not be empty")
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
