package socket

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func v4Addr(port uint16) Addr {
	return IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port))
}

func v6Addr(port uint16) Addr {
	return IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), port))
}

func relayAddr(t *testing.T, host string) Addr {
	t.Helper()
	u, err := netaddr.ParseRelayUrl("https://" + host)
	if err != nil {
		t.Fatalf("parse relay url: %v", err)
	}
	var eid key.EndpointId
	return RelayAddr(u, eid)
}

func cand(a Addr, rttMs int) PathCandidate {
	return PathCandidate{Addr: a, RTT: time.Duration(rttMs) * time.Millisecond}
}

// selectAddr runs the default selector and returns the selected address string,
// or "" when nothing is selected (keep current).
func selectAddr(current *Addr, cands []PathCandidate) string {
	a, ok := BiasedRttPathSelector{}.Select(current, cands)
	if !ok {
		return ""
	}
	return a.String()
}

// TestPathSelectorIPv6Bias mirrors the Rust ipv6_wins_over_ipv4_within_bias test
// (biased_rtt_path_selector.rs:246).
func TestPathSelectorIPv6Bias(t *testing.T) {
	v4 := v4Addr(1)
	v6 := v6Addr(1)

	tests := []struct {
		name   string
		v4ms   int
		v6ms   int
		wantV6 bool
	}{
		{"equal rtt: ipv6 wins by bias", 10, 10, true},
		{"ipv6 2ms slower still wins (within 3ms bias)", 10, 12, true},
		{"ipv6 10ms slower loses (exceeds 3ms bias)", 10, 20, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectAddr(nil, []PathCandidate{cand(v4, tt.v4ms), cand(v6, tt.v6ms)})
			want := v4.String()
			if tt.wantV6 {
				want = v6.String()
			}
			if got != want {
				t.Errorf("selected %q, want %q", got, want)
			}
		})
	}
}

// TestPathSelectorPrimaryBeatsBackup mirrors
// primary_wins_over_backup_regardless_of_rtt (biased_rtt_path_selector.rs:264).
func TestPathSelectorPrimaryBeatsBackup(t *testing.T) {
	v4 := v4Addr(1)
	relay := relayAddr(t, "relay1.iroh.computer")

	tests := []struct {
		name string
		v4ms int
		rlms int
	}{
		{"primary 100ms beats backup 10ms", 100, 10},
		{"primary 1000ms beats backup 1ms", 1000, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectAddr(nil, []PathCandidate{cand(v4, tt.v4ms), cand(relay, tt.rlms)})
			if got != v4.String() {
				t.Errorf("selected %q, want the primary IP path %q", got, v4.String())
			}
		})
	}
}

// TestPathSelectorSameTierThreshold mirrors
// same_tier_only_switches_with_significant_rtt_diff
// (biased_rtt_path_selector.rs:284). The switch condition is `best+5ms <= cur`.
func TestPathSelectorSameTierThreshold(t *testing.T) {
	v1 := v4Addr(1)
	v2 := v4Addr(2)

	tests := []struct {
		name       string
		curMs      int
		newMs      int
		wantSwitch bool
	}{
		{"2ms diff < 5ms threshold: keep current", 20, 18, false},
		{"4ms diff < 5ms: keep current", 20, 16, false},
		{"5ms diff hits threshold (<=): switch", 20, 15, true},
		{"6ms diff > 5ms: switch", 20, 14, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cur := v1
			got := selectAddr(&cur, []PathCandidate{cand(v1, tt.curMs), cand(v2, tt.newMs)})
			if tt.wantSwitch {
				if got != v2.String() {
					t.Errorf("selected %q, want switch to %q", got, v2.String())
				}
			} else if got != "" {
				t.Errorf("selected %q, want no switch", got)
			}
		})
	}
}

// TestPathSelectorNoCurrentSelectsBest mirrors no_current_path_selects_best
// (biased_rtt_path_selector.rs:305).
func TestPathSelectorNoCurrentSelectsBest(t *testing.T) {
	v1 := v4Addr(1)
	v2 := v4Addr(2)
	got := selectAddr(nil, []PathCandidate{cand(v1, 20), cand(v2, 10)})
	if got != v2.String() {
		t.Errorf("selected %q, want lowest-RTT %q", got, v2.String())
	}
}

// TestPathSelectorEmpty mirrors empty_paths_returns_none
// (biased_rtt_path_selector.rs:313).
func TestPathSelectorEmpty(t *testing.T) {
	if got := selectAddr(nil, nil); got != "" {
		t.Errorf("no current, no candidates: selected %q, want none", got)
	}
	v1 := v4Addr(1)
	if got := selectAddr(&v1, nil); got != "" {
		t.Errorf("current set, no candidates: selected %q, want keep current", got)
	}
}

// TestPathSelectorCrossTierImmediate verifies an immediate switch across tiers:
// a current relay (backup) path yields to any primary path regardless of the
// 5ms same-tier threshold.
func TestPathSelectorCrossTierImmediate(t *testing.T) {
	relay := relayAddr(t, "relay1.iroh.computer")
	v4 := v4Addr(1)
	// Current is the relay; a primary path appears with a worse raw RTT.
	cur := relay
	got := selectAddr(&cur, []PathCandidate{cand(relay, 1), cand(v4, 100)})
	if got != v4.String() {
		t.Errorf("selected %q, want immediate cross-tier switch to %q", got, v4.String())
	}
}
