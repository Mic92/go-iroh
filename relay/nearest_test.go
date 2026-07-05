package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

func testURL(t *testing.T, s string) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(s)
	if err != nil {
		t.Fatalf("ParseRelayURL(%q): %v", s, err)
	}
	return u
}

// fakeProber returns latencies keyed by relay host, and an error for any host
// present in fails. It models distinct RTTs without touching the network.
func fakeProber(latency map[string]time.Duration, fails map[string]bool) Prober {
	return func(ctx context.Context, u netaddr.RelayURL) (time.Duration, error) {
		if fails[u.Host()] {
			return 0, errors.New("unreachable")
		}
		d, ok := latency[u.Host()]
		if !ok {
			return 0, errors.New("no latency for host")
		}
		return d, nil
	}
}

func TestNearestPicksFastest(t *testing.T) {
	// Mirrors the production case: an AP relay is slow, a US-West relay is
	// ~2.7x closer, and selection must prefer the closer one.
	m := MapFromURLs(
		testURL(t, "https://aps1-1.relay.example."),
		testURL(t, "https://usw1-1.relay.example."),
		testURL(t, "https://use1-1.relay.example."),
	)
	prober := fakeProber(map[string]time.Duration{
		"aps1-1.relay.example.": 319 * time.Millisecond,
		"usw1-1.relay.example.": 117 * time.Millisecond,
		"use1-1.relay.example.": 190 * time.Millisecond,
	}, nil)

	got, err := m.Nearest(context.Background(), prober)
	if err != nil {
		t.Fatalf("Nearest: %v", err)
	}
	if want := "usw1-1.relay.example."; got.Host() != want {
		t.Errorf("Nearest = %s, want host %s", got, want)
	}
}

func TestRankByLatencyOrder(t *testing.T) {
	m := MapFromURLs(
		testURL(t, "https://a.relay.example."),
		testURL(t, "https://b.relay.example."),
		testURL(t, "https://c.relay.example."),
	)
	prober := fakeProber(map[string]time.Duration{
		"a.relay.example.": 300 * time.Millisecond,
		"b.relay.example.": 100 * time.Millisecond,
		"c.relay.example.": 200 * time.Millisecond,
	}, nil)

	ranked := RankByLatency(context.Background(), m, prober)
	wantHosts := []string{"b.relay.example.", "c.relay.example.", "a.relay.example."}
	if len(ranked) != len(wantHosts) {
		t.Fatalf("got %d results, want %d", len(ranked), len(wantHosts))
	}
	for i, want := range wantHosts {
		if got := ranked[i].URL.Host(); got != want {
			t.Errorf("rank[%d] = %s, want %s", i, got, want)
		}
		if ranked[i].Err != nil {
			t.Errorf("rank[%d] host %s: unexpected err %v", i, want, ranked[i].Err)
		}
	}
}

func TestRankSortsUnreachableLast(t *testing.T) {
	m := MapFromURLs(
		testURL(t, "https://dead.relay.example."),
		testURL(t, "https://slow.relay.example."),
		testURL(t, "https://fast.relay.example."),
	)
	prober := fakeProber(map[string]time.Duration{
		"slow.relay.example.": 250 * time.Millisecond,
		"fast.relay.example.": 50 * time.Millisecond,
	}, map[string]bool{"dead.relay.example.": true})

	ranked := RankByLatency(context.Background(), m, prober)
	// Reachable, ascending latency, then unreachable.
	wantHosts := []string{"fast.relay.example.", "slow.relay.example.", "dead.relay.example."}
	for i, want := range wantHosts {
		if got := ranked[i].URL.Host(); got != want {
			t.Errorf("rank[%d] = %s, want %s", i, got, want)
		}
	}
	if ranked[2].Err == nil {
		t.Errorf("expected unreachable relay to carry an error")
	}
	// Nearest must skip the unreachable relay and pick the fastest reachable one.
	got, err := m.Nearest(context.Background(), prober)
	if err != nil {
		t.Fatalf("Nearest: %v", err)
	}
	if want := "fast.relay.example."; got.Host() != want {
		t.Errorf("Nearest = %s, want %s", got, want)
	}
}

func TestNearestTieBreakIsDeterministic(t *testing.T) {
	// Equal latencies must break ties by URL order, so repeated selection is
	// reproducible rather than depending on goroutine scheduling.
	m := MapFromURLs(
		testURL(t, "https://z.relay.example."),
		testURL(t, "https://a.relay.example."),
		testURL(t, "https://m.relay.example."),
	)
	prober := fakeProber(map[string]time.Duration{
		"z.relay.example.": 100 * time.Millisecond,
		"a.relay.example.": 100 * time.Millisecond,
		"m.relay.example.": 100 * time.Millisecond,
	}, nil)

	for i := 0; i < 20; i++ {
		got, err := m.Nearest(context.Background(), prober)
		if err != nil {
			t.Fatalf("Nearest: %v", err)
		}
		if want := "a.relay.example."; got.Host() != want {
			t.Fatalf("iteration %d: Nearest = %s, want %s (tie must break by URL)", i, got, want)
		}
	}
}

func TestNearestAllUnreachable(t *testing.T) {
	m := MapFromURLs(
		testURL(t, "https://a.relay.example."),
		testURL(t, "https://b.relay.example."),
	)
	prober := fakeProber(nil, map[string]bool{
		"a.relay.example.": true,
		"b.relay.example.": true,
	})
	if _, err := m.Nearest(context.Background(), prober); !errors.Is(err, ErrNoRelays) {
		t.Errorf("Nearest err = %v, want ErrNoRelays", err)
	}
}

func TestNearestEmptyMap(t *testing.T) {
	m := NewMap()
	if _, err := m.Nearest(context.Background(), fakeProber(nil, nil)); !errors.Is(err, ErrNoRelays) {
		t.Errorf("Nearest on empty map err = %v, want ErrNoRelays", err)
	}
}

func TestPreferNearestReducesMap(t *testing.T) {
	m := MapFromURLs(
		testURL(t, "https://aps1.relay.example."),
		testURL(t, "https://usw1.relay.example."),
	)
	prober := fakeProber(map[string]time.Duration{
		"aps1.relay.example.": 319 * time.Millisecond,
		"usw1.relay.example.": 117 * time.Millisecond,
	}, nil)

	got, err := m.PreferNearest(context.Background(), prober)
	if err != nil {
		t.Fatalf("PreferNearest: %v", err)
	}
	if got.Len() != 1 {
		t.Fatalf("PreferNearest map len = %d, want 1", got.Len())
	}
	if !got.Contains(testURL(t, "https://usw1.relay.example.")) {
		t.Errorf("PreferNearest kept %v, want usw1", got.URLs())
	}
	// Original map is unchanged.
	if m.Len() != 2 {
		t.Errorf("source map mutated: len = %d, want 2", m.Len())
	}
}
