package socket

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// ipPath returns a distinct IP candidate path keyed by index.
func ipPath(i int) Addr {
	return IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 9))
}

// relayPath returns a distinct relay candidate path keyed by index. Distinct
// relay URLs guarantee distinct path keys without needing valid curve-point
// endpoint ids.
func relayPath(t *testing.T, i int) Addr {
	t.Helper()
	u, err := netaddr.ParseRelayURL(fmt.Sprintf("https://relay%d.localhost", i))
	if err != nil {
		t.Fatal(err)
	}
	var eid key.EndpointID
	return RelayAddr(u, eid)
}

func TestPrune(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name  string
		build func(p *RemotePathState)
		want  int // expected path count after Prune
	}{
		{
			name: "under limit: no prune",
			build: func(p *RemotePathState) {
				for i := 0; i < MaxNonRelayPaths-1; i++ {
					p.SetOpen(ipPath(i))
				}
			},
			want: MaxNonRelayPaths - 1,
		},
		{
			name: "all open at limit: keep all (open never pruned)",
			build: func(p *RemotePathState) {
				for i := 0; i < MaxNonRelayPaths; i++ {
					p.SetOpen(ipPath(i))
				}
			},
			want: MaxNonRelayPaths,
		},
		{
			name: "unusable paths pruned down to open ones",
			build: func(p *RemotePathState) {
				// 5 open, then enough unusable to exceed the limit.
				for i := 0; i < 5; i++ {
					p.SetOpen(ipPath(i))
				}
				for i := 5; i < MaxNonRelayPaths+10; i++ {
					p.SetUnusable(ipPath(i))
				}
			},
			want: 5, // only the open paths survive
		},
		{
			name: "keep MAX_INACTIVE most-recent inactive, prune older",
			build: func(p *RemotePathState) {
				// 20 open paths (kept), plus 15 inactive paths closed at
				// increasing times. Prune keeps the 10 most-recently closed.
				for i := 0; i < 20; i++ {
					p.SetOpen(ipPath(i))
				}
				for i := 20; i < 35; i++ {
					a := ipPath(i)
					p.SetOpen(a)
					p.SetClosed(a, now.Add(time.Duration(i)*time.Second))
				}
			},
			want: 20 + MaxInactiveNonRelayPaths, // 20 open + 10 inactive kept
		},
		{
			name: "all failed: keep MAX_NON_RELAY_PATHS, do not prune all",
			build: func(p *RemotePathState) {
				for i := 0; i < MaxNonRelayPaths+5; i++ {
					p.SetUnusable(ipPath(i))
				}
			},
			want: MaxNonRelayPaths,
		},
		{
			name: "relay paths never counted or pruned",
			build: func(p *RemotePathState) {
				// 25 IP paths (under the non-relay limit) plus 10 relay paths.
				for i := 0; i < 25; i++ {
					p.SetOpen(ipPath(i))
				}
				for i := 0; i < 10; i++ {
					// Same relay URL, zero eid: only one distinct relay path. Use
					// distinct relay keys by varying the eid via valid keys.
					p.SetOpen(relayPath(t, i))
				}
			},
			// Non-relay count is 25 < limit, so no pruning happens.
			want: -1, // checked specially below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewRemotePathState()
			tt.build(p)
			before := p.Len()
			p.Prune()
			got := p.Len()
			if tt.want == -1 {
				// "no prune" case: count unchanged.
				if got != before {
					t.Errorf("prune changed count from %d to %d, want unchanged", before, got)
				}
				return
			}
			if got != tt.want {
				t.Errorf("after prune: %d paths, want %d", got, tt.want)
			}
		})
	}
}

// TestPruneNeverDropsRelay asserts relay paths survive a prune that removes
// non-relay paths.
func TestPruneNeverDropsRelay(t *testing.T) {
	p := NewRemotePathState()
	relay := relayPath(t, 0)
	p.SetOpen(relay)
	// Add enough unusable non-relay paths to trigger a prune.
	for i := 0; i < MaxNonRelayPaths+5; i++ {
		p.SetUnusable(ipPath(i))
	}
	p.Prune()
	if _, ok := p.Status(relay); !ok {
		t.Error("relay path was pruned; relay paths must never be pruned")
	}
}

// TestStatusTransitions checks the open -> inactive -> unusable lifecycle.
func TestStatusTransitions(t *testing.T) {
	p := NewRemotePathState()
	a := ipPath(1)

	p.SetOpen(a)
	if s, _ := p.Status(a); s != PathStatusOpen {
		t.Fatalf("after SetOpen: %v, want open", s)
	}
	p.SetClosed(a, time.Now())
	if s, _ := p.Status(a); s != PathStatusInactive {
		t.Fatalf("after SetClosed from open: %v, want inactive", s)
	}
	// Closing an unknown path that is already unusable stays unusable.
	b := ipPath(2)
	p.Add(b) // unknown
	p.SetClosed(b, time.Now())
	if s, _ := p.Status(b); s != PathStatusUnusable {
		t.Fatalf("after SetClosed from unknown: %v, want unusable", s)
	}
}

func TestOpenAddrs(t *testing.T) {
	p := NewRemotePathState()
	open2 := ipPath(2)
	open1 := ipPath(1)
	inactive := ipPath(3)
	unknown := ipPath(4)
	unusable := ipPath(5)

	p.SetOpen(open2)
	p.SetOpen(open1)
	p.SetOpen(inactive)
	p.SetClosed(inactive, time.Now())
	p.Add(unknown)
	p.SetUnusable(unusable)

	got := p.OpenAddrs()
	if len(got) != 2 {
		t.Fatalf("OpenAddrs len = %d, want 2: %v", len(got), got)
	}
	if got[0].String() != open1.String() || got[1].String() != open2.String() {
		t.Fatalf("OpenAddrs = %v, want sorted [%v %v]", got, open1, open2)
	}
}

func TestExpireIdleUsesPathTimeouts(t *testing.T) {
	now := time.Unix(1000, 0)
	direct := ipPath(1)
	relay := relayPath(t, 0)

	p := NewRemotePathState()
	p.SetOpenAt(direct, now)
	p.SetOpenAt(relay, now)

	if closed := p.ExpireIdle(now.Add(PathMaxIdleTimeout - time.Nanosecond)); len(closed) != 0 {
		t.Fatalf("ExpireIdle before direct timeout closed %v, want none", closed)
	}
	closed := p.ExpireIdle(now.Add(PathMaxIdleTimeout))
	if len(closed) != 1 || closed[0].String() != direct.String() {
		t.Fatalf("ExpireIdle at direct timeout closed %v, want [%v]", closed, direct)
	}
	if s, _ := p.Status(direct); s != PathStatusInactive {
		t.Fatalf("direct status = %v, want inactive", s)
	}
	if s, _ := p.Status(relay); s != PathStatusOpen {
		t.Fatalf("relay status = %v, want open", s)
	}

	closed = p.ExpireIdle(now.Add(RelayPathMaxIdleTimeout))
	if len(closed) != 1 || closed[0].String() != relay.String() {
		t.Fatalf("ExpireIdle at relay timeout closed %v, want [%v]", closed, relay)
	}
	if s, _ := p.Status(relay); s != PathStatusInactive {
		t.Fatalf("relay status = %v, want inactive", s)
	}
}
