package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// A Prober measures the connect latency to a single relay. It returns the
// round-trip establishment time and nil on success, or a non-nil error if the
// relay could not be reached within ctx.
//
// Prober is the seam for latency-aware relay selection: [RankByLatency] and
// [Map.Nearest] call it once per candidate relay, concurrently. The default
// implementation is [HTTPConnectProber]; tests inject a deterministic Prober.
type Prober func(ctx context.Context, url netaddr.RelayURL) (time.Duration, error)

// RelayLatency pairs a relay URL with its measured connect latency.
//
// Err is non-nil when the relay could not be probed; in that case Latency is
// not meaningful. [RankByLatency] sorts reachable relays (Err == nil) ahead of
// unreachable ones.
type RelayLatency struct {
	URL     netaddr.RelayURL
	Latency time.Duration
	Err     error
}

// ErrNoRelays is returned by [Map.Nearest] when the map has no relays or none
// could be reached.
var ErrNoRelays = errors.New("relay: no reachable relay in map")

// defaultProbeTimeout bounds a single probe when the caller's context has no
// deadline. It is generous enough for a trans-oceanic TLS handshake yet short
// enough that one dead relay does not stall selection.
const defaultProbeTimeout = 3 * time.Second

// RankByLatency probes every relay in m using prober, concurrently, and returns
// the results sorted by ascending latency. Reachable relays (Err == nil) sort
// before unreachable ones; ties and unreachable relays are ordered
// deterministically by relay URL so selection is reproducible.
//
// If prober is nil, [HTTPConnectProber] is used. RankByLatency never returns a
// nil slice for a non-empty map: an unreachable relay appears with its Err set.
func RankByLatency(ctx context.Context, m *Map, prober Prober) []RelayLatency {
	if prober == nil {
		prober = HTTPConnectProber(nil)
	}
	urls := m.URLs()
	results := make([]RelayLatency, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := probeOne(ctx, prober, u)
			results[i] = RelayLatency{URL: u, Latency: d, Err: err}
		}()
	}
	wg.Wait()

	slices.SortFunc(results, func(a, b RelayLatency) int {
		// Reachable relays sort ahead of unreachable ones.
		if (a.Err == nil) != (b.Err == nil) {
			if a.Err == nil {
				return -1
			}
			return 1
		}
		if a.Err == nil {
			if c := int(a.Latency - b.Latency); c != 0 {
				return sign(c)
			}
		}
		// Deterministic tie-break (and total order for unreachable relays).
		return a.URL.Compare(b.URL)
	})
	return results
}

// probeOne runs a single probe, applying defaultProbeTimeout when ctx carries no
// deadline so one unresponsive relay cannot stall the whole ranking.
func probeOne(ctx context.Context, prober Prober, u netaddr.RelayURL) (time.Duration, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}
	return prober(ctx, u)
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}

// Nearest probes the relays in m and returns the URL of the lowest-latency
// reachable relay. It returns [ErrNoRelays] if the map is empty or no relay
// could be reached. If prober is nil, [HTTPConnectProber] is used.
//
// Nearest is the seam a ticket minter (e.g. ccl's transfer layer) calls to pick
// a home relay close to the local machine instead of an arbitrary one.
func (m *Map) Nearest(ctx context.Context, prober Prober) (netaddr.RelayURL, error) {
	ranked := RankByLatency(ctx, m, prober)
	if len(ranked) == 0 || ranked[0].Err != nil {
		return netaddr.RelayURL{}, ErrNoRelays
	}
	return ranked[0].URL, nil
}

// PreferNearest returns a Map containing only the lowest-latency reachable relay
// in m, using prober (or [HTTPConnectProber] if nil). It is a convenience for
// wiring nearest-relay selection into a [Mode]:
//
//	m, err := relay.DefaultMap().PreferNearest(ctx, nil)
//	if err == nil {
//		mode = relay.ModeCustom(m)
//	}
//
// On error (empty map or all relays unreachable) it returns the error and a nil
// map so the caller can fall back to the full set.
func (m *Map) PreferNearest(ctx context.Context, prober Prober) (*Map, error) {
	u, err := m.Nearest(ctx, prober)
	if err != nil {
		return nil, err
	}
	c, ok := m.Get(u)
	if !ok {
		c = Config{URL: u}
	}
	return NewMap(c), nil
}

// HTTPConnectProber returns a Prober that measures the time to establish a TLS
// connection to a relay's HTTPS endpoint. It reflects the real connect cost a
// relay client pays, which is dominated by round-trip latency to the relay, and
// is cheaper than a full net-report probe.
//
// tlsConfig, if non-nil, overrides the TLS configuration (used in tests to skip
// verification against a local relay). A relay URL without an explicit port uses
// 443.
func HTTPConnectProber(tlsConfig *tls.Config) Prober {
	return func(ctx context.Context, u netaddr.RelayURL) (time.Duration, error) {
		host := u.Host()
		if host == "" {
			return 0, errors.New("relay: probe url has no host")
		}
		port := "443"
		if p := u.URL().Port(); p != "" {
			port = p
		}
		addr := net.JoinHostPort(host, port)

		start := time.Now()
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return 0, err
		}
		defer raw.Close()

		cfg := tlsConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: host}
		}
		tconn := tls.Client(raw, cfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		_ = tconn.Close()
		return time.Since(start), nil
	}
}
