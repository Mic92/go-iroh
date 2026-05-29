package socket

import "time"

// Path-selection bias constants. These match the Rust BiasedRttPathSelector
// (iroh/src/socket/biased_rtt_path_selector.rs:18,22) and remote_state.rs:55.
const (
	// IPv6RttAdvantage is how much lower an IPv6 path's biased RTT is made,
	// expressing a default preference for IPv6 over IPv4.
	IPv6RttAdvantage = 3 * time.Millisecond

	// RttSwitchingMin is the minimum biased-RTT improvement required to switch
	// to a different path in the same tier. It prevents flapping under jitter.
	RttSwitchingMin = 5 * time.Millisecond

	// GoodEnoughLatency is the RTT at or under which a direct path is considered
	// good enough that the actor does not try to upgrade to a better path.
	GoodEnoughLatency = 10 * time.Millisecond
)

// transportTier classifies a path as a primary or backup route. Primary paths
// are preferred whenever available; backup paths are used only when no primary
// path exists. Today the only backup transport is the relay. It mirrors the Rust
// TransportType (biased_rtt_path_selector.rs:30).
type transportTier int

const (
	// tierPrimary is a primary path (direct IP, custom): used whenever available.
	tierPrimary transportTier = iota
	// tierBackup is a backup path (relay): used only when no primary is available.
	tierBackup
)

// PathCandidate is one path offered to a [PathSelector], pairing its [Addr] with
// the most recent RTT observed for it. It is the Go analog of the Rust
// PathSelectionData (biased_rtt_path_selector.rs).
type PathCandidate struct {
	// Addr is the path's transport address.
	Addr Addr
	// RTT is the smoothed round-trip time observed on the path.
	//
	// In this single-path build the RTT comes from qng's
	// quic.Conn.ConnectionStats().SmoothedRTT for the connection's active path;
	// qng does not expose per-PathId RTT (no multipath), so every candidate on a
	// connection reports that connection's active-path RTT. See iroh/DESIGN.md
	// §3.3 / O9.
	RTT time.Duration
}

// PathSelector chooses the preferred path among the candidates for a remote
// endpoint. It is a pure function of the candidate set and the currently
// selected path. Implementations must not block.
//
// It is the Go analog of the Rust PathSelector trait
// (iroh/src/socket/remote_map/remote_state.rs). The default implementation is
// [BiasedRttPathSelector].
type PathSelector interface {
	// Select returns the address of the path to use, or ok=false to keep the
	// current selection (including keeping no selection). current is the
	// currently selected path, if any.
	Select(current *Addr, candidates []PathCandidate) (selected Addr, ok bool)
}

// BiasedRttPathSelector is the default [PathSelector]. It sorts paths by
// (tier, biased RTT): the primary tier always beats the backup tier, and within
// a tier the lowest biased RTT wins. IPv6 paths receive a [IPv6RttAdvantage]
// bias. Switching within a tier requires the candidate's biased RTT to be at
// least [RttSwitchingMin] better than the current path (no flapping); switching
// across tiers is immediate.
//
// It mirrors the Rust BiasedRttPathSelector
// (iroh/src/socket/biased_rtt_path_selector.rs:135).
//
// The zero value is ready to use.
type BiasedRttPathSelector struct{}

var _ PathSelector = BiasedRttPathSelector{}

// bias returns the (tier, rttBias) for an address. The rttBias is added to the
// raw RTT before comparison; a negative bias makes the path more preferred.
// IPv4 and custom paths are primary with no bias; IPv6 is primary with a
// negative bias; relay is backup.
func bias(a Addr) (transportTier, time.Duration) {
	switch a.Kind() {
	case AddrRelay:
		return tierBackup, 0
	case AddrIP:
		if ap, ok := a.IP(); ok && ap.Addr().Is6() {
			return tierPrimary, -IPv6RttAdvantage
		}
		return tierPrimary, 0
	default:
		// Custom and any future primary transport: no bias.
		return tierPrimary, 0
	}
}

// sortKey returns the comparison key for a path: lower is better. The key is
// (tier, biasedRTT); tier dominates, then biased RTT breaks ties.
func sortKey(a Addr, rtt time.Duration) (transportTier, time.Duration) {
	tier, b := bias(a)
	return tier, rtt + b
}

// keyLess reports whether path key x is strictly better (lower) than y.
func keyLess(xt transportTier, xr time.Duration, yt transportTier, yr time.Duration) bool {
	if xt != yt {
		return xt < yt
	}
	return xr < yr
}

// Select implements [PathSelector]. It returns the best candidate to use, or
// ok=false to keep the current selection. The decision follows the Rust
// single-pass algorithm (biased_rtt_path_selector.rs:136): find the
// lowest-keyed candidate and the lowest key seen for the current path, then
// switch across tiers immediately and within a tier only when the improvement
// meets [RttSwitchingMin].
func (BiasedRttPathSelector) Select(current *Addr, candidates []PathCandidate) (Addr, bool) {
	var (
		best     PathCandidate
		bestTier transportTier
		bestRTT  time.Duration
		haveBest bool

		curTier transportTier
		curRTT  time.Duration
		haveCur bool
	)

	for _, c := range candidates {
		tier, biased := sortKey(c.Addr, c.RTT)
		if current != nil && c.Addr.String() == current.String() {
			if !haveCur || keyLess(tier, biased, curTier, curRTT) {
				curTier, curRTT, haveCur = tier, biased, true
			}
		}
		if !haveBest || keyLess(tier, biased, bestTier, bestRTT) {
			best, bestTier, bestRTT, haveBest = c, tier, biased, true
		}
	}

	if !haveBest {
		return Addr{}, false
	}
	// No data for a current path: switch to the best candidate.
	if !haveCur {
		return best.Addr, true
	}
	if curTier != bestTier {
		// Always switch across tiers (e.g. relay -> direct).
		return best.Addr, true
	}
	// Within a tier, switch only when meaningfully better. The condition is
	// `<=` so that an exactly-RttSwitchingMin improvement triggers a switch,
	// matching the Rust comparison (biased_rtt_path_selector.rs:178).
	if bestRTT+RttSwitchingMin <= curRTT {
		return best.Addr, true
	}
	return Addr{}, false
}
