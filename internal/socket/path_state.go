package socket

import (
	"sort"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// Path-state pruning limits. These bound the number of candidate paths an actor
// keeps per remote so the set cannot grow without limit. Relay paths are never
// counted or pruned. Values match the Rust reference
// (iroh/src/socket/remote_map/remote_state/path_state.rs:18,23).
const (
	// MaxNonRelayPaths is the maximum number of non-relay paths kept per remote.
	MaxNonRelayPaths = 30

	// MaxInactiveNonRelayPaths is the maximum number of inactive (previously
	// open, now closed) non-relay paths kept per remote.
	MaxInactiveNonRelayPaths = 10
)

// PathStatus is the lifecycle status of a candidate path. It mirrors the Rust
// PathStatus enum (path_state.rs:44).
type PathStatus int

const (
	// PathStatusUnknown is a path that has never been dialed: it was added by an
	// address-lookup mechanism and is only potentially usable.
	PathStatusUnknown PathStatus = iota
	// PathStatusOpen is a path that is currently open in QUIC.
	PathStatusOpen
	// PathStatusInactive is a path that was open at some point but has since
	// closed. The time records when it closed, used to prune oldest-first.
	PathStatusInactive
	// PathStatusUnusable is a path where hole-punching was attempted and failed.
	PathStatusUnusable
)

func (s PathStatus) String() string {
	switch s {
	case PathStatusUnknown:
		return "unknown"
	case PathStatusOpen:
		return "open"
	case PathStatusInactive:
		return "inactive"
	case PathStatusUnusable:
		return "unusable"
	default:
		return "invalid"
	}
}

// PathState is the per-path bookkeeping kept by [RemotePathState].
type PathState struct {
	// Status is the current lifecycle status of the path.
	Status PathStatus
	// lastActive records when an open path was last observed as active.
	lastActive time.Time
	// closedAt records when an inactive path was last closed; it is only
	// meaningful when Status is PathStatusInactive and orders inactive-path
	// pruning (most recently closed kept first).
	closedAt time.Time
}

// TransportAddrUsage reports whether a remote transport address is currently
// active.
type TransportAddrUsage int

const (
	// TransportAddrInactive means the address is known but not currently used.
	TransportAddrInactive TransportAddrUsage = iota
	// TransportAddrActive means the address is currently used.
	TransportAddrActive
)

// TransportAddrInfo is a remote transport address plus usage metadata.
type TransportAddrInfo struct {
	Addr       netaddr.TransportAddr
	Usage      TransportAddrUsage
	Provenance string
}

// RemotePathState tracks all candidate paths to a single remote endpoint:
// direct IP, relay, and custom transport addresses, each with a [PathStatus].
// It is the Go analog of the Rust RemotePathState (path_state.rs).
//
// Paths added by address lookup start [PathStatusUnknown]; QUIC path events move
// them through Open and Inactive; failed hole-punches mark them Unusable. The
// set is bounded by [RemotePathState.Prune], which keeps at most
// [MaxNonRelayPaths] non-relay paths plus [MaxInactiveNonRelayPaths] inactive
// non-relay paths. Relay paths are never pruned.
//
// RemotePathState is not safe for concurrent use; it is owned by a single
// [RemoteStateActor] goroutine.
type RemotePathState struct {
	paths map[string]pathEntry
}

// pathEntry stores a path's [Addr] alongside its [PathState]. The map is keyed
// by Addr.String() because [Addr] is not directly comparable (it embeds a
// non-comparable netaddr.CustomAddr).
type pathEntry struct {
	addr       Addr
	state      PathState
	provenance string
}

// NewRemotePathState returns an empty path-state tracker.
func NewRemotePathState() *RemotePathState {
	return &RemotePathState{paths: make(map[string]pathEntry)}
}

// key returns the stable map key for an [Addr].
func pathKey(a Addr) string { return a.String() }

// IsEmpty reports whether no paths are known.
func (p *RemotePathState) IsEmpty() bool { return len(p.paths) == 0 }

// Len returns the number of known paths, including relay paths.
func (p *RemotePathState) Len() int { return len(p.paths) }

// Addrs returns the addresses of all known paths in unspecified order.
func (p *RemotePathState) Addrs() []Addr {
	out := make([]Addr, 0, len(p.paths))
	for _, e := range p.paths {
		out = append(out, e.addr)
	}
	return out
}

// OpenAddrs returns the addresses of all currently open paths.
func (p *RemotePathState) OpenAddrs() []Addr {
	out := make([]Addr, 0, len(p.paths))
	for _, e := range p.paths {
		if e.state.Status == PathStatusOpen {
			out = append(out, e.addr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].String() < out[j].String()
	})
	return out
}

// RemoteAddrs returns all known remote addresses with active/inactive usage.
func (p *RemotePathState) RemoteAddrs() []TransportAddrInfo {
	out := make([]TransportAddrInfo, 0, len(p.paths))
	for _, e := range p.paths {
		addr, ok := transportAddrFromAddr(e.addr)
		if !ok {
			continue
		}
		usage := TransportAddrInactive
		if e.state.Status == PathStatusOpen {
			usage = TransportAddrActive
		}
		out = append(out, TransportAddrInfo{Addr: addr, Usage: usage, Provenance: e.provenance})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Addr.String() < out[j].Addr.String()
	})
	return out
}

// Status returns the status of addr and whether it is known.
func (p *RemotePathState) Status(addr Addr) (PathStatus, bool) {
	e, ok := p.paths[pathKey(addr)]
	if !ok {
		return PathStatusUnknown, false
	}
	return e.state.Status, true
}

// Add records a candidate path with [PathStatusUnknown] if it is not already
// known. A path already present keeps its current status.
func (p *RemotePathState) Add(addr Addr) {
	p.AddWithProvenance(addr, "")
}

// AddWithProvenance records a candidate path with lookup provenance.
func (p *RemotePathState) AddWithProvenance(addr Addr, provenance string) {
	k := pathKey(addr)
	if e, ok := p.paths[k]; ok {
		if e.provenance == "" && provenance != "" {
			e.provenance = provenance
			p.paths[k] = e
		}
		return
	}
	p.paths[k] = pathEntry{addr: addr, state: PathState{Status: PathStatusUnknown}, provenance: provenance}
}

// SetOpen marks addr as open, adding it if unknown. It mirrors the Rust
// add_path / on path-open transition (path_state.rs:90).
func (p *RemotePathState) SetOpen(addr Addr) {
	p.SetOpenAt(addr, time.Now())
}

// SetOpenAt marks addr as open with an explicit activity time. It is used by
// tests and by the actor heartbeat, which already has a shared timestamp for
// all observed paths.
func (p *RemotePathState) SetOpenAt(addr Addr, now time.Time) {
	k := pathKey(addr)
	e := p.paths[k]
	e.addr = addr
	e.state = PathState{Status: PathStatusOpen, lastActive: now}
	p.paths[k] = e
}

// SetClosed transitions addr toward an inactive/unusable status, recording the
// close time for inactive pruning. It mirrors the Rust remove_path transition
// (path_state.rs:106): an open or already-inactive path becomes inactive (still
// considered usable later); an unusable or unknown path becomes unusable.
func (p *RemotePathState) SetClosed(addr Addr, now time.Time) {
	k := pathKey(addr)
	e, ok := p.paths[k]
	if !ok {
		return
	}
	switch e.state.Status {
	case PathStatusOpen, PathStatusInactive:
		e.state.Status = PathStatusInactive
		e.state.closedAt = now
	case PathStatusUnusable, PathStatusUnknown:
		e.state.Status = PathStatusUnusable
	}
	p.paths[k] = e
}

// SetUnusable marks addr unusable: a hole-punch was attempted and failed.
func (p *RemotePathState) SetUnusable(addr Addr) {
	k := pathKey(addr)
	e, ok := p.paths[k]
	if !ok {
		e = pathEntry{addr: addr}
	}
	e.addr = addr
	e.state.Status = PathStatusUnusable
	p.paths[k] = e
}

// ExpireIdle closes open paths that have not been observed within their path
// idle timeout. Direct and custom paths use [PathMaxIdleTimeout]; relay paths
// use [RelayPathMaxIdleTimeout].
func (p *RemotePathState) ExpireIdle(now time.Time) []Addr {
	var closed []Addr
	for k, e := range p.paths {
		if e.state.Status != PathStatusOpen || e.state.lastActive.IsZero() {
			continue
		}
		timeout := PathMaxIdleTimeout
		if isRelayAddr(e.addr) {
			timeout = RelayPathMaxIdleTimeout
		}
		if now.Sub(e.state.lastActive) < timeout {
			continue
		}
		e.state.Status = PathStatusInactive
		e.state.closedAt = now
		p.paths[k] = e
		closed = append(closed, e.addr)
	}
	return closed
}

// Prune bounds the non-relay path set. It is a no-op when there are fewer than
// [MaxNonRelayPaths] non-relay paths. Otherwise it removes failed (unusable)
// paths and all but the [MaxInactiveNonRelayPaths] most-recently-closed inactive
// paths. Open and unknown paths are always kept; relay paths are never pruned or
// counted. It mirrors prune_non_relay_paths (path_state.rs:254).
func (p *RemotePathState) Prune() {
	// Bail early if the total path count is below the limit.
	if len(p.paths) < MaxNonRelayPaths {
		return
	}

	nonRelay := 0
	for _, e := range p.paths {
		if !isRelayAddr(e.addr) {
			nonRelay++
		}
	}
	if nonRelay < MaxNonRelayPaths {
		return
	}

	type inactiveEntry struct {
		key      string
		closedAt time.Time
	}
	var inactive []inactiveEntry
	var failed []string
	for k, e := range p.paths {
		if isRelayAddr(e.addr) {
			continue
		}
		switch e.state.Status {
		case PathStatusInactive:
			inactive = append(inactive, inactiveEntry{key: k, closedAt: e.state.closedAt})
		case PathStatusUnusable:
			failed = append(failed, k)
		}
	}

	// If every path failed, do not prune all of them: keep MaxNonRelayPaths.
	// This implies inactive is empty.
	if len(failed) == len(p.paths) {
		keep := len(p.paths) - MaxNonRelayPaths
		if keep < 0 {
			keep = 0
		}
		failed = failed[:keep]
	}

	// Sort inactive most-recently-closed first, then drop everything beyond the
	// MaxInactiveNonRelayPaths we keep.
	sort.Slice(inactive, func(i, j int) bool {
		return inactive[i].closedAt.After(inactive[j].closedAt)
	})
	keepInactive := MaxInactiveNonRelayPaths
	if keepInactive > len(inactive) {
		keepInactive = len(inactive)
	}
	oldInactive := inactive[keepInactive:]

	prune := make(map[string]struct{}, len(failed)+len(oldInactive))
	for _, k := range failed {
		prune[k] = struct{}{}
	}
	for _, e := range oldInactive {
		prune[e.key] = struct{}{}
	}
	for k := range prune {
		delete(p.paths, k)
	}
}

// isRelayAddr reports whether a is a relay path.
func isRelayAddr(a Addr) bool { return a.Kind() == AddrRelay }

func transportAddrFromAddr(a Addr) (netaddr.TransportAddr, bool) {
	if ap, ok := a.IP(); ok {
		return netaddr.IPAddr{Addr: ap}, true
	}
	if url, _, ok := a.Relay(); ok {
		return netaddr.RelayAddr{URL: url}, true
	}
	if custom, ok := a.Custom(); ok {
		return custom, true
	}
	return nil, false
}
