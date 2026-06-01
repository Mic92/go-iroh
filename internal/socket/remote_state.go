package socket

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/tmc/go-iroh/base"
)

// Actor timing constants. These match the Rust reference
// (iroh/src/socket/remote_map/remote_state.rs:52,66,74 and socket.rs).
const (
	// HeartbeatInterval is how often the actor wakes to keep paths alive and
	// re-evaluate path selection. remote_state.rs HEARTBEAT_INTERVAL / socket.rs.
	HeartbeatInterval = 5 * time.Second

	// UpgradeInterval is how often the actor tries to upgrade to a better path
	// even when a working non-relay route exists. remote_state.rs:66.
	UpgradeInterval = 60 * time.Second

	// HolepunchAttemptsInterval throttles hole-punch attempts when the NAT
	// candidate set has not changed. remote_state.rs:52.
	HolepunchAttemptsInterval = 5 * time.Second

	// ActorMaxIdleTimeout is how long an actor with no connections stays alive
	// before it exits and deregisters. remote_state.rs:74.
	ActorMaxIdleTimeout = 60 * time.Second
)

// ErrExtensionNotNegotiated is returned by hole-punching and other operations
// that depend on a QUIC extension that is not negotiated on an active
// connection. Endpoint defaults advertise qng multipath; QNT/DISCO
// hole-punching is still gated separately.
var ErrExtensionNotNegotiated = errors.New("socket: QUIC extension not negotiated (qng X1/X2/X3 gate)")

// ErrHolepunchNotImplemented is returned when the active connection has
// negotiated qng multipath, but the connection cannot open a path from socket.
var ErrHolepunchNotImplemented = errors.New("socket: hole-punch driver not implemented")

// Connection is the minimal view of a QUIC connection the [RemoteStateActor]
// needs. The iroh package adapts a qng *quic.Conn to it; tests use a fake. It
// stays small on purpose: the actor only reads liveness and RTT.
//
// SmoothedRTT returns the connection's active-path smoothed RTT. Done is closed
// when the connection ends. RemoteAddr reports the path the connection is on,
// so the actor can register it as a candidate path.
type Connection interface {
	// SmoothedRTT returns the smoothed round-trip time of the active path.
	SmoothedRTT() time.Duration
	// Done is closed when the connection is closed.
	Done() <-chan struct{}
	// RemoteAddr returns the transport address the connection is using.
	RemoteAddr() Addr
}

type multipathConnection interface {
	MultipathNegotiated() bool
}

type natTraversalRoundConnection interface {
	AddNATTraversalAddress(netip.AddrPort) error
	InitiateNATTraversalRound(context.Context) ([]netip.AddrPort, error)
}

type natTraversalRemoteAddressConnection interface {
	NATTraversalAddresses() ([]netip.AddrPort, error)
}

// PathInfo is qng multipath path state observed through a [Connection]. Addr and
// RTT are set only when qng reports them; socket must not fabricate Addr from
// the connection's original RemoteAddr.
type PathInfo struct {
	// ID is the QUIC multipath PathID.
	ID uint32
	// Validated reports whether the path can carry non-probing application data.
	Validated bool
	// Addr is the path's transport address, when HasAddr is true.
	Addr Addr
	// HasAddr reports whether Addr was observed from qng route metadata.
	HasAddr bool
	// RTT is the path's smoothed round-trip time, when HasRTT is true.
	RTT time.Duration
	// HasRTT reports whether RTT was observed from qng per-path state.
	HasRTT bool
}

type pathObservingConnection interface {
	Paths() []PathInfo
}

type natTraversalAddressConnection interface {
	AddNATTraversalAddress(netip.AddrPort) error
	RemoveNATTraversalAddress(netip.AddrPort) error
}

// ResolveFunc resolves additional transport addresses for a remote endpoint. It
// is supplied by the iroh package (which owns the address-lookup services) so
// the socket package does not import iroh. It returns the resolved addresses, or
// an error if lookup failed. A nil ResolveFunc disables lookup-driven resolution.
//
// It is the hook for the Rust RemoteStateActor::resolve_remote path
// (remote_state.rs:843), wired in slice G's address lookup.
type ResolveFunc func(ctx context.Context, id base.EndpointId) ([]base.TransportAddr, error)

// remoteMessage is the actor inbox message. Exactly one field is set.
type remoteMessage struct {
	addConnection *addConnectionMsg
	resolve       *resolveMsg
	connClosed    Connection // a registered connection's Done fired
}

// addConnectionMsg registers a new connection with the actor and returns a path
// event subscription.
type addConnectionMsg struct {
	conn  Connection
	reply chan<- (<-chan PathEvent)
}

// resolveMsg asks the actor to resolve more addresses for the remote and add
// them as candidate paths. reply receives nil on success or the lookup error.
type resolveMsg struct {
	addrs base.EndpointAddr
	reply chan<- error
}

// connState is the actor's per-connection bookkeeping.
type connState struct {
	conn  Connection
	addr  Addr
	paths []Addr
}

// RemoteStateActor manages all connection and path state for a single remote
// endpoint. Exactly one goroutine runs per remote, driven by a single select
// loop over the inbox (which carries add-connection, resolve, and
// connection-closed messages) and timers (heartbeat, upgrade, idle teardown). It
// is the Go analog of the Rust RemoteStateActor
// (iroh/src/socket/remote_map/remote_state.rs).
//
// QNT/DISCO boundary (iroh/DESIGN.md §3.4): the actor does not build traversal
// frames itself. It advertises vetted local candidates and asks qng to start NAT
// traversal rounds; qng owns probe timers, response matching, and route-bearing
// path opening. Path selection is driven by qng path observability.
//
// Create an actor with the RemoteMap; do not construct one directly.
type RemoteStateActor struct {
	id       base.EndpointId
	selector PathSelector
	resolve  ResolveFunc
	idle     time.Duration
	watcher  *PathWatcher

	// inbox carries messages from the RemoteMap and from per-connection watcher
	// goroutines. It is buffered so callers do not block.
	inbox chan remoteMessage
	// done is closed when the actor goroutine returns.
	done chan struct{}

	// onExit is called once, when the actor goroutine returns, so the RemoteMap
	// can deregister it under the same lock that inserts it (the O12 invariant).
	onExit func()

	// mu guards the fields below, which SendDatagram and SelectedPath read
	// concurrently with the actor loop.
	mu       sync.Mutex
	paths    *RemotePathState
	conns    map[Connection]*connState
	selected *Addr
	localNAT []netip.AddrPort
}

// newRemoteStateActor creates and starts an actor for id. The returned actor is
// already running its loop in a goroutine; it stops when ctx is cancelled or it
// idles out, calling onExit on the way out.
func newRemoteStateActor(ctx context.Context, id base.EndpointId, selector PathSelector, resolve ResolveFunc, idle time.Duration, onExit func()) *RemoteStateActor {
	if selector == nil {
		selector = BiasedRttPathSelector{}
	}
	if idle <= 0 {
		idle = ActorMaxIdleTimeout
	}
	a := &RemoteStateActor{
		id:       id,
		selector: selector,
		resolve:  resolve,
		idle:     idle,
		watcher:  NewPathWatcher(),
		inbox:    make(chan remoteMessage, 16),
		done:     make(chan struct{}),
		onExit:   onExit,
		paths:    NewRemotePathState(),
		conns:    make(map[Connection]*connState),
	}
	go a.run(ctx)
	return a
}

// ID returns the remote endpoint this actor manages.
func (a *RemoteStateActor) ID() base.EndpointId { return a.id }

// donec is closed when the actor goroutine has exited.
func (a *RemoteStateActor) donec() <-chan struct{} { return a.done }

// AddConnection registers conn with the actor and returns a channel of path
// events for it. ok is false if the actor stopped before it could register the
// connection; the caller should retry with a fresh actor. The returned channel
// is closed when the actor stops.
func (a *RemoteStateActor) AddConnection(conn Connection) (events <-chan PathEvent, ok bool) {
	reply := make(chan (<-chan PathEvent), 1)
	select {
	case a.inbox <- remoteMessage{addConnection: &addConnectionMsg{conn: conn, reply: reply}}:
	case <-a.done:
		return nil, false
	}
	select {
	case ch := <-reply:
		return ch, true
	case <-a.done:
		return nil, false
	}
}

// ResolveRemote asks the actor to resolve more addresses for addr via the
// [ResolveFunc] and register them as candidate paths. It blocks until resolution
// completes, returning the lookup error if any. With no resolver and no addrs it
// returns nil immediately.
func (a *RemoteStateActor) ResolveRemote(addr base.EndpointAddr) error {
	reply := make(chan error, 1)
	select {
	case a.inbox <- remoteMessage{resolve: &resolveMsg{addrs: addr, reply: reply}}:
	case <-a.done:
		return context.Canceled
	}
	select {
	case err := <-reply:
		return err
	case <-a.done:
		return context.Canceled
	}
}

// run is the single actor loop. It exits when ctx is cancelled or when the actor
// has had no connections for its idle timeout, deregistering via onExit.
func (a *RemoteStateActor) run(ctx context.Context) {
	defer close(a.done)
	defer a.watcher.Close()
	if a.onExit != nil {
		defer a.onExit()
	}

	heartbeat := time.NewTicker(HeartbeatInterval)
	defer heartbeat.Stop()
	upgrade := time.NewTicker(UpgradeInterval)
	defer upgrade.Stop()
	idleTimer := time.NewTimer(a.idle)
	defer idleTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-a.inbox:
			a.handle(ctx, msg)
		case <-idleTimer.C:
			// Idle out only when there are no connections. The timer is reset to
			// the full timeout whenever a connection is present, so a stray fire
			// while connections exist is rescheduled here.
			a.mu.Lock()
			n := len(a.conns)
			a.mu.Unlock()
			if n == 0 {
				return
			}
			resetTimer(idleTimer, a.idle)
		case <-heartbeat.C:
			a.reselect()
		case <-upgrade.C:
			// Upgrade tick: try a QNT round when the active connection supports it.
			// Errors are non-fatal; the actor keeps using the best path it already
			// knows and tries again on the next cadence.
			_ = a.TriggerHolepunch()
			a.reselect()
		}
		// Keep the idle timer disarmed (reset to a fresh full timeout) while
		// connections exist, so an active actor never idles out.
		a.mu.Lock()
		n := len(a.conns)
		a.mu.Unlock()
		if n > 0 {
			resetTimer(idleTimer, a.idle)
		}
	}
}

// handle dispatches one inbox message.
func (a *RemoteStateActor) handle(ctx context.Context, msg remoteMessage) {
	switch {
	case msg.addConnection != nil:
		a.handleAddConnection(msg.addConnection)
	case msg.resolve != nil:
		a.handleResolve(ctx, msg.resolve)
	case msg.connClosed != nil:
		a.handleConnClosed(msg.connClosed)
	}
}

// handleAddConnection registers a connection, records its path, subscribes the
// caller to path events, emits an Opened event, and starts a watcher goroutine
// that posts a connClosed message when the connection ends.
func (a *RemoteStateActor) handleAddConnection(m *addConnectionMsg) {
	sub, _ := a.watcher.Subscribe()

	addr := m.conn.RemoteAddr()
	cs := &connState{conn: m.conn, addr: addr}
	paths := observeMultipathPaths(m.conn)

	a.mu.Lock()
	a.conns[m.conn] = cs
	a.paths.SetOpen(addr)
	opened := a.syncMultipathPathsLocked(cs, paths)
	a.paths.Prune()
	localNAT := append([]netip.AddrPort(nil), a.localNAT...)
	a.mu.Unlock()

	m.reply <- sub
	seedNATTraversalAddresses(m.conn, localNAT)

	// Watch the connection's lifetime. One goroutine per connection (single-path:
	// usually one); it exits when the connection closes or the actor stops.
	go func(conn Connection) {
		select {
		case <-conn.Done():
			select {
			case a.inbox <- remoteMessage{connClosed: conn}:
			case <-a.done:
			}
		case <-a.done:
		}
	}(m.conn)

	a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
	for _, addr := range opened {
		a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
	}
	a.reselect()
}

// handleResolve resolves additional addresses for the remote and adds them as
// candidate paths.
func (a *RemoteStateActor) handleResolve(ctx context.Context, m *resolveMsg) {
	// Add any addresses carried directly in the EndpointAddr as candidate paths.
	a.mu.Lock()
	for _, ta := range m.addrs.Addrs() {
		if pa, ok := transportToAddr(ta, a.id); ok {
			a.paths.Add(pa)
		}
	}
	a.mu.Unlock()

	if a.resolve == nil {
		m.reply <- nil
		return
	}
	addrs, err := a.resolve(ctx, m.addrs.Id)
	if err != nil {
		m.reply <- err
		return
	}
	a.mu.Lock()
	for _, ta := range addrs {
		if pa, ok := transportToAddr(ta, a.id); ok {
			a.paths.Add(pa)
		}
	}
	a.paths.Prune()
	a.mu.Unlock()
	m.reply <- nil
}

// handleConnClosed handles a connection closing: it removes the connection,
// marks its path inactive, clears the selection if it pointed at that path, and
// emits a Closed event.
func (a *RemoteStateActor) handleConnClosed(conn Connection) {
	a.mu.Lock()
	cs, ok := a.conns[conn]
	if !ok {
		a.mu.Unlock()
		return
	}
	delete(a.conns, conn)
	now := time.Now()
	closed := []Addr{cs.addr}
	a.paths.SetClosed(cs.addr, now)
	for _, addr := range cs.paths {
		if a.multipathPathOpenLocked(addr) {
			continue
		}
		a.paths.SetClosed(addr, now)
		closed = appendUniqueAddr(closed, addr)
	}
	if a.selected != nil && a.selected.String() == cs.addr.String() {
		a.selected = nil
	}
	if a.selected != nil {
		for _, addr := range closed {
			if a.selected.String() == addr.String() {
				a.selected = nil
				break
			}
		}
	}
	a.mu.Unlock()
	for _, addr := range closed {
		a.watcher.Send(PathEvent{Kind: PathEventClosed, Addr: addr})
	}
}

type connPathSnapshot struct {
	conn  Connection
	addr  Addr
	rtt   time.Duration
	paths []PathInfo
}

func (a *RemoteStateActor) connectionPathSnapshots() []connPathSnapshot {
	a.mu.Lock()
	conns := make([]connPathSnapshot, 0, len(a.conns))
	for _, cs := range a.conns {
		conns = append(conns, connPathSnapshot{conn: cs.conn, addr: cs.addr})
	}
	a.mu.Unlock()

	for i := range conns {
		conns[i].rtt = conns[i].conn.SmoothedRTT()
		conns[i].paths = observeMultipathPaths(conns[i].conn)
	}
	return conns
}

func observeMultipathPaths(conn Connection) []PathInfo {
	observer, ok := conn.(pathObservingConnection)
	if !ok {
		return nil
	}
	return observer.Paths()
}

func appendCandidate(candidates []PathCandidate, seen map[string]struct{}, addr Addr, rtt time.Duration) []PathCandidate {
	k := addr.String()
	if _, ok := seen[k]; ok {
		return candidates
	}
	seen[k] = struct{}{}
	return append(candidates, PathCandidate{Addr: addr, RTT: rtt})
}

func appendMultipathCandidates(candidates []PathCandidate, seen map[string]struct{}, paths []PathInfo, rtt time.Duration) []PathCandidate {
	for _, p := range paths {
		if p.Validated && p.HasAddr {
			pathRTT := rtt
			if p.HasRTT {
				pathRTT = p.RTT
			}
			candidates = appendCandidate(candidates, seen, p.Addr, pathRTT)
		}
	}
	return candidates
}

// syncMultipathPathsLocked records validated qng paths with explicit route
// metadata as open socket paths. a.mu must be held.
func (a *RemoteStateActor) syncMultipathPathsLocked(cs *connState, paths []PathInfo) []Addr {
	var opened []Addr
	for _, p := range paths {
		if !p.Validated || !p.HasAddr {
			continue
		}
		cs.paths = appendUniqueAddr(cs.paths, p.Addr)
		if status, known := a.paths.Status(p.Addr); known && status == PathStatusOpen {
			continue
		}
		a.paths.SetOpen(p.Addr)
		opened = appendUniqueAddr(opened, p.Addr)
	}
	return opened
}

// multipathPathOpenLocked reports whether another live connection still owns
// addr as a qng route path. a.mu must be held.
func (a *RemoteStateActor) multipathPathOpenLocked(addr Addr) bool {
	for _, cs := range a.conns {
		for _, path := range cs.paths {
			if path.String() == addr.String() {
				return true
			}
		}
	}
	return false
}

func appendUniqueAddr(addrs []Addr, addr Addr) []Addr {
	for _, a := range addrs {
		if a.String() == addr.String() {
			return addrs
		}
	}
	return append(addrs, addr)
}

func appendUniqueNATAddr(addrs []netip.AddrPort, addr netip.AddrPort) []netip.AddrPort {
	addr, ok := canonicalNATAddr(addr)
	if !ok {
		return addrs
	}
	for _, a := range addrs {
		if a == addr {
			return addrs
		}
	}
	return append(addrs, addr)
}

func containsNATAddr(addrs []netip.AddrPort, addr netip.AddrPort) bool {
	for _, a := range addrs {
		if a == addr {
			return true
		}
	}
	return false
}

func canonicalNATAddr(addr netip.AddrPort) (netip.AddrPort, bool) {
	if !addr.IsValid() || addr.Port() == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), true
}

// reselect runs the path selector over the current candidates and, if the
// selection changes, records it and emits a Selected event.
func (a *RemoteStateActor) reselect() {
	snapshots := a.connectionPathSnapshots()

	a.mu.Lock()
	candidates := make([]PathCandidate, 0, len(snapshots))
	seen := make(map[string]struct{}, len(snapshots))
	var opened []Addr
	for _, snap := range snapshots {
		cs, ok := a.conns[snap.conn]
		if !ok {
			continue
		}
		candidates = appendCandidate(candidates, seen, snap.addr, snap.rtt)
		opened = append(opened, a.syncMultipathPathsLocked(cs, snap.paths)...)
		candidates = appendMultipathCandidates(candidates, seen, snap.paths, snap.rtt)
	}
	a.paths.Prune()
	current := a.selected
	selected, ok := a.selector.Select(current, candidates)
	if !ok {
		a.mu.Unlock()
		for _, addr := range opened {
			a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
		}
		return
	}
	if current != nil && current.String() == selected.String() {
		a.mu.Unlock()
		for _, addr := range opened {
			a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
		}
		return
	}
	sel := selected
	a.selected = &sel
	a.mu.Unlock()
	for _, addr := range opened {
		a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
	}
	a.watcher.Send(PathEvent{Kind: PathEventSelected, Addr: selected})
}

func seedNATTraversalAddresses(conn Connection, candidates []netip.AddrPort) {
	if len(candidates) == 0 {
		return
	}
	mp, ok := conn.(multipathConnection)
	if !ok || !mp.MultipathNegotiated() {
		return
	}
	qnt, ok := conn.(natTraversalAddressConnection)
	if !ok {
		return
	}
	for _, addr := range candidates {
		_ = qnt.AddNATTraversalAddress(addr)
	}
}

// TriggerHolepunch attempts to open a new direct path by NAT traversal. It is
// gated on an active qng connection with QNT support: socket advertises its
// already-known local candidates and asks qng to initiate one NAT traversal
// round. qng owns QNT frames, probe timers, response matching, and path opening.
func (a *RemoteStateActor) TriggerHolepunch() error {
	a.mu.Lock()
	conns := make([]Connection, 0, len(a.conns))
	for conn := range a.conns {
		conns = append(conns, conn)
	}
	candidates := append([]netip.AddrPort(nil), a.localNAT...)
	a.mu.Unlock()

	negotiated := false
	var target natTraversalRoundConnection
	for _, conn := range conns {
		mp, ok := conn.(multipathConnection)
		if !ok || !mp.MultipathNegotiated() {
			continue
		}
		negotiated = true
		if qnt, ok := conn.(natTraversalRoundConnection); ok {
			target = qnt
			break
		}
	}
	if !negotiated {
		return ErrExtensionNotNegotiated
	}
	if target == nil {
		return ErrHolepunchNotImplemented
	}
	ctx, cancel := context.WithTimeout(context.Background(), HolepunchAttemptsInterval)
	defer cancel()
	for _, addr := range candidates {
		if err := target.AddNATTraversalAddress(addr); err != nil {
			return fmt.Errorf("socket: add nat traversal address %s: %w", addr, err)
		}
	}
	if _, err := target.InitiateNATTraversalRound(ctx); err != nil {
		return fmt.Errorf("socket: initiate nat traversal round: %w", err)
	}
	return nil
}

// SelectedPath returns the actor's currently selected path and whether one is
// selected. It is safe to call concurrently with the actor loop.
func (a *RemoteStateActor) SelectedPath() (Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.selected == nil {
		return Addr{}, false
	}
	return *a.selected, true
}

// MultipathPaths returns qng multipath path state observed from active
// connections. Paths with explicit qng route metadata are also registered with
// RemotePathState by the actor loop and can produce path events.
func (a *RemoteStateActor) MultipathPaths() []PathInfo {
	a.mu.Lock()
	conns := make([]Connection, 0, len(a.conns))
	for conn := range a.conns {
		conns = append(conns, conn)
	}
	a.mu.Unlock()

	var paths []PathInfo
	for _, conn := range conns {
		observer, ok := conn.(pathObservingConnection)
		if !ok {
			continue
		}
		paths = append(paths, observer.Paths()...)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].ID != paths[j].ID {
			return paths[i].ID < paths[j].ID
		}
		return !paths[i].Validated && paths[j].Validated
	})
	return paths
}

// NATTraversalAddresses returns the remote QNT ADD_ADDRESS set observed on
// active qng connections. Duplicate addresses are removed in first-seen order.
func (a *RemoteStateActor) NATTraversalAddresses() ([]netip.AddrPort, error) {
	a.mu.Lock()
	conns := make([]Connection, 0, len(a.conns))
	for conn := range a.conns {
		conns = append(conns, conn)
	}
	a.mu.Unlock()

	negotiated := false
	var out []netip.AddrPort
	for _, conn := range conns {
		mp, ok := conn.(multipathConnection)
		if !ok || !mp.MultipathNegotiated() {
			continue
		}
		negotiated = true
		qnt, ok := conn.(natTraversalRemoteAddressConnection)
		if !ok {
			continue
		}
		addrs, err := qnt.NATTraversalAddresses()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			out = appendUniqueNATAddr(out, addr)
		}
	}
	if !negotiated {
		return nil, ErrExtensionNotNegotiated
	}
	if out == nil {
		out = []netip.AddrPort{}
	}
	return out, nil
}

// AddNATTraversalAddresses reconciles the full local QNT candidate set for
// active qng connections. Candidate discovery stays outside this method:
// callers must pass already-vetted local candidates, such as endpoint-bound
// direct addresses and QAD reflexive addresses. qng owns QNT state, wire frames,
// probe timers, and eventual path opening.
func (a *RemoteStateActor) AddNATTraversalAddresses(addrs []netip.AddrPort) error {
	a.mu.Lock()
	var candidates []netip.AddrPort
	for _, addr := range addrs {
		canon, ok := canonicalNATAddr(addr)
		if !ok {
			continue
		}
		candidates = appendUniqueNATAddr(candidates, canon)
	}
	var removed []netip.AddrPort
	for _, addr := range a.localNAT {
		if !containsNATAddr(candidates, addr) {
			removed = append(removed, addr)
		}
	}
	var added []netip.AddrPort
	for _, addr := range candidates {
		if !containsNATAddr(a.localNAT, addr) {
			added = append(added, addr)
		}
	}
	a.localNAT = candidates
	conns := make([]Connection, 0, len(a.conns))
	for conn := range a.conns {
		conns = append(conns, conn)
	}
	a.mu.Unlock()

	negotiated := false
	var target natTraversalAddressConnection
	for _, conn := range conns {
		mp, ok := conn.(multipathConnection)
		if !ok || !mp.MultipathNegotiated() {
			continue
		}
		negotiated = true
		if qnt, ok := conn.(natTraversalAddressConnection); ok {
			target = qnt
			break
		}
	}
	if !negotiated {
		return ErrExtensionNotNegotiated
	}
	if target == nil {
		return ErrHolepunchNotImplemented
	}
	for _, addr := range removed {
		if err := target.RemoveNATTraversalAddress(addr); err != nil {
			return fmt.Errorf("socket: remove nat traversal address %s: %w", addr, err)
		}
	}
	for _, addr := range added {
		if err := target.AddNATTraversalAddress(addr); err != nil {
			return fmt.Errorf("socket: add nat traversal address %s: %w", addr, err)
		}
	}
	return nil
}

// SendDatagram routes a datagram toward the remote via send. If a path is
// selected it sends there; otherwise it sends to every known path. It NEVER
// returns an error for an unreachable path: an unroutable datagram is treated as
// lost so QUIC loss recovery handles it (the socket-core blackhole invariant,
// iroh/src/socket/remote_map/remote_state.rs:782). send's bool result is
// advisory only.
//
// qng addresses datagrams to a concrete path directly through the MagicConn, so
// this method backs the Mixed-EndpointId send path (DESIGN.md §3.1), which is
// exercised by unit tests rather than the QUIC data plane in this slice.
func (a *RemoteStateActor) SendDatagram(p []byte, send func(Addr, []byte) bool) error {
	a.mu.Lock()
	var targets []Addr
	if a.selected != nil {
		targets = []Addr{*a.selected}
	} else {
		targets = a.paths.Addrs()
	}
	a.mu.Unlock()
	for _, t := range targets {
		send(t, p) // result advisory; blackhole on failure
	}
	return nil
}

// PathEvents returns a fresh subscription to this actor's path events and a
// function to cancel it.
func (a *RemoteStateActor) PathEvents() (<-chan PathEvent, func()) {
	return a.watcher.Subscribe()
}

// resetTimer drains and resets a timer to fire after d.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// transportToAddr converts a base.TransportAddr (the public address type) to the
// socket package's internal [Addr], pairing relay addresses with the remote id.
// It returns ok=false for address kinds the magic socket cannot route.
func transportToAddr(ta base.TransportAddr, id base.EndpointId) (Addr, bool) {
	switch v := ta.(type) {
	case base.IPAddr:
		return IPAddr(v.Addr), true
	case base.RelayAddr:
		return RelayAddr(v.URL, id), true
	case base.CustomAddr:
		return CustomAddr(v), true
	default:
		return Addr{}, false
	}
}
