package socket

import (
	"context"
	"errors"
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
// that depend on QUIC extensions the qng fork does not implement: multipath
// (X1), NAT traversal / DISCO (X2), and observed-address reports (X3). See
// iroh/DESIGN.md §0/§3.4/§5.
//
// In this single-path build the actor falls back to the relay path and any
// pre-validated direct path chosen at dial time; it never opens new paths via
// hole-punching. This is a documented degradation, not a bug.
var ErrExtensionNotNegotiated = errors.New("socket: QUIC extension not negotiated (qng X1/X2/X3 gate)")

// Connection is the minimal view of a QUIC connection the [RemoteStateActor]
// needs. The iroh package adapts a qng *quic.Conn to it; tests use a fake. It
// stays small on purpose: the actor only reads liveness and RTT.
//
// SmoothedRTT returns the connection's active-path smoothed RTT (qng exposes no
// per-path RTT in this single-path build; see iroh/DESIGN.md O9). Done is closed
// when the connection ends. RemoteAddr reports the path the connection is on, so
// the actor can register it as a candidate path.
type Connection interface {
	// SmoothedRTT returns the smoothed round-trip time of the active path.
	SmoothedRTT() time.Duration
	// Done is closed when the connection is closed.
	Done() <-chan struct{}
	// RemoteAddr returns the transport address the connection is using.
	RemoteAddr() Addr
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
	conn Connection
	addr Addr
}

// RemoteStateActor manages all connection and path state for a single remote
// endpoint. Exactly one goroutine runs per remote, driven by a single select
// loop over the inbox (which carries add-connection, resolve, and
// connection-closed messages) and timers (heartbeat, upgrade, idle teardown). It
// is the Go analog of the Rust RemoteStateActor
// (iroh/src/socket/remote_map/remote_state.rs).
//
// Degradation (qng X1/X2/X3 gate, iroh/DESIGN.md §3.4): hole-punching is gated.
// [RemoteStateActor.TriggerHolepunch] returns [ErrExtensionNotNegotiated]; the
// actor never opens new paths. It manages the relay path and any pre-validated
// direct path chosen at dial time, selecting between them with the
// [PathSelector]. This is a single-path-aware subset of the full driver, not a
// stub.
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
			// Upgrade tick: in this build there is no hole-punching to trigger
			// (ErrExtensionNotNegotiated), so the actor only re-evaluates path
			// selection over the paths it already has.
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
	m.reply <- sub

	addr := m.conn.RemoteAddr()
	cs := &connState{conn: m.conn, addr: addr}

	a.mu.Lock()
	a.conns[m.conn] = cs
	a.paths.SetOpen(addr)
	a.paths.Prune()
	a.mu.Unlock()

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
	a.paths.SetClosed(cs.addr, time.Now())
	if a.selected != nil && a.selected.String() == cs.addr.String() {
		a.selected = nil
	}
	a.mu.Unlock()
	a.watcher.Send(PathEvent{Kind: PathEventClosed, Addr: cs.addr})
}

// reselect runs the path selector over the current candidates and, if the
// selection changes, records it and emits a Selected event.
func (a *RemoteStateActor) reselect() {
	a.mu.Lock()
	candidates := make([]PathCandidate, 0, len(a.conns))
	for _, cs := range a.conns {
		candidates = append(candidates, PathCandidate{Addr: cs.addr, RTT: cs.conn.SmoothedRTT()})
	}
	current := a.selected
	selected, ok := a.selector.Select(current, candidates)
	if !ok {
		a.mu.Unlock()
		return
	}
	if current != nil && current.String() == selected.String() {
		a.mu.Unlock()
		return
	}
	sel := selected
	a.selected = &sel
	a.mu.Unlock()
	a.watcher.Send(PathEvent{Kind: PathEventSelected, Addr: selected})
}

// TriggerHolepunch attempts to open a new direct path by NAT traversal. In this
// build it always returns [ErrExtensionNotNegotiated]: hole-punching lives
// inside qng's QNT extension (X2), which is not implemented. The actor falls
// back to the relay path and any pre-validated direct path. See iroh/DESIGN.md
// §3.4.
func (a *RemoteStateActor) TriggerHolepunch() error {
	return ErrExtensionNotNegotiated
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

// SendDatagram routes a datagram toward the remote via send. If a path is
// selected it sends there; otherwise it sends to every known path. It NEVER
// returns an error for an unreachable path: an unroutable datagram is treated as
// lost so QUIC loss recovery handles it (the socket-core blackhole invariant,
// iroh/src/socket/remote_map/remote_state.rs:782). send's bool result is
// advisory only.
//
// In the live single-path build qng addresses its datagrams to a concrete path
// directly through the MagicConn, so this method backs the Mixed-EndpointId send
// path (DESIGN.md §3.1) which is exercised by unit tests rather than the QUIC
// data plane in this slice.
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
