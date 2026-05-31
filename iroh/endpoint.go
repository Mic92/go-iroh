package iroh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/internal/netreport"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/watch"
)

// Endpoint is a bound iroh node: it owns a secret key, a UDP socket, and the
// QUIC transport used to dial and accept connections. Create one with [Bind].
//
// An Endpoint is safe for concurrent use. Close it with [Endpoint.Close].
type Endpoint struct {
	secretKey base.SecretKey
	alpns     [][]byte

	udp          *net.UDPConn
	sock         *socket.Socket
	magic        *socket.MagicConn
	relay        *socket.RelayTransport // nil when relays are disabled
	serveStop    context.CancelFunc
	transport    *quic.Transport
	listener     *quic.EarlyListener
	quicConf     *quic.Config
	sessionCache *SessionCache

	// remotes is the per-remote state registry. The endpoint owns it: it
	// registers every established connection so the actor for that remote can
	// track paths and select between them (DESIGN.md §3.3). The actor never holds
	// a reference back to the endpoint, so there is no import cycle.
	remotes *socket.RemoteMap
	lookup  *AddressLookupServices

	mu          sync.Mutex
	closed      bool
	externalNAT []netip.AddrPort
	netReport   netReportRunner
}

// config holds the options assembled by [Option] values before [Bind].
type config struct {
	secretKey       base.SecretKey
	haveKey         bool
	alpns           [][]byte
	bindAddr        netip.AddrPort
	haveBindAddr    bool
	relayMode       relay.Mode
	lookup          *AddressLookupServices
	enableNetReport bool
	netReport       netReportRunner
}

// Option configures an [Endpoint] at [Bind] time.
type Option func(*config) error

type netReportRunner func(context.Context) (*netreport.Report, error)

// WithSecretKey sets the endpoint's identity. If unset, [Bind] generates a
// random key.
func WithSecretKey(sk base.SecretKey) Option {
	return func(c *config) error {
		c.secretKey = sk
		c.haveKey = true
		return nil
	}
}

// WithALPNs sets the ALPN protocols this endpoint accepts on incoming
// connections. Each ALPN is an arbitrary byte string.
func WithALPNs(alpns ...[]byte) Option {
	return func(c *config) error {
		c.alpns = append(c.alpns, alpns...)
		return nil
	}
}

// WithBindAddr sets the local UDP address to bind. The default is an
// OS-assigned port on the unspecified address.
func WithBindAddr(addr netip.AddrPort) Option {
	return func(c *config) error {
		c.bindAddr = addr
		c.haveBindAddr = true
		return nil
	}
}

// WithAddressLookup sets the address-lookup services the endpoint uses to
// resolve additional addresses for a remote endpoint (pkarr, DNS, in-memory).
// The per-remote state machine consults them through its resolve hook. When
// unset, the endpoint does no lookup-driven address resolution and connects only
// to the addresses passed to [Endpoint.Connect].
func WithAddressLookup(s *AddressLookupServices) Option {
	return func(c *config) error {
		c.lookup = s
		return nil
	}
}

// WithRelayMode selects which relay servers the endpoint uses. The default is
// [relay.ModeDisabled] (no relays), matching this build's direct-only default.
// Pass [relay.ModeDefault], [relay.ModeStaging], or [relay.ModeCustom] to enable
// relay connectivity.
func WithRelayMode(mode relay.Mode) Option {
	return func(c *config) error {
		c.relayMode = mode
		return nil
	}
}

// WithNetReport enables one background net_report run after [Bind]. When relays
// are configured, the report's QAD-derived global addresses are advertised as
// local QNT candidates for active remotes.
func WithNetReport() Option {
	return func(c *config) error {
		c.enableNetReport = true
		return nil
	}
}

// Bind binds a UDP socket and returns a ready [Endpoint].
//
// By default the endpoint enables qng datagrams and advertises the iroh
// multipath path limit. Direct UDP works without relays; relay transport,
// address discovery, and QNT hole-punching are separate connectivity features.
func Bind(ctx context.Context, opts ...Option) (*Endpoint, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}
	if !c.haveKey {
		sk, err := base.GenerateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("iroh: generate key: %w", err)
		}
		c.secretKey = sk
	}

	bind := c.bindAddr
	if !c.haveBindAddr {
		bind = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bind))
	if err != nil {
		return nil, fmt.Errorf("iroh: bind udp: %w", err)
	}

	quicConf := &quic.Config{
		KeepAlivePeriod:                HeartbeatInterval,
		MaxIdleTimeout:                 RelayPathMaxIdleTimeout,
		EnableDatagrams:                true,
		InitialMaxPathID:               initialMaxPathID(),
		MaxRemoteNATTraversalAddresses: maxRemoteNATTraversalAddresses(),
		// Accept 0-RTT early data on incoming connections that resume a prior
		// session. Allow0RTT is ignored for dialed connections, so sharing this
		// config with Connect is safe. Mirrors the Rust server enabling early
		// data with max_early_data_size = u32::MAX (iroh/src/tls.rs:118).
		Allow0RTT: true,
		// Remember the server's NEW_TOKEN frames so a resuming dial can present a
		// validation token. Without it the server cannot validate the client's
		// address ahead of the handshake and rejects 0-RTT. Tokens are keyed by
		// the TLS server name (ServerName(id)), the same per-peer bucketing the
		// session cache uses. The capacity matches maxTLSTickets.
		TokenStore: quic.NewLRUTokenStore(32, 8),
	}

	// The QUIC transport is driven over the magic socket rather than the raw
	// UDP socket: a single net.PacketConn that multiplexes every iroh path. The
	// magic socket always carries the direct-IP transport and, when relays are
	// configured, a relay transport (DESIGN.md §3).
	sock := socket.NewSocket()

	var relayActor *socket.RelayActor
	relayMap := c.relayMode.Map()
	if !relayMap.IsEmpty() {
		relayActor = socket.NewRelayActor(socket.RelayActorConfig{
			SecretKey: c.secretKey,
			Map:       relayMap,
		})
	}

	magic := socket.NewMagicConnWithRelay(sock, udp, relayActor)
	serveCtx, serveStop := context.WithCancel(context.Background())
	go magic.Serve(serveCtx)

	ep := &Endpoint{
		secretKey:    c.secretKey,
		alpns:        c.alpns,
		udp:          udp,
		sock:         sock,
		magic:        magic,
		relay:        magic.Relay(),
		serveStop:    serveStop,
		transport:    &quic.Transport{Conn: magic, ConnectionIDLength: 8},
		quicConf:     quicConf,
		sessionCache: NewSessionCache(),
		lookup:       c.lookup,
		netReport:    endpointNetReportRunner(c, relayMap),
	}
	// The per-remote state registry shares the serve context: its actors stop
	// when the endpoint's recv loop stops. Its resolve hook is backed by the
	// endpoint's address-lookup services (slice G), passed down as a func value
	// so internal/socket does not import iroh.
	ep.remotes = socket.NewRemoteMap(serveCtx, socket.BiasedRttPathSelector{}, ep.resolveFunc())

	// Select a home relay. net_report-based selection (latency probing) is a
	// later slice; until then the lexically-first configured relay is the home
	// relay, which is enough to make relay connectivity work.
	if ep.relay != nil {
		if urls := relayMap.URLs(); len(urls) > 0 {
			ep.relay.SetHomeRelay(urls[0])
		}
	}

	if len(c.alpns) > 0 {
		if err := ep.startListener(); err != nil {
			serveStop()
			udp.Close()
			return nil, err
		}
	}
	if ep.netReport != nil {
		go func() { _ = ep.refreshNetReport(serveCtx) }()
	}
	return ep, nil
}

func endpointNetReportRunner(c config, relayMap *relay.Map) netReportRunner {
	if c.netReport != nil {
		return c.netReport
	}
	if !c.enableNetReport || relayMap.IsEmpty() {
		return nil
	}
	client := netreport.NewClient(relayMap)
	return func(ctx context.Context) (*netreport.Report, error) {
		return client.GetReport(ctx, netreport.IfStateDetails{HaveV4: true, HaveV6: true}, false)
	}
}

func initialMaxPathID() *uint32 {
	v := uint32(MaxMultipathPaths)
	return &v
}

func maxRemoteNATTraversalAddresses() *uint8 {
	v := uint8(MaxQNTAddresses)
	return &v
}

// startListener begins accepting incoming connections with the current ALPNs.
// It uses an early listener so the QUIC stack can accept 0-RTT early data from
// peers that resume a prior session.
func (e *Endpoint) startListener() error {
	serverTLS, err := serverTLSConfig(e.secretKey, alpnsToStrings(e.alpns))
	if err != nil {
		return err
	}
	ln, err := e.transport.ListenEarly(serverTLS, e.quicConf)
	if err != nil {
		return fmt.Errorf("iroh: listen: %w", err)
	}
	e.listener = ln
	return nil
}

// SetALPNs sets the ALPN protocols the endpoint accepts and begins (or
// continues) listening for incoming connections. It is the Go analog of the Rust
// Endpoint::set_alpns (iroh/src/endpoint.rs), used by [Router.Spawn] to register
// every protocol's ALPN at once.
//
// SetALPNs must be called before any [Endpoint.Accept]: it starts the listener.
// It cannot change the ALPNs of an already-started listener; calling it a second
// time, or after binding with [WithALPNs], returns an error. Pass each ALPN as
// an arbitrary byte string.
func (e *Endpoint) SetALPNs(alpns [][]byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEndpointClosed
	}
	if e.listener != nil {
		return errors.New("iroh: ALPNs already set; cannot change a running listener")
	}
	e.alpns = alpns
	return e.startListener()
}

// ID returns the endpoint's identifier (its ed25519 public key).
func (e *Endpoint) ID() base.EndpointId { return e.secretKey.Public() }

// SecretKey returns the endpoint's secret key.
func (e *Endpoint) SecretKey() base.SecretKey { return e.secretKey }

// LocalAddr returns the bound UDP address.
func (e *Endpoint) LocalAddr() netip.AddrPort {
	return e.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// localNATTraversalCandidates returns concrete local direct addresses this
// endpoint can hand to qng's QNT state. The default bind address is unspecified
// ([::]:port), which is not a usable candidate and must not be advertised.
// QAD-derived external addresses are appended after the same canonicalization
// and validity checks.
func (e *Endpoint) localNATTraversalCandidates() []netip.AddrPort {
	var addrs []netip.AddrPort
	if addr, ok := canonicalNATTraversalCandidate(e.LocalAddr()); ok {
		addrs = appendUniqueNATTraversalCandidate(addrs, addr)
	}
	e.mu.Lock()
	external := append([]netip.AddrPort(nil), e.externalNAT...)
	e.mu.Unlock()
	for _, addr := range external {
		addrs = appendUniqueNATTraversalCandidate(addrs, addr)
	}
	return addrs
}

func (e *Endpoint) setExternalNATTraversalCandidates(addrs ...netip.AddrPort) bool {
	var next []netip.AddrPort
	for _, addr := range addrs {
		next = appendUniqueNATTraversalCandidate(next, addr)
	}

	e.mu.Lock()
	if equalAddrPorts(e.externalNAT, next) {
		e.mu.Unlock()
		return false
	}
	e.externalNAT = next
	e.mu.Unlock()

	e.advertiseNATTraversalCandidates()
	return true
}

func (e *Endpoint) applyNetReport(report netreport.Report) bool {
	return e.setExternalNATTraversalCandidates(report.GlobalV4, report.GlobalV6)
}

func (e *Endpoint) refreshNetReport(ctx context.Context) error {
	if e.netReport == nil {
		return nil
	}
	report, err := e.netReport(ctx)
	if report != nil {
		e.applyNetReport(*report)
	}
	if err != nil {
		return fmt.Errorf("iroh: netreport: %w", err)
	}
	return nil
}

func (e *Endpoint) advertiseNATTraversalCandidates() {
	if e.remotes == nil {
		return
	}
	candidates := e.localNATTraversalCandidates()
	e.remotes.AddNATTraversalAddresses(candidates)
}

func canonicalNATTraversalCandidate(addr netip.AddrPort) (netip.AddrPort, bool) {
	if !addr.IsValid() || addr.Port() == 0 || addr.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), true
}

func appendUniqueNATTraversalCandidate(addrs []netip.AddrPort, addr netip.AddrPort) []netip.AddrPort {
	addr, ok := canonicalNATTraversalCandidate(addr)
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

func equalAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Addr returns the endpoint's [base.EndpointAddr] from currently-known local
// information: its id, the bound direct address, and (when relays are enabled
// and a home relay is connected) its home relay URL. Later slices add reflexive
// addresses.
func (e *Endpoint) Addr() base.EndpointAddr {
	a := base.NewEndpointAddr(e.ID()).WithIP(e.LocalAddr())
	if e.relay != nil {
		if st := e.relay.HomeRelayStatus().Get(); st != nil {
			a = a.WithRelayURL(st.URL)
		}
	}
	return a
}

// RelayStatus is the connection status of the endpoint's home relay, observed
// through [Endpoint.HomeRelayStatus].
type RelayStatus = socket.RelayStatus

// HomeRelayStatus returns a watcher over the endpoint's home relay connection
// status. The watched value is nil until a home relay is selected; it updates
// whenever the home relay or its connection state changes. When relays are
// disabled the watcher always reports nil.
//
// It is the Go analog of the Rust Endpoint::home_relay_status
// (iroh/src/endpoint.rs:1324).
func (e *Endpoint) HomeRelayStatus() watch.Watcher[*RelayStatus] {
	if e.relay == nil {
		return watch.NewValue[*RelayStatus](nil).Watch()
	}
	return e.relay.HomeRelayStatus()
}

// Online blocks until the endpoint has a connected home relay, or until ctx is
// done. It returns nil once connected, or ctx.Err() if the context ends first.
// When relays are disabled it returns [ErrNoRelay] immediately.
//
// It is the Go analog of the Rust Endpoint::online (iroh/src/endpoint.rs:1295).
func (e *Endpoint) Online(ctx context.Context) error {
	if e.relay == nil {
		return ErrNoRelay
	}
	w := e.relay.HomeRelayStatus()
	for {
		if st := w.Get(); st != nil && st.IsConnected() {
			return nil
		}
		if _, err := w.Updated(ctx); err != nil {
			return err
		}
	}
}

// ErrNoRelay is returned by [Endpoint.Online] when the endpoint has no relays
// configured (relays disabled), so it can never come online via a relay.
var ErrNoRelay = errors.New("iroh: no relays configured")

// ErrEndpointClosed is returned by operations on a closed [Endpoint].
var ErrEndpointClosed = errors.New("iroh: endpoint closed")

// ErrSelfConnect is returned by [Endpoint.Connect] when asked to dial the
// endpoint's own id.
var ErrSelfConnect = errors.New("iroh: cannot connect to self")

// ErrNoAddress is returned when an [base.EndpointAddr] has no usable address:
// no direct IP and no relay URL (or relays are disabled on this endpoint).
var ErrNoAddress = errors.New("iroh: no reachable address for endpoint")

// Connect dials the endpoint identified by addr and negotiates alpn, returning
// an established [Conn]. It tries the direct IP addresses in addr in order, then
// (if relays are enabled) the relay URLs in addr. A relay path carries the QUIC
// handshake over a relay mapped address that routes through the relay transport.
func (e *Endpoint) Connect(ctx context.Context, addr base.EndpointAddr, alpn []byte) (*Conn, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if addr.Id.Equal(e.ID()) {
		return nil, ErrSelfConnect
	}

	dials := e.dialTargets(addr)
	if len(dials) == 0 {
		return nil, ErrNoAddress
	}

	clientTLS, err := clientTLSConfig(e.secretKey, addr.Id, []string{string(alpn)}, e.sessionCache)
	if err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}

	// DialEarly attempts 0-RTT: if the session cache holds a valid ticket for
	// addr.Id (bucketed by its SNI), the QUIC stack restores the session and
	// DialEarly returns a Conn ready for 0-RTT early data before the handshake
	// completes. Data written to such a Conn is sent as 0-RTT. Without a ticket,
	// DialEarly returns only once the handshake completes, exactly like Dial.
	//
	// The peer identity is the dialed addr.Id; the RFC 7250 VerifyConnection
	// check enforces it once the handshake completes, so a 0-RTT Conn carries an
	// asserted-but-not-yet-authenticated identity. Callers that sent 0-RTT data
	// wait on [Conn.HandshakeComplete] and check [Conn.Used0RTT] to learn whether
	// the server accepted the early data; on rejection the data must be resent.
	var firstErr error
	for _, target := range dials {
		qc, err := e.transport.DialEarly(ctx, target, clientTLS, e.quicConf)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		conn, err := newConn(qc, addr.Id, alpn, SideClient)
		if err != nil {
			return nil, err
		}
		e.registerConn(addr.Id, qc)
		return conn, nil
	}
	return nil, fmt.Errorf("iroh: connect to %s: %w", addr.Id, firstErr)
}

// dialTargets returns the ordered net.Addr dial targets for addr: real UDP
// addresses for direct IPs, then relay mapped addresses (when relays are
// enabled) for each relay URL. Each relay target is registered in the
// mapped-address table so the magic socket routes its QUIC packets to the relay
// transport.
func (e *Endpoint) dialTargets(addr base.EndpointAddr) []net.Addr {
	var targets []net.Addr
	for _, ip := range addr.IPAddrs() {
		targets = append(targets, net.UDPAddrFromAddrPort(ip))
	}
	if e.relay != nil {
		for _, u := range addr.RelayURLs() {
			m := e.sock.RelayMappedAddrFor(u, addr.Id)
			targets = append(targets, net.UDPAddrFromAddrPort(m.AddrPort()))
		}
	}
	return targets
}

// Accept blocks until an incoming connection completes its handshake, then
// returns it as a [Conn]. It returns an error if the endpoint is closed or has
// no configured ALPNs. ctx cancels the wait.
//
// In this build Accept returns a fully-established connection; the pre-handshake
// Incoming/Connecting controls in iroh/DESIGN.md arrive with a later slice.
func (e *Endpoint) Accept(ctx context.Context) (*Conn, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if e.listener == nil {
		return nil, errors.New("iroh: no ALPNs configured; nothing to accept")
	}
	qc, err := e.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	// The early listener returns connections before the handshake completes so
	// the QUIC stack can buffer 0-RTT early data. The peer's identity is only
	// authenticated once the handshake finishes, so wait for it before reading
	// the verified peer id and negotiated ALPN. Any 0-RTT streams are preserved
	// and surface through Accept{,Uni}Stream after this returns.
	select {
	case <-qc.HandshakeComplete():
	case <-ctx.Done():
		qc.CloseWithError(0, "")
		return nil, ctx.Err()
	}
	remote, err := peerEndpointId(qc.ConnectionState().TLS)
	if err != nil {
		qc.CloseWithError(0, "bad peer certificate")
		return nil, err
	}
	alpn := []byte(qc.ConnectionState().TLS.NegotiatedProtocol)
	conn, err := newConn(qc, remote, alpn, SideServer)
	if err != nil {
		return nil, err
	}
	e.registerConn(remote, qc)
	return conn, nil
}

// registerConn registers an established QUIC connection with the per-remote
// state actor for remote, so the actor tracks its path and selects between
// available paths. Registration failures are non-fatal: the connection still
// works; it just is not path-managed. It mirrors the Rust RemoteMap::add_connection
// (iroh/src/socket/remote_map.rs:273).
func (e *Endpoint) registerConn(remote base.EndpointId, qc *quic.Conn) {
	if e.remotes == nil {
		return
	}
	addr := e.sock.PathAddr(remote, qc.RemoteAddr())
	e.remotes.AddConnection(remote, newConnAdapter(qc, addr))
	if !qc.ConnectionState().MultipathNegotiated {
		return
	}
	// Candidate seeding is opportunistic: QNT may still be disabled or
	// incomplete, and path management must not make an otherwise-established
	// connection fail. The actor/qng layers keep the failure visible to explicit
	// hole-punch calls.
	_ = e.remotes.Actor(remote).AddNATTraversalAddresses(e.localNATTraversalCandidates())
}

// resolveFunc returns the address-lookup hook the RemoteMap actors use to
// resolve additional addresses for a remote, or nil when no lookup services are
// configured. It adapts the iroh AddressLookupServices stream to the socket
// package's ResolveFunc, so internal/socket does not import iroh.
func (e *Endpoint) resolveFunc() socket.ResolveFunc {
	lookup := e.lookup
	if lookup == nil {
		return nil
	}
	return func(ctx context.Context, id base.EndpointId) ([]base.TransportAddr, error) {
		var addrs []base.TransportAddr
		var lastErr error
		for res := range lookup.Resolve(ctx, id) {
			if res.Err != nil {
				lastErr = res.Err
				continue
			}
			addrs = append(addrs, res.Item.Addr().Addrs()...)
		}
		if len(addrs) == 0 && lastErr != nil {
			return nil, lastErr
		}
		return addrs, nil
	}
}

// Close shuts down the endpoint: it stops accepting, closes the QUIC transport,
// and releases the UDP socket. In-flight connections are not forcibly closed.
func (e *Endpoint) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	var firstErr error
	if e.listener != nil {
		if err := e.listener.Close(); err != nil {
			firstErr = err
		}
	}
	// Stop the magic socket's recv loop, then close the QUIC transport (which
	// closes the MagicConn and, through it, the UDP socket).
	e.serveStop()
	if err := e.transport.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := e.udp.Close(); err != nil && firstErr == nil && !errors.Is(err, net.ErrClosed) {
		firstErr = err
	}
	return firstErr
}

func (e *Endpoint) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// alpnsToStrings converts ALPN byte strings to the []string the TLS config
// expects. Go strings hold arbitrary bytes, so the conversion is lossless.
func alpnsToStrings(alpns [][]byte) []string {
	out := make([]string, len(alpns))
	for i, a := range alpns {
		out[i] = string(a)
	}
	return out
}
