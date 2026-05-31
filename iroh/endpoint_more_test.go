package iroh

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/internal/netreport"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/relay"
)

func withNetReportRunner(run netReportRunner) Option {
	return func(c *config) error {
		c.enableNetReport = true
		c.netReport = run
		return nil
	}
}

// TestEndpointSecretKey verifies SecretKey returns the configured key and that
// its public half matches the endpoint id.
func TestEndpointSecretKey(t *testing.T) {
	ctx := context.Background()
	sk, _ := base.GenerateSecretKey()
	ep, err := Bind(ctx, WithSecretKey(sk))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	if !ep.SecretKey().Public().Equal(sk.Public()) {
		t.Errorf("SecretKey().Public() = %s, want %s", ep.SecretKey().Public(), sk.Public())
	}
	if !ep.SecretKey().Public().Equal(ep.ID()) {
		t.Errorf("SecretKey().Public() = %s, but ID() = %s", ep.SecretKey().Public(), ep.ID())
	}
}

func TestEndpointLifecycleAddressSurface(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	if got := ep.BoundSockets(); len(got) != 1 || got[0] != ep.LocalAddr() {
		t.Fatalf("BoundSockets = %v, want [%v]", got, ep.LocalAddr())
	}
	select {
	case <-ep.Closed():
		t.Fatal("Closed channel fired before Close")
	default:
	}

	w := ep.WatchAddr()
	if got := w.Get(); len(got.IPAddrs()) != 1 || got.IPAddrs()[0] != ep.LocalAddr() {
		t.Fatalf("WatchAddr initial = %v, want local %v", got.IPAddrs(), ep.LocalAddr())
	}
	if got, err := w.Updated(ctx); err != nil || len(got.IPAddrs()) != 1 || got.IPAddrs()[0] != ep.LocalAddr() {
		t.Fatalf("WatchAddr first Updated = %v, %v", got.IPAddrs(), err)
	}

	external := netip.MustParseAddrPort("203.0.113.44:4444")
	ep.AddExternalAddr(ctx, external)
	got, err := w.Updated(ctx)
	if err != nil {
		t.Fatalf("WatchAddr update: %v", err)
	}
	if !containsAddrPort(got.IPAddrs(), external) {
		t.Fatalf("WatchAddr IPs = %v, want external %v", got.IPAddrs(), external)
	}
	if !containsAddrPort(ep.Addr().IPAddrs(), external) {
		t.Fatalf("Addr IPs = %v, want external %v", ep.Addr().IPAddrs(), external)
	}

	if err := ep.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-ep.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed channel did not fire")
	}
}

func containsAddrPort(addrs []netip.AddrPort, want netip.AddrPort) bool {
	for _, addr := range addrs {
		if addr == want {
			return true
		}
	}
	return false
}

// TestEndpointWithAddressLookup verifies the option wires the lookup services
// into the endpoint's resolve hook: with a lookup configured the hook resolves
// a registered id to its addresses, and without one no hook is installed.
func TestEndpointWithAddressLookup(t *testing.T) {
	ctx := context.Background()

	// Without WithAddressLookup, the endpoint installs no resolve hook.
	plain, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close(ctx)
	if plain.resolveFunc() != nil {
		t.Error("resolveFunc() != nil without WithAddressLookup, want nil")
	}

	// With WithAddressLookup, the hook resolves through the registered services.
	sk, _ := base.GenerateSecretKey()
	id := sk.Public()
	ip := netip.MustParseAddrPort("1.2.3.4:1234")

	mem := NewMemoryLookup()
	mem.AddEndpointInfo(dns.NewEndpointInfo(id).WithIPAddrs(ip))
	var svcs AddressLookupServices
	svcs.Add(mem)

	ep, err := Bind(ctx, WithAddressLookup(&svcs))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	resolve := ep.resolveFunc()
	if resolve == nil {
		t.Fatal("resolveFunc() = nil with WithAddressLookup, want non-nil")
	}
	addrs, err := resolve(ctx, id)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var found bool
	for _, a := range addrs {
		if ipa, ok := a.(base.IPAddr); ok && ipa.Addr == ip {
			found = true
		}
	}
	if !found {
		t.Errorf("resolved addrs = %v, want one containing %s", addrs, ip)
	}
}

func TestEndpointLocalNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()

	unspecified, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unspecified.Close(ctx)
	if got := unspecified.localNATTraversalCandidates(); len(got) != 0 {
		t.Fatalf("default localNATTraversalCandidates = %v, want none for unspecified bind", got)
	}

	loopback, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Close(ctx)
	got := loopback.localNATTraversalCandidates()
	if len(got) != 1 {
		t.Fatalf("loopback localNATTraversalCandidates len = %d, want 1; got %v", len(got), got)
	}
	if got[0] != loopback.LocalAddr() {
		t.Fatalf("loopback localNATTraversalCandidates = %v, want [%v]", got, loopback.LocalAddr())
	}

	external4 := netip.MustParseAddrPort("203.0.113.10:4444")
	external6 := netip.MustParseAddrPort("[2001:db8::10]:5555")
	if !loopback.setExternalNATTraversalCandidates(external4, external6) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	got = loopback.localNATTraversalCandidates()
	want := []netip.AddrPort{loopback.LocalAddr(), external4, external6}
	if !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates with externals = %v, want %v", got, want)
	}
	if loopback.setExternalNATTraversalCandidates(external4, external6) {
		t.Fatal("same setExternalNATTraversalCandidates = true, want false")
	}
}

func TestEndpointExternalNATTraversalCandidatesCanonicalize(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	bound := ep.LocalAddr()
	mapped := netip.AddrPortFrom(netip.AddrFrom16(bound.Addr().As16()), bound.Port())
	externalMapped := netip.MustParseAddrPort("[::ffff:198.51.100.10]:4444")
	externalCanon := netip.MustParseAddrPort("198.51.100.10:4444")
	if !ep.setExternalNATTraversalCandidates(
		mapped,
		externalMapped,
		externalCanon,
		netip.AddrPort{},
		netip.MustParseAddrPort("0.0.0.0:4444"),
		netip.MustParseAddrPort("198.51.100.11:0"),
	) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	want := []netip.AddrPort{
		bound,
		externalCanon,
	}
	if got := ep.localNATTraversalCandidates(); !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates = %v, want %v", got, want)
	}
}

func TestEndpointExternalNATTraversalCandidatesReadvertiseActiveRemotes(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	remote, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	external := netip.MustParseAddrPort("203.0.113.10:4444")
	if !ep.setExternalNATTraversalCandidates(external) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	want := []netip.AddrPort{ep.LocalAddr(), external}
	if !equalAddrPorts(conn.natAddrs, want) {
		t.Fatalf("advertised candidates = %v, want %v", conn.natAddrs, want)
	}
}

func TestEndpointExternalNATTraversalCandidatesRemoveStaleRemoteCandidate(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	remote, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	oldExternal := netip.MustParseAddrPort("203.0.113.10:4444")
	newExternal := netip.MustParseAddrPort("203.0.113.11:5555")
	if !ep.setExternalNATTraversalCandidates(oldExternal) {
		t.Fatal("first setExternalNATTraversalCandidates = false, want true")
	}
	if !ep.setExternalNATTraversalCandidates(newExternal) {
		t.Fatal("replacement setExternalNATTraversalCandidates = false, want true")
	}

	wantCurrent := []netip.AddrPort{ep.LocalAddr(), newExternal}
	if !equalAddrPorts(conn.currentNAT, wantCurrent) {
		t.Fatalf("current QNT candidates = %v, want %v", conn.currentNAT, wantCurrent)
	}
	if len(conn.removedNAT) != 1 || conn.removedNAT[0] != oldExternal {
		t.Fatalf("removed QNT candidates = %v, want [%v]", conn.removedNAT, oldExternal)
	}
}

func TestEndpointApplyNetReportNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	global4 := netip.MustParseAddrPort("[::ffff:198.51.100.10]:4444")
	global4Canon := netip.MustParseAddrPort("198.51.100.10:4444")
	global6 := netip.MustParseAddrPort("[2001:db8::10]:5555")
	if !ep.applyNetReport(netreport.Report{GlobalV4: global4, GlobalV6: global6}) {
		t.Fatal("applyNetReport = false, want true")
	}
	want := []netip.AddrPort{ep.LocalAddr(), global4Canon, global6}
	if got := ep.localNATTraversalCandidates(); !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates = %v, want %v", got, want)
	}
	if ep.applyNetReport(netreport.Report{GlobalV4: global4Canon, GlobalV6: global6}) {
		t.Fatal("same applyNetReport = true, want false")
	}
}

func TestEndpointApplyEmptyNetReportClearsExternalNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	remote, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	external := netip.MustParseAddrPort("203.0.113.10:4444")
	if !ep.applyNetReport(netreport.Report{GlobalV4: external}) {
		t.Fatal("applyNetReport with global = false, want true")
	}
	if !ep.applyNetReport(netreport.Report{}) {
		t.Fatal("empty applyNetReport = false, want true")
	}
	if got, want := ep.localNATTraversalCandidates(), []netip.AddrPort{ep.LocalAddr()}; !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates after empty report = %v, want %v", got, want)
	}
	if got, want := conn.currentNAT, []netip.AddrPort{ep.LocalAddr()}; !equalAddrPorts(got, want) {
		t.Fatalf("current QNT candidates = %v, want %v", got, want)
	}
	if len(conn.removedNAT) != 1 || conn.removedNAT[0] != external {
		t.Fatalf("removed QNT candidates = %v, want [%v]", conn.removedNAT, external)
	}
}

func TestEndpointWithNetReportAdvertisesCandidates(t *testing.T) {
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	external := netip.MustParseAddrPort("203.0.113.10:4444")
	ep, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		withNetReportRunner(func(ctx context.Context) (*netreport.Report, error) {
			close(started)
			select {
			case <-release:
				return &netreport.Report{GlobalV4: external}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("netreport runner did not start")
	}

	remote, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	close(release)
	want := []netip.AddrPort{ep.LocalAddr(), external}
	deadline := time.After(2 * time.Second)
	for !equalAddrPorts(conn.currentNATTraversalCandidates(), want) {
		select {
		case <-deadline:
			t.Fatalf("current QNT candidates = %v, want %v", conn.currentNATTraversalCandidates(), want)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestEndpointQADCandidatesOpenSelectedQNTRouteDataPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	relayServer := newEchoRelayServer(t)
	relayURL := relayServer.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-qad-qnt-data-path/0"
	server, err := Bind(ctx, WithALPNs([]byte(alpn)), WithRelayMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)
	client, err := Bind(ctx, WithRelayMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	serverQAD := loopbackQADCandidate(server)
	clientQAD := loopbackQADCandidate(client)
	if !server.applyNetReport(netreport.Report{GlobalV6: serverQAD}) {
		t.Fatal("server applyNetReport = false, want QAD candidate change")
	}
	if !client.applyNetReport(netreport.Report{GlobalV6: clientQAD}) {
		t.Fatal("client applyNetReport = false, want QAD candidate change")
	}
	if got, want := server.localNATTraversalCandidates(), []netip.AddrPort{serverQAD}; !equalAddrPorts(got, want) {
		t.Fatalf("server localNATTraversalCandidates = %v, want QAD-only %v", got, want)
	}
	if got, want := client.localNATTraversalCandidates(), []netip.AddrPort{clientQAD}; !equalAddrPorts(got, want) {
		t.Fatalf("client localNATTraversalCandidates = %v, want QAD-only %v", got, want)
	}

	type acceptResult struct {
		conn *Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		accepted <- acceptResult{conn: conn, err: err}
	}()

	conn, err := client.Connect(ctx, base.NewEndpointAddr(server.ID()).WithRelayURL(relayURL), []byte(alpn))
	if err != nil {
		t.Fatalf("relay Connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	res := <-accepted
	if res.err != nil {
		t.Fatalf("server Accept: %v", res.err)
	}
	serverConn := res.conn
	defer serverConn.CloseWithError(0, "")

	if !conn.MultipathNegotiated() || !serverConn.MultipathNegotiated() {
		t.Fatalf("MultipathNegotiated client=%v server=%v, want both true", conn.MultipathNegotiated(), serverConn.MultipathNegotiated())
	}

	clientActor := client.remotes.Actor(server.ID())
	waitForSelectedPath(t, ctx, clientActor, socket.RelayAddr(relayURL, server.ID()))
	waitForConnNATAddress(t, ctx, conn.qc, serverQAD)
	waitForConnNATAddress(t, ctx, serverConn.qc, clientQAD)

	if err := clientActor.TriggerHolepunch(); err != nil {
		t.Fatalf("TriggerHolepunch: %v", err)
	}
	path := waitForQNTRoutePath(t, ctx, conn.qc, serverQAD)
	waitForSelectedPath(t, ctx, clientActor, socket.IPAddr(serverQAD))

	const msg = "qad-qnt-route-datagram"
	if err := conn.qc.SendDatagramOnPath(path.ID, []byte(msg)); err != nil {
		t.Fatalf("SendDatagramOnPath(%d): %v", path.ID, err)
	}
	got, err := serverConn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("server ReadDatagram: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("server datagram = %q, want %q", got, msg)
	}
}

func loopbackQADCandidate(e *Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(netip.IPv6Loopback(), e.LocalAddr().Port())
}

func waitForConnNATAddress(t *testing.T, ctx context.Context, c *quic.Conn, want netip.AddrPort) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		addrs, err := c.NATTraversalAddresses()
		if err != nil {
			t.Fatalf("NATTraversalAddresses: %v", err)
		}
		for _, addr := range addrs {
			if addr == want {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for remote NAT address %v; last addrs=%v", want, addrs)
		case <-ticker.C:
		}
	}
}

func waitForQNTRoutePath(t *testing.T, ctx context.Context, c *quic.Conn, want netip.AddrPort) quic.PathInfo {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		paths := c.Paths()
		for _, p := range paths {
			if p.ID != 0 && p.Validated && p.RemoteAddr == want {
				return p
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for validated QNT route path %v; last paths=%v closeCause=%v", want, paths, context.Cause(c.Context()))
		case <-ticker.C:
		}
	}
}

func waitForSelectedPath(t *testing.T, ctx context.Context, a *socket.RemoteStateActor, want socket.Addr) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got, ok := a.SelectedPath(); ok && got.String() == want.String() {
			return
		}
		select {
		case <-ctx.Done():
			got, ok := a.SelectedPath()
			t.Fatalf("timed out waiting for selected path %s; last selected=%v ok=%v", want, got, ok)
		case <-ticker.C:
		}
	}
}

type endpointQNTFakeConn struct {
	addr       socket.Addr
	done       chan struct{}
	mu         sync.Mutex
	natAddrs   []netip.AddrPort
	removedNAT []netip.AddrPort
	currentNAT []netip.AddrPort
}

func (c *endpointQNTFakeConn) SmoothedRTT() time.Duration { return time.Millisecond }
func (c *endpointQNTFakeConn) Done() <-chan struct{}      { return c.done }
func (c *endpointQNTFakeConn) RemoteAddr() socket.Addr    { return c.addr }
func (c *endpointQNTFakeConn) MultipathNegotiated() bool  { return true }
func (c *endpointQNTFakeConn) AddNATTraversalAddress(addr netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.natAddrs = append(c.natAddrs, addr)
	c.currentNAT = appendUniqueNATTraversalCandidate(c.currentNAT, addr)
	return nil
}
func (c *endpointQNTFakeConn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removedNAT = append(c.removedNAT, addr)
	var next []netip.AddrPort
	for _, cur := range c.currentNAT {
		if cur != addr {
			next = append(next, cur)
		}
	}
	c.currentNAT = next
	return nil
}
func (c *endpointQNTFakeConn) currentNATTraversalCandidates() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netip.AddrPort(nil), c.currentNAT...)
}

func TestEndpointRegisterConnSeedsQNTCandidatesOpportunistically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const alpn = "iroh-qnt-handoff-test/0"
	server, err := Bind(ctx,
		WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	candidates := client.localNATTraversalCandidates()
	if len(candidates) == 0 {
		t.Fatal("client localNATTraversalCandidates = nil, want concrete loopback candidate")
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			accepted <- err
			return
		}
		accepted <- conn.CloseWithError(0, "")
	}()

	conn, err := client.Connect(ctx, base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), []byte(alpn))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.MultipathNegotiated() {
		t.Fatal("MultipathNegotiated = false, want true so registerConn attempts QNT handoff")
	}
	if err := conn.qc.AddNATTraversalAddress(candidates[0]); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// TestEndpointHomeRelayStatusNoRelay verifies that with relays disabled (the
// default), the home-relay watcher reports a nil status.
func TestEndpointHomeRelayStatusNoRelay(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(ctx)

	w := ep.HomeRelayStatus()
	if st := w.Get(); st != nil {
		t.Errorf("HomeRelayStatus().Get() = %v with relays disabled, want nil", st)
	}

	// Online returns ErrNoRelay immediately when relays are disabled.
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ep.Online(tctx); err != ErrNoRelay {
		t.Errorf("Online() = %v, want ErrNoRelay", err)
	}
}
