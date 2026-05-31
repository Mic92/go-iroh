package iroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
)

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

type endpointQNTFakeConn struct {
	addr     socket.Addr
	done     chan struct{}
	natAddrs []netip.AddrPort
}

func (c *endpointQNTFakeConn) SmoothedRTT() time.Duration { return time.Millisecond }
func (c *endpointQNTFakeConn) Done() <-chan struct{}      { return c.done }
func (c *endpointQNTFakeConn) RemoteAddr() socket.Addr    { return c.addr }
func (c *endpointQNTFakeConn) MultipathNegotiated() bool  { return true }
func (c *endpointQNTFakeConn) AddNATTraversalAddress(addr netip.AddrPort) error {
	c.natAddrs = append(c.natAddrs, addr)
	return nil
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
	if err := conn.qc.AddNATTraversalAddress(candidates[0]); !errors.Is(err, quic.ErrNATTraversalNotNegotiated) {
		t.Fatalf("AddNATTraversalAddress = %v, want %v", err, quic.ErrNATTraversalNotNegotiated)
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
