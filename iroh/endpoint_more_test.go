package iroh

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
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
