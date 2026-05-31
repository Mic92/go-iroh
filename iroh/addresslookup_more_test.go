package iroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
)

// TestMemoryLookupFromInfo checks the pre-populating constructor and the
// EndpointInfo accessor on the resolved item.
func TestMemoryLookupFromInfo(t *testing.T) {
	skA, _ := base.GenerateSecretKey()
	skB, _ := base.GenerateSecretKey()
	idA, idB := skA.Public(), skB.Public()
	relay := relayURL(t, "https://relay.example/")

	infoA := dns.NewEndpointInfo(idA).WithRelayURL(relay)
	infoB := dns.NewEndpointInfo(idB).WithIPAddrs(netip.MustParseAddrPort("1.2.3.4:1"))

	m := MemoryLookupFromInfo(infoA, infoB)

	for _, id := range []base.EndpointId{idA, idB} {
		results := drain(m.Resolve(context.Background(), id))
		if len(results) != 1 || results[0].Err != nil {
			t.Fatalf("Resolve(%s) = %+v, want one success", id, results)
		}
		// EndpointInfo accessor returns the discovered info for the right id.
		if !results[0].Item.EndpointInfo().Id.Equal(id) {
			t.Errorf("EndpointInfo().Id = %s, want %s", results[0].Item.EndpointInfo().Id, id)
		}
	}
}

// TestMemoryLookupSetEndpointInfo verifies SetEndpointInfo replaces all stored
// info and reports the previous entry.
func TestMemoryLookupSetEndpointInfo(t *testing.T) {
	sk, _ := base.GenerateSecretKey()
	id := sk.Public()
	m := NewMemoryLookup()

	first := dns.NewEndpointInfo(id).WithIPAddrs(netip.MustParseAddrPort("1.2.3.4:1"))
	prev, existed := m.SetEndpointInfo(first)
	if existed {
		t.Errorf("SetEndpointInfo on empty store reported existed=true")
	}
	if prev.HasAddrs() {
		t.Errorf("SetEndpointInfo returned non-empty previous data %v", prev.Addrs())
	}

	// Replacing returns the previous data and does not merge: only the new
	// address remains.
	second := dns.NewEndpointInfo(id).WithIPAddrs(netip.MustParseAddrPort("5.6.7.8:2"))
	prev, existed = m.SetEndpointInfo(second)
	if !existed {
		t.Errorf("SetEndpointInfo replacing existing reported existed=false")
	}
	if len(prev.IPAddrs()) != 1 || prev.IPAddrs()[0] != netip.MustParseAddrPort("1.2.3.4:1") {
		t.Errorf("previous IPAddrs = %v, want [1.2.3.4:1]", prev.IPAddrs())
	}

	got, ok := m.GetEndpointInfo(id)
	if !ok {
		t.Fatal("expected stored info after SetEndpointInfo")
	}
	if len(got.IPAddrs()) != 1 || got.IPAddrs()[0] != netip.MustParseAddrPort("5.6.7.8:2") {
		t.Errorf("after replace IPAddrs = %v, want [5.6.7.8:2] (replace, not merge)", got.IPAddrs())
	}
}

// TestFilteredAddressLookupResolveAndInner verifies the Inner accessor and that
// Resolve is delegated to the wrapped lookup unchanged.
func TestFilteredAddressLookupResolveAndInner(t *testing.T) {
	sk, _ := base.GenerateSecretKey()
	id := sk.Public()
	relay := relayURL(t, "https://relay.example/")

	mem := NewMemoryLookup()
	mem.AddEndpointInfo(dns.NewEndpointInfo(id).WithRelayURL(relay))

	f := NewFilteredAddressLookup(mem, IPOnlyFilter)

	// Inner returns the wrapped lookup: it resolves the entry added to mem.
	inner, ok := f.Inner().(MemoryLookup)
	if !ok {
		t.Fatalf("Inner() type = %T, want MemoryLookup", f.Inner())
	}
	if _, ok := inner.GetEndpointInfo(id); !ok {
		t.Error("Inner() is not the wrapped MemoryLookup: missing the added entry")
	}

	// Resolution is delegated unchanged: the memory entry resolves through.
	results := drain(f.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if !results[0].Item.EndpointID().Equal(id) {
		t.Errorf("resolved id = %s, want %s", results[0].Item.EndpointID(), id)
	}
}

// TestLookupErrorUnwrap checks LookupError wraps the underlying error for
// errors.Is/errors.As.
func TestLookupErrorUnwrap(t *testing.T) {
	sentinel := errors.New("boom")
	le := lookupErr("dns", sentinel)
	if !errors.Is(le, sentinel) {
		t.Errorf("errors.Is(LookupError, sentinel) = false, want true")
	}
	if got := le.Unwrap(); got != sentinel {
		t.Errorf("Unwrap() = %v, want %v", got, sentinel)
	}
}

// TestAddressLookupServicesLenIsEmptyClear covers the registry accessors.
func TestAddressLookupServicesLenIsEmptyClear(t *testing.T) {
	var svcs AddressLookupServices
	if !svcs.IsEmpty() {
		t.Errorf("zero registry IsEmpty() = false, want true")
	}
	if svcs.Len() != 0 {
		t.Errorf("zero registry Len() = %d, want 0", svcs.Len())
	}

	svcs.Add(NewMemoryLookup())
	svcs.Add(NewMemoryLookup())
	if svcs.Len() != 2 {
		t.Errorf("Len() = %d after two Adds, want 2", svcs.Len())
	}
	if svcs.IsEmpty() {
		t.Error("IsEmpty() = true after Add, want false")
	}

	svcs.Clear()
	if svcs.Len() != 0 || !svcs.IsEmpty() {
		t.Errorf("after Clear: Len()=%d IsEmpty()=%v, want 0/true", svcs.Len(), svcs.IsEmpty())
	}
}

// TestPkarrPublisherOptions verifies the publisher builder option setters take
// effect by exercising the resulting publisher against an in-memory relay: a
// custom filter publishes the address it selects, and the publisher resolves
// back through a paired resolver.
func TestPkarrPublisherOptions(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := base.GenerateSecretKey()
	id := sk.Public()
	relay := relayURL(t, "https://relay.example/")
	ip := netip.MustParseAddrPort("1.2.3.4:9999")

	// WithAddrFilter(IPOnlyFilter) overrides the default relay-only filter, so the
	// IP is published and the relay is dropped. WithTTL and WithRepublishInterval
	// are also set to confirm the chained builder returns a usable publisher.
	pub, err := NewPkarrPublisher(srv.URL).
		WithHTTPClient(srv.Client()).
		WithTTL(120).
		WithRepublishInterval(time.Hour).
		WithAddrFilter(IPOnlyFilter).
		Build(sk)
	if err != nil {
		t.Fatalf("Build publisher: %v", err)
	}
	defer pub.Close()

	pub.Publish(dns.NewEndpointData(
		base.RelayAddr{URL: relay},
		base.IPAddr{Addr: ip},
	))

	res, err := NewPkarrResolver(srv.URL).WithHTTPClient(srv.Client()).Build()
	if err != nil {
		t.Fatalf("Build resolver: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].Err == nil {
			addr := results[0].Item.Addr()
			if len(addr.RelayURLs()) != 0 {
				t.Fatalf("relay leaked past IPOnlyFilter: %v", addr.RelayURLs())
			}
			ips := addr.IPAddrs()
			if len(ips) != 1 || ips[0] != ip {
				t.Fatalf("IPAddrs = %v, want [%s]", ips, ip)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Resolve never succeeded: %+v", results)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestN0PkarrConstructors smoke-tests the number0 production constructors build
// without error and that the publisher's Resolve and the resolver's Publish are
// the documented no-ops.
func TestN0PkarrConstructors(t *testing.T) {
	sk, _ := base.GenerateSecretKey()

	pub, err := N0PkarrPublisher().Build(sk)
	if err != nil {
		t.Fatalf("N0PkarrPublisher Build: %v", err)
	}
	defer pub.Close()
	// A publisher does not resolve.
	if ch := pub.Resolve(context.Background(), sk.Public()); ch != nil {
		t.Error("PkarrPublisher.Resolve returned a non-nil channel, want nil")
	}

	res, err := N0PkarrResolver().Build()
	if err != nil {
		t.Fatalf("N0PkarrResolver Build: %v", err)
	}
	// A resolver does not publish: Publish is a no-op and must not panic.
	res.Publish(dns.NewEndpointData(base.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")}))
}

func TestPkarrDefaults(t *testing.T) {
	if N0DNSPkarrRelayProd != "https://dns.iroh.link/pkarr" {
		t.Fatalf("prod relay = %q", N0DNSPkarrRelayProd)
	}
	if N0DNSPkarrRelayStaging != "https://staging-dns.iroh.link/pkarr" {
		t.Fatalf("staging relay = %q", N0DNSPkarrRelayStaging)
	}
	if DefaultPkarrTTL != 30 {
		t.Fatalf("DefaultPkarrTTL = %d, want 30", DefaultPkarrTTL)
	}
	if DefaultRepublishInterval != 5*time.Minute {
		t.Fatalf("DefaultRepublishInterval = %v, want 5m", DefaultRepublishInterval)
	}
	pub := NewPkarrPublisher(N0DNSPkarrRelayProd)
	if pub.relayURL != N0DNSPkarrRelayProd {
		t.Fatalf("publisher relay = %q, want %q", pub.relayURL, N0DNSPkarrRelayProd)
	}
	if pub.ttl != DefaultPkarrTTL {
		t.Fatalf("publisher ttl = %d, want %d", pub.ttl, DefaultPkarrTTL)
	}
	if pub.republishInterval != DefaultRepublishInterval {
		t.Fatalf("publisher republish = %v, want %v", pub.republishInterval, DefaultRepublishInterval)
	}
	res := NewPkarrResolver(N0DNSPkarrRelayStaging)
	if res.relayURL != N0DNSPkarrRelayStaging {
		t.Fatalf("resolver relay = %q, want %q", res.relayURL, N0DNSPkarrRelayStaging)
	}
}

// TestN0DnsAddressLookup smoke-tests the number0 production DNS constructor and
// its no-op Publish.
func TestN0DnsAddressLookup(t *testing.T) {
	// nil resolver falls back to the system DNS resolver; construction must not
	// panic and Publish is a no-op.
	lookup := N0DnsAddressLookup(nil)
	lookup.Publish(dns.NewEndpointData(base.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")}))

	// With an explicit resolver, resolution uses the configured origin. A canned
	// TXT lookuper makes this deterministic.
	sk, _ := base.GenerateSecretKey()
	id := sk.Public()
	info := dns.NewEndpointInfo(id).WithRelayURL(relayURL(t, "https://relay.example/"))
	resolver := &dns.Resolver{Lookuper: &fakeTxtLookuper{values: info.ToTxtStrings()}}

	lookup = N0DnsAddressLookup(resolver)
	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if !results[0].Item.EndpointID().Equal(id) {
		t.Errorf("resolved id = %s, want %s", results[0].Item.EndpointID(), id)
	}
}
