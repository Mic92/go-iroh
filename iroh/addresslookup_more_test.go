package iroh

import (
	"context"
	"errors"
	"iter"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestMemoryLookupFromInfo checks the pre-populating constructor and the
// EndpointInfo accessor on the resolved item.
func TestMemoryLookupFromInfo(t *testing.T) {
	skA, _ := key.GenerateSecretKey()
	skB, _ := key.GenerateSecretKey()
	idA, idB := skA.Public().EndpointID(), skB.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")

	infoA := dns.EndpointInfo{ID: idA, Data: dns.NewEndpointData(netaddr.RelayAddr{URL: relay})}
	infoB := dns.EndpointInfo{ID: idB, Data: dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")})}

	m := MemoryLookupFromInfo(infoA, infoB)

	for _, id := range []key.EndpointID{idA, idB} {
		results := drain(m.Resolve(context.Background(), id))
		if len(results) != 1 || results[0].err != nil {
			t.Fatalf("Resolve(%s) = %+v, want one success", id, results)
		}
		// EndpointInfo accessor returns the discovered info for the right id.
		if !results[0].item.EndpointInfo().ID.Equal(id) {
			t.Errorf("EndpointInfo().ID = %s, want %s", results[0].item.EndpointInfo().ID, id)
		}
	}
}

// TestMemoryLookupSetEndpointInfo verifies SetEndpointInfo replaces all stored
// info and reports the previous entry.
func TestMemoryLookupSetEndpointInfo(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	m := NewMemoryLookup()

	first := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")})}
	prev, existed := m.SetEndpointInfo(first)
	if existed {
		t.Errorf("SetEndpointInfo on empty store reported existed=true")
	}
	if prev.HasAddrs() {
		t.Errorf("SetEndpointInfo returned non-empty previous data %v", prev.Addrs())
	}

	// Replacing returns the previous data and does not merge: only the new
	// address remains.
	second := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("5.6.7.8:2")})}
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
	if len(got.Data.IPAddrs()) != 1 || got.Data.IPAddrs()[0] != netip.MustParseAddrPort("5.6.7.8:2") {
		t.Errorf("after replace IPAddrs = %v, want [5.6.7.8:2] (replace, not merge)", got.Data.IPAddrs())
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

	svcs.AddResolver(NewMemoryLookup())
	svcs.AddPublisher(&recordingLookup{})
	if svcs.Len() != 2 {
		t.Errorf("Len() = %d after one resolver and one publisher, want 2", svcs.Len())
	}
	if svcs.IsEmpty() {
		t.Error("IsEmpty() = true after registration, want false")
	}

	svcs.Clear()
	if svcs.Len() != 0 || !svcs.IsEmpty() {
		t.Errorf("after Clear: Len()=%d IsEmpty()=%v, want 0/true", svcs.Len(), svcs.IsEmpty())
	}
}

func TestAddressLookupServicesResolveCancelOnEarlyBreak(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	info := endpointInfoWithIP(id, netip.MustParseAddrPort("127.0.0.1:1"))
	cancelled := make(chan struct{})

	resolver := AddressResolverFunc(func(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
		return func(yield func(Item, error) bool) {
			if !yield(NewItem(info, "blocking", nil), nil) {
				return
			}
			<-ctx.Done()
			close(cancelled)
		}
	})

	var svcs AddressLookupServices
	svcs.AddResolver(resolver)
	for range svcs.Resolve(context.Background(), id) {
		break
	}

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("resolver did not observe cancellation after early break")
	}
}

// TestPkarrPublisherOptions verifies the publisher configuration takes
// effect by exercising the resulting publisher against an in-memory relay: a
// custom filter publishes the address it selects, and the publisher resolves
// back through a paired resolver.
func TestPkarrPublisherOptions(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")
	ip := netip.MustParseAddrPort("1.2.3.4:9999")

	// AddrFilter overrides the default relay-only filter, so the IP is
	// published and the relay is dropped. TTL and RepublishInterval are also set
	// to confirm the config returns a usable publisher.
	pub, err := NewPkarrPublisher(sk, srv.URL, &PkarrPublisherConfig{
		HTTPClient:        srv.Client(),
		TTL:               120,
		RepublishInterval: time.Hour,
		AddrFilter:        IPOnlyFilter,
	})
	if err != nil {
		t.Fatalf("NewPkarrPublisher: %v", err)
	}
	defer pub.Close()

	pub.Publish(dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: ip},
	))

	res, err := NewPkarrResolver(srv.URL, &PkarrResolverConfig{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewPkarrResolver: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].err == nil {
			addr := results[0].item.Addr()
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

// TestN0PkarrConstructors smoke-tests the number0 production constructors.
func TestN0PkarrConstructors(t *testing.T) {
	sk, _ := key.GenerateSecretKey()

	pub, err := N0PkarrPublisher(sk, nil)
	if err != nil {
		t.Fatalf("N0PkarrPublisher: %v", err)
	}
	defer pub.Close()

	res, err := N0PkarrResolver(nil)
	if err != nil {
		t.Fatalf("N0PkarrResolver: %v", err)
	}
	if res.client == nil {
		t.Fatal("resolver client is nil")
	}
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
	sk, _ := key.GenerateSecretKey()
	pub, err := NewPkarrPublisher(sk, N0DNSPkarrRelayProd, nil)
	if err != nil {
		t.Fatalf("NewPkarrPublisher: %v", err)
	}
	defer pub.Close()
	if pub.addrFilter == nil {
		t.Fatal("publisher addr filter is nil, want default")
	}
	res, err := NewPkarrResolver(N0DNSPkarrRelayStaging, nil)
	if err != nil {
		t.Fatalf("NewPkarrResolver: %v", err)
	}
	if res.client == nil {
		t.Fatal("resolver client is nil")
	}
}

// TestN0DNSAddressLookup smoke-tests the number0 production DNS constructor.
func TestN0DNSAddressLookup(t *testing.T) {
	// nil resolver falls back to the system DNS resolver; construction must not panic.
	_ = N0DNSAddressLookup(nil)

	// With an explicit resolver, resolution uses the configured origin. A canned
	// TXT lookuper makes this deterministic.
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	info := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(
		netaddr.RelayAddr{URL: relayURL(t, "https://relay.example/")},
	)}
	resolver := &dns.Resolver{Lookuper: &fakeTXTLookuper{values: info.ToTXTStrings()}}

	lookup := N0DNSAddressLookup(resolver)
	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if !results[0].item.EndpointID().Equal(id) {
		t.Errorf("resolved id = %s, want %s", results[0].item.EndpointID(), id)
	}
}
