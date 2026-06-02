package iroh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// drain collects every Result from ch until it is closed.
func drain(ch <-chan Result) []Result {
	var out []Result
	for r := range ch {
		out = append(out, r)
	}
	return out
}

func relayURL(t *testing.T, s string) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(s)
	if err != nil {
		t.Fatalf("ParseRelayURL(%q): %v", s, err)
	}
	return u
}

func TestMemoryLookup(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	m := NewMemoryLookup()

	if _, ok := m.GetEndpointInfo(id); ok {
		t.Fatal("empty lookup returned an entry")
	}
	if ch := m.Resolve(context.Background(), id); ch != nil {
		t.Fatal("Resolve of unknown id should return nil channel")
	}

	addr := netaddr.NewEndpointAddr(id).WithRelayURL(relayURL(t, "https://relay.example/"))
	m.AddEndpointAddr(addr)

	got, ok := m.GetEndpointInfo(id)
	if !ok {
		t.Fatal("expected stored info")
	}
	if len(got.RelayURLs()) != 1 {
		t.Fatalf("RelayURLs = %v, want one", got.RelayURLs())
	}

	results := drain(m.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].Item.Provenance(); got != MemoryProvenance {
		t.Errorf("provenance = %q, want %q", got, MemoryProvenance)
	}
	if _, ok := results[0].Item.LastUpdated(); !ok {
		t.Error("memory item should report last-updated")
	}

	removed, ok := m.RemoveEndpointInfo(id)
	if !ok || removed.ID != id {
		t.Fatalf("RemoveEndpointInfo = %v, %v", removed, ok)
	}
	if _, ok := m.GetEndpointInfo(id); ok {
		t.Fatal("entry should be gone after removal")
	}
}

func TestMemoryLookupAddMerges(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	m := NewMemoryLookupWithProvenance("custom")

	m.AddEndpointAddr(netaddr.NewEndpointAddr(id).WithIP(netip.MustParseAddrPort("1.2.3.4:1")))
	m.AddEndpointAddr(netaddr.NewEndpointAddr(id).WithIP(netip.MustParseAddrPort("5.6.7.8:2")))

	got, _ := m.GetEndpointInfo(id)
	if len(got.IPAddrs()) != 2 {
		t.Fatalf("IPAddrs = %v, want two after merge", got.IPAddrs())
	}
	results := drain(m.Resolve(context.Background(), id))
	if results[0].Item.Provenance() != "custom" {
		t.Errorf("provenance = %q", results[0].Item.Provenance())
	}
}

func TestDNSTxtRoundTrip(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	relay := relayURL(t, "https://relay.example/")

	info := dns.NewEndpointInfo(id).WithRelayURL(relay).WithIPAddrs(netip.MustParseAddrPort("9.9.9.9:1234"))
	values := info.ToTxtStrings()

	name := dns.IrohTxtName + "." + id.Z32() + "." + dns.N0DNSEndpointOriginProd
	back, err := dns.EndpointInfoFromTxtLookup(name, values)
	if err != nil {
		t.Fatalf("EndpointInfoFromTxtLookup: %v", err)
	}
	if !back.ID.Equal(id) {
		t.Errorf("id = %s, want %s", back.ID, id)
	}
	if len(back.RelayURLs()) != 1 || !back.RelayURLs()[0].Equal(relay) {
		t.Errorf("RelayURLs = %v", back.RelayURLs())
	}
	if len(back.IPAddrs()) != 1 {
		t.Errorf("IPAddrs = %v", back.IPAddrs())
	}
}

// fakeTxtLookuper serves canned TXT values for any name, recording the queried
// name.
type fakeTxtLookuper struct {
	values []string
}

func (f *fakeTxtLookuper) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return f.values, nil
}

func TestDnsAddressLookupResolve(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	info := dns.NewEndpointInfo(id).WithRelayURL(relayURL(t, "https://relay.example/"))

	resolver := &dns.Resolver{Lookuper: &fakeTxtLookuper{values: info.ToTxtStrings()}}
	lookup := NewDnsAddressLookup(dns.N0DNSEndpointOriginProd, resolver)

	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].Item.Provenance(); got != DNSProvenance {
		t.Errorf("provenance = %q, want %q", got, DNSProvenance)
	}
	if !results[0].Item.EndpointID().Equal(id) {
		t.Errorf("id = %s, want %s", results[0].Item.EndpointID(), id)
	}
}

// pkarrTestRelay is an in-memory pkarr relay: PUT /<z32> stores the relay
// payload, GET /<z32> returns it. It matches iroh-dns-server/src/http/pkarr.rs.
func pkarrTestRelay(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	store := map[string][]byte{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			store[key] = body
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			mu.Lock()
			body, ok := store[key]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pkarr-signed-packet")
			w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux)
}

func TestPkarrPublishResolveRoundTrip(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	relay := relayURL(t, "https://relay.example/")

	pub, err := NewPkarrPublisher(srv.URL).
		WithHTTPClient(srv.Client()).
		Build(sk)
	if err != nil {
		t.Fatalf("Build publisher: %v", err)
	}
	defer pub.Close()

	data := dns.NewEndpointData(netaddr.RelayAddr{URL: relay})
	pub.Publish(data)

	res, err := NewPkarrResolver(srv.URL).WithHTTPClient(srv.Client()).Build()
	if err != nil {
		t.Fatalf("Build resolver: %v", err)
	}

	// The publish runs in the background; poll until the relay has the packet.
	var item Item
	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].Err == nil {
			item = results[0].Item
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Resolve never succeeded: %+v", results)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !item.EndpointID().Equal(id) {
		t.Errorf("id = %s, want %s", item.EndpointID(), id)
	}
	if got := item.Provenance(); got != PkarrProvenance {
		t.Errorf("provenance = %q, want %q", got, PkarrProvenance)
	}
	urls := item.Addr().RelayURLs()
	if len(urls) != 1 || !urls[0].Equal(relay) {
		t.Errorf("RelayURLs = %v, want [%s]", urls, relay)
	}
}

func TestPkarrPublisherRelayOnlyFilter(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	relay := relayURL(t, "https://relay.example/")

	pub, err := NewPkarrPublisher(srv.URL).WithHTTPClient(srv.Client()).Build(sk)
	if err != nil {
		t.Fatalf("Build publisher: %v", err)
	}
	defer pub.Close()

	// Publish both a relay and an IP address; default filter keeps relay only.
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:9999")},
	)
	pub.Publish(data)

	res, _ := NewPkarrResolver(srv.URL).WithHTTPClient(srv.Client()).Build()
	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].Err == nil {
			addr := results[0].Item.Addr()
			if len(addr.IPAddrs()) != 0 {
				t.Fatalf("IP address leaked past relay-only filter: %v", addr.IPAddrs())
			}
			if len(addr.RelayURLs()) != 1 {
				t.Fatalf("relay address missing: %v", addr.RelayURLs())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Resolve never succeeded: %+v", results)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// staticLookup is a test [AddressLookup] that resolves to a fixed info after a
// delay, or yields a fixed error.
type staticLookup struct {
	provenance string
	info       *dns.EndpointInfo
	err        error
	delay      time.Duration
}

func (s staticLookup) Publish(dns.EndpointData) {}

func (s staticLookup) Resolve(ctx context.Context, _ key.EndpointID) <-chan Result {
	out := make(chan Result, 1)
	go func() {
		defer close(out)
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return
		}
		if s.err != nil {
			out <- Result{Err: lookupErr(s.provenance, s.err)}
			return
		}
		out <- Result{Item: NewItem(*s.info, s.provenance, nil)}
	}()
	return out
}

func TestServicesNoServiceConfigured(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	var svcs AddressLookupServices
	results := drain(svcs.Resolve(context.Background(), sk.Public()))
	if len(results) != 1 || !errors.Is(results[0].Err, ErrNoServiceConfigured) {
		t.Fatalf("Resolve = %+v, want ErrNoServiceConfigured", results)
	}
}

func TestServicesSucceedsAfterOtherErrors(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	info := dns.NewEndpointInfo(id).WithRelayURL(relayURL(t, "https://relay.example/"))

	var svcs AddressLookupServices
	svcs.Add(staticLookup{provenance: "fail", err: errors.New("boom"), delay: 10 * time.Millisecond})
	svcs.Add(staticLookup{provenance: "ok", info: &info, delay: 80 * time.Millisecond})

	results := drain(svcs.Resolve(context.Background(), id))
	var sawErr, sawOK bool
	for _, r := range results {
		if r.Err != nil {
			sawErr = true
		} else if r.Item.EndpointID().Equal(id) {
			sawOK = true
		}
	}
	if !sawErr {
		t.Error("expected the failing service's error to be delivered inline")
	}
	if !sawOK {
		t.Error("expected the slow successful service's item to be delivered")
	}
}

func TestServicesNoResults(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	var svcs AddressLookupServices
	svcs.Add(staticLookup{provenance: "fail", err: errors.New("boom"), delay: time.Millisecond})

	results := drain(svcs.Resolve(context.Background(), sk.Public()))
	last := results[len(results)-1]
	if !errors.Is(last.Err, ErrNoResults) {
		t.Fatalf("final result = %+v, want ErrNoResults", last)
	}
}

func TestServicesPublishAppliesFilter(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public()
	rec := &recordingLookup{}

	var svcs AddressLookupServices
	svcs.SetAddrFilter(RelayOnlyFilter)
	svcs.Add(rec)

	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")},
	)
	svcs.Publish(data)

	if len(rec.published) != 1 {
		t.Fatalf("published %d times, want 1", len(rec.published))
	}
	got := rec.published[0]
	if len(got.IPAddrs()) != 0 {
		t.Errorf("IP address should be filtered out, got %v", got.IPAddrs())
	}
	if len(got.RelayURLs()) != 1 {
		t.Errorf("relay address should be kept, got %v", got.RelayURLs())
	}
	_ = id
}

// recordingLookup records published data.
type recordingLookup struct {
	mu        sync.Mutex
	published []dns.EndpointData
}

func (r *recordingLookup) Publish(data dns.EndpointData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.published = append(r.published, data)
}

func (r *recordingLookup) Resolve(context.Context, key.EndpointID) <-chan Result { return nil }

func TestServicesAddPublishesHistorical(t *testing.T) {
	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(netaddr.RelayAddr{URL: relay})

	var svcs AddressLookupServices
	svcs.Publish(data)

	rec := &recordingLookup{}
	svcs.Add(rec) // added after publish; should receive the historical data
	if len(rec.published) != 1 {
		t.Fatalf("late-added service got %d publishes, want 1", len(rec.published))
	}
}

func TestFilteredAddressLookup(t *testing.T) {
	rec := &recordingLookup{}
	f := NewFilteredAddressLookup(rec, IPOnlyFilter)

	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")},
	)
	f.Publish(data)

	if len(rec.published) != 1 {
		t.Fatalf("published %d times, want 1", len(rec.published))
	}
	if len(rec.published[0].RelayURLs()) != 0 {
		t.Errorf("relay should be filtered out by IPOnlyFilter")
	}
	if len(rec.published[0].IPAddrs()) != 1 {
		t.Errorf("IP address should be kept, got %v", rec.published[0].IPAddrs())
	}
}
