package iroh

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// AddressLookup is a system for publishing and resolving the addressing
// information of an [key.EndpointID]. It lets an [Endpoint] connect to a peer
// knowing only its id, by looking up a [netaddr.EndpointAddr] (a relay URL and/or
// direct addresses) through one or more lookup services.
//
// Multiple implementations coexist: pkarr-relay ([PkarrPublisher] /
// [PkarrResolver]), DNS ([DNSAddressLookup]), and in-memory ([MemoryLookup]).
// An [Endpoint] combines them with [AddressLookupServices].
//
// It is the Go analog of iroh's AddressLookup trait
// (iroh/src/address_lookup.rs).
type AddressLookup interface {
	// Publish records the endpoint data with the lookup service. It is
	// fire-and-forget: the call must not block, starting any background work
	// itself. A service that only resolves leaves this a no-op.
	Publish(data dns.EndpointData)

	// Resolve looks up addressing information for id. It returns a sequence of
	// discovered [Item] values and per-service errors, or nil if the service
	// does not perform resolution. Cancel ctx to stop pending work.
	Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error]
}

// Item is a single address-lookup result: the [dns.EndpointInfo] discovered for
// an endpoint plus metadata about the lookup source. It is the item carried in
// the streams returned by [AddressLookup.Resolve].
//
// It is the Go analog of iroh's address_lookup::Item.
type Item struct {
	info        dns.EndpointInfo
	provenance  string
	lastUpdated uint64 // microseconds since the unix epoch, 0 if unknown
	hasUpdated  bool
}

// NewItem returns an Item for info from a lookup source identified by
// provenance. lastUpdated is microseconds since the unix epoch, or nil if the
// source does not track it.
func NewItem(info dns.EndpointInfo, provenance string, lastUpdated *uint64) Item {
	it := Item{info: info, provenance: provenance}
	if lastUpdated != nil {
		it.lastUpdated = *lastUpdated
		it.hasUpdated = true
	}
	return it
}

// EndpointID returns the id of the discovered endpoint.
func (i Item) EndpointID() key.EndpointID { return i.info.ID }

// EndpointInfo returns the discovered endpoint info.
func (i Item) EndpointInfo() dns.EndpointInfo { return i.info }

// Provenance returns a stable string identifying the lookup source that
// produced this item, such as "pkarr", "dns", or "memory_lookup".
func (i Item) Provenance() string { return i.provenance }

// LastUpdated returns the time the source last updated this info, in
// microseconds since the unix epoch, and whether the source tracks it.
func (i Item) LastUpdated() (uint64, bool) { return i.lastUpdated, i.hasUpdated }

// Addr converts the item into a [netaddr.EndpointAddr].
func (i Item) Addr() netaddr.EndpointAddr { return i.info.Addr() }

// LookupError reports a failed address lookup from a single service. The
// provenance identifies which service failed.
//
// It is the Go analog of iroh's address_lookup::Error.
type LookupError struct {
	Provenance string
	Err        error
}

// Error implements error.
func (e *LookupError) Error() string {
	return fmt.Sprintf("address lookup service %q failed: %v", e.Provenance, e.Err)
}

// Unwrap returns the wrapped error for use with [errors.Is] and [errors.As].
func (e *LookupError) Unwrap() error { return e.Err }

// lookupErr wraps err as a [LookupError] from the named service.
func lookupErr(provenance string, err error) *LookupError {
	return &LookupError{Provenance: provenance, Err: err}
}

type lookupResult struct {
	item Item
	err  error
}

// Errors returned by [AddressLookupServices.Resolve] when no service produces a
// result.
var (
	// ErrNoServiceConfigured is reported when resolution is attempted with no
	// services registered.
	ErrNoServiceConfigured = errors.New("no address lookup configured")
	// ErrNoResults is reported when every configured service finished without
	// yielding an item. The per-service errors, if any, are joined into it.
	ErrNoResults = errors.New("all address lookup services failed or produced no results")
)

// AddrFilter selects and orders the transport addresses published to a lookup
// service. It receives the full address set and returns the subset to publish,
// in priority order. A nil AddrFilter publishes all addresses unchanged.
//
// It is the Go analog of iroh's address_lookup::AddrFilter.
type AddrFilter func(addrs []netaddr.TransportAddr) []netaddr.TransportAddr

// RelayOnlyFilter keeps only relay addresses. It is the default filter for
// [PkarrPublisher], avoiding leaking direct IP addresses to a public pkarr
// relay.
func RelayOnlyFilter(addrs []netaddr.TransportAddr) []netaddr.TransportAddr {
	out := make([]netaddr.TransportAddr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := a.(netaddr.RelayAddr); ok {
			out = append(out, a)
		}
	}
	return out
}

// IPOnlyFilter keeps only direct IP and custom addresses, dropping relays.
func IPOnlyFilter(addrs []netaddr.TransportAddr) []netaddr.TransportAddr {
	out := make([]netaddr.TransportAddr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := a.(netaddr.RelayAddr); !ok {
			out = append(out, a)
		}
	}
	return out
}

// applyFilter returns data with f applied to its addresses, preserving the user
// data. A nil filter returns data unchanged.
func applyFilter(data dns.EndpointData, f AddrFilter) dns.EndpointData {
	if f == nil {
		return data
	}
	out := dns.NewEndpointData(f(data.Addrs())...)
	if u := data.UserData(); u != nil {
		out.SetUserData(u)
	}
	return out
}

// AddressLookupServices is the registry of [AddressLookup] services for an
// [Endpoint]. It publishes the endpoint's own info to every service and merges
// their resolution streams.
//
// The zero value is an empty, ready-to-use registry. It is safe for concurrent
// use.
//
// It is the Go analog of iroh's AddressLookupServices.
type AddressLookupServices struct {
	mu         sync.RWMutex
	services   []AddressLookup
	lastData   *dns.EndpointData
	addrFilter AddrFilter
}

// SetAddrFilter sets a filter applied to all data before publishing to any
// service, ensuring consistent filtering across services.
func (s *AddressLookupServices) SetAddrFilter(f AddrFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrFilter = f
}

// Add registers a service. If data has already been published, it is published
// to the new service immediately.
func (s *AddressLookupServices) Add(service AddressLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastData != nil {
		service.Publish(*s.lastData)
	}
	s.services = append(s.services, service)
}

// Len returns the number of registered services.
func (s *AddressLookupServices) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.services)
}

// IsEmpty reports whether no services are registered.
func (s *AddressLookupServices) IsEmpty() bool { return s.Len() == 0 }

// Clear removes all registered services.
func (s *AddressLookupServices) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.services = nil
}

// Publish publishes data on every registered service, applying the registry's
// address filter first, and records it for services added later.
func (s *AddressLookupServices) Publish(data dns.EndpointData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := applyFilter(data, s.addrFilter)
	for _, service := range s.services {
		service.Publish(filtered)
	}
	s.lastData = &filtered
}

// Resolve looks up id across all registered services concurrently, merging
// their streams into the returned sequence. Each successful [Item] is yielded as
// it is produced, letting the caller act on the first usable address while
// slower services run.
//
// A per-service error is yielded inline and does not end the sequence. If every
// configured service finishes without yielding an item, a final
// [ErrNoResults] wrapping the per-service errors is yielded. If no services are
// registered, [ErrNoServiceConfigured] is yielded once.
//
// Cancel ctx to stop all services and end the sequence.
func (s *AddressLookupServices) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
	s.mu.RLock()
	services := slices.Clone(s.services)
	s.mu.RUnlock()

	return func(yield func(Item, error) bool) {
		if len(services) == 0 {
			if ctx.Err() == nil {
				yield(Item{}, ErrNoServiceConfigured)
			}
			return
		}
		var wg sync.WaitGroup
		merged := make(chan lookupResult)
		for _, service := range services {
			seq := service.Resolve(ctx, id)
			if seq == nil {
				continue
			}
			wg.Add(1)
			go func(seq iter.Seq2[Item, error]) {
				defer wg.Done()
				for item, err := range seq {
					select {
					case merged <- lookupResult{item: item, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}(seq)
		}
		go func() {
			wg.Wait()
			close(merged)
		}()

		var didEmit bool
		var errs []error
		for {
			select {
			case r, ok := <-merged:
				if !ok {
					if !didEmit {
						if ctx.Err() == nil {
							yield(Item{}, fmt.Errorf("%w: %w", ErrNoResults, errors.Join(errs...)))
						}
					}
					return
				}
				if r.err != nil {
					errs = append(errs, r.err)
				} else {
					didEmit = true
				}
				if !yield(r.item, r.err) {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
}
