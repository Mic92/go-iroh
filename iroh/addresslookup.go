package iroh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
)

// AddressLookup is a system for publishing and resolving the addressing
// information of an [base.EndpointId]. It lets an [Endpoint] connect to a peer
// knowing only its id, by looking up a [base.EndpointAddr] (a relay URL and/or
// direct addresses) through one or more lookup services.
//
// Multiple implementations coexist: pkarr-relay ([PkarrPublisher] /
// [PkarrResolver]), DNS ([DnsAddressLookup]), and in-memory ([MemoryLookup]).
// An [Endpoint] combines them with [AddressLookupServices].
//
// It is the Go analog of iroh's AddressLookup trait
// (iroh/src/address_lookup.rs).
type AddressLookup interface {
	// Publish records the endpoint data with the lookup service. It is
	// fire-and-forget: the call must not block, starting any background work
	// itself. A service that only resolves leaves this a no-op.
	Publish(data dns.EndpointData)

	// Resolve looks up addressing information for id. It returns a channel of
	// [Result] values, closed when the lookup is exhausted, or nil if the
	// service does not perform resolution. Cancel ctx to stop pending work; the
	// channel is then closed.
	Resolve(ctx context.Context, id base.EndpointId) <-chan Result
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
func (i Item) EndpointID() base.EndpointId { return i.info.Id }

// EndpointInfo returns the discovered endpoint info.
func (i Item) EndpointInfo() dns.EndpointInfo { return i.info }

// Provenance returns a stable string identifying the lookup source that
// produced this item, such as "pkarr", "dns", or "memory_lookup".
func (i Item) Provenance() string { return i.provenance }

// LastUpdated returns the time the source last updated this info, in
// microseconds since the unix epoch, and whether the source tracks it.
func (i Item) LastUpdated() (uint64, bool) { return i.lastUpdated, i.hasUpdated }

// Addr converts the item into a [base.EndpointAddr].
func (i Item) Addr() base.EndpointAddr { return i.info.Addr() }

// Result is one element of an [AddressLookup.Resolve] stream: either an [Item]
// or an error from a single service. It mirrors the Rust stream's
// Result<Item, Error>, where a per-service error does not end the merged
// stream of [AddressLookupServices].
type Result struct {
	// Item is the discovered information. It is meaningful only when Err is nil.
	Item Item
	// Err is the per-service lookup error, or nil on success.
	Err error
}

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
type AddrFilter func(addrs []base.TransportAddr) []base.TransportAddr

// RelayOnlyFilter keeps only relay addresses. It is the default filter for
// [PkarrPublisher], avoiding leaking direct IP addresses to a public pkarr
// relay.
func RelayOnlyFilter(addrs []base.TransportAddr) []base.TransportAddr {
	out := make([]base.TransportAddr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := a.(base.RelayAddr); ok {
			out = append(out, a)
		}
	}
	return out
}

// IPOnlyFilter keeps only direct IP and custom addresses, dropping relays.
func IPOnlyFilter(addrs []base.TransportAddr) []base.TransportAddr {
	out := make([]base.TransportAddr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := a.(base.RelayAddr); !ok {
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
// their streams into the returned channel. Each successful [Item] is delivered
// as it is produced as a [Result] with a nil Err, letting the caller act on the
// first usable address while slower services run.
//
// A per-service error is delivered inline as a [Result] with that error set and
// does not end the stream. If every service finishes without yielding an item,
// a final [Result] carries [ErrNoResults] wrapping the per-service errors. If
// no services are registered, a single [Result] carries
// [ErrNoServiceConfigured].
//
// Cancel ctx to stop all services and close the channel.
func (s *AddressLookupServices) Resolve(ctx context.Context, id base.EndpointId) <-chan Result {
	s.mu.RLock()
	services := slices.Clone(s.services)
	s.mu.RUnlock()

	out := make(chan Result)
	if len(services) == 0 {
		go func() {
			defer close(out)
			select {
			case out <- Result{Err: ErrNoServiceConfigured}:
			case <-ctx.Done():
			}
		}()
		return out
	}

	go func() {
		defer close(out)
		var wg sync.WaitGroup
		merged := make(chan Result)
		for _, service := range services {
			ch := service.Resolve(ctx, id)
			if ch == nil {
				continue
			}
			wg.Add(1)
			go func(ch <-chan Result) {
				defer wg.Done()
				for r := range ch {
					select {
					case merged <- r:
					case <-ctx.Done():
						return
					}
				}
			}(ch)
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
						select {
						case out <- Result{Err: fmt.Errorf("%w: %w", ErrNoResults, errors.Join(errs...))}:
						case <-ctx.Done():
						}
					}
					return
				}
				if r.Err != nil {
					errs = append(errs, r.Err)
				} else {
					didEmit = true
				}
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
