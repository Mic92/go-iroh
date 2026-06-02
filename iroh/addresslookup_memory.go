package iroh

import (
	"context"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// MemoryProvenance is the default provenance string for [MemoryLookup] items.
const MemoryProvenance = "memory_lookup"

// MemoryLookup is an in-memory [AddressLookup] for addressing information added
// out-of-band, such as from an endpoint ticket. Applications add and remove
// entries; resolution returns the stored info for an id.
//
// The zero value is not usable; create one with [NewMemoryLookup] or
// [NewMemoryLookupWithProvenance]. A MemoryLookup is safe for concurrent use,
// and copies share the same underlying store.
//
// It is the Go analog of iroh's MemoryLookup.
type MemoryLookup struct {
	mu         *sync.RWMutex
	endpoints  map[key.EndpointId]storedInfo
	provenance string
}

type storedInfo struct {
	data        dns.EndpointData
	lastUpdated time.Time
}

// NewMemoryLookup returns an empty MemoryLookup using [MemoryProvenance].
func NewMemoryLookup() MemoryLookup {
	return NewMemoryLookupWithProvenance(MemoryProvenance)
}

// NewMemoryLookupWithProvenance returns an empty MemoryLookup whose resolved
// [Item]s report the given provenance.
func NewMemoryLookupWithProvenance(provenance string) MemoryLookup {
	return MemoryLookup{
		mu:         &sync.RWMutex{},
		endpoints:  make(map[key.EndpointId]storedInfo),
		provenance: provenance,
	}
}

// MemoryLookupFromInfo returns a MemoryLookup pre-populated with infos.
func MemoryLookupFromInfo(infos ...dns.EndpointInfo) MemoryLookup {
	m := NewMemoryLookup()
	for _, info := range infos {
		m.AddEndpointInfo(info)
	}
	return m
}

// SetEndpointInfo replaces all stored info for info.Id, returning the previous
// [dns.EndpointData] and whether an entry existed.
func (m MemoryLookup) SetEndpointInfo(info dns.EndpointInfo) (dns.EndpointData, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, existed := m.endpoints[info.Id]
	m.endpoints[info.Id] = storedInfo{data: info.Data, lastUpdated: time.Now()}
	return prev.data, existed
}

// AddEndpointInfo merges info into the stored entry for info.Id: new direct
// addresses are appended and the user data is overwritten. If no entry exists,
// one is created.
func (m MemoryLookup) AddEndpointInfo(info dns.EndpointInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.endpoints[info.Id]
	if !ok {
		m.endpoints[info.Id] = storedInfo{data: info.Data, lastUpdated: time.Now()}
		return
	}
	existing.data.AddAddrs(info.Data.Addrs()...)
	existing.data.SetUserData(info.Data.UserData())
	existing.lastUpdated = time.Now()
	m.endpoints[info.Id] = existing
}

// AddEndpointAddr is a convenience wrapper for [MemoryLookup.AddEndpointInfo]
// taking an [netaddr.EndpointAddr].
func (m MemoryLookup) AddEndpointAddr(addr netaddr.EndpointAddr) {
	m.AddEndpointInfo(dns.EndpointInfoFromAddr(addr))
}

// GetEndpointInfo returns the stored info for id and whether it exists.
func (m MemoryLookup) GetEndpointInfo(id key.EndpointId) (dns.EndpointInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.endpoints[id]
	if !ok {
		return dns.EndpointInfo{}, false
	}
	return dns.EndpointInfoFromParts(id, info.data), true
}

// RemoveEndpointInfo removes and returns the info for id, and whether it
// existed.
func (m MemoryLookup) RemoveEndpointInfo(id key.EndpointId) (dns.EndpointInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, ok := m.endpoints[id]
	if !ok {
		return dns.EndpointInfo{}, false
	}
	delete(m.endpoints, id)
	return dns.EndpointInfoFromParts(id, info.data), true
}

// Publish is a no-op: a MemoryLookup is populated through its own methods.
func (m MemoryLookup) Publish(dns.EndpointData) {}

// Resolve returns the stored info for id, or nil if there is no entry.
func (m MemoryLookup) Resolve(ctx context.Context, id key.EndpointId) <-chan Result {
	m.mu.RLock()
	info, ok := m.endpoints[id]
	m.mu.RUnlock()
	if !ok {
		return nil
	}
	lastUpdated := uint64(info.lastUpdated.UnixMicro())
	item := NewItem(dns.EndpointInfoFromParts(id, info.data), m.provenance, &lastUpdated)
	out := make(chan Result, 1)
	out <- Result{Item: item}
	close(out)
	return out
}

// FilteredAddressLookup wraps an [AddressLookup], applying an [AddrFilter] to
// the data before publishing it to the inner service. Resolution is delegated
// unchanged.
//
// The zero value is not usable; create one with [NewFilteredAddressLookup].
//
// It is the Go analog of iroh's FilteredAddressLookup.
type FilteredAddressLookup struct {
	inner  AddressLookup
	filter AddrFilter
}

// NewFilteredAddressLookup wraps inner so that published data is filtered by f
// before reaching inner.
func NewFilteredAddressLookup(inner AddressLookup, f AddrFilter) FilteredAddressLookup {
	return FilteredAddressLookup{inner: inner, filter: f}
}

// Inner returns the wrapped lookup.
func (f FilteredAddressLookup) Inner() AddressLookup { return f.inner }

// Publish filters data and publishes it to the inner service.
func (f FilteredAddressLookup) Publish(data dns.EndpointData) {
	f.inner.Publish(applyFilter(data, f.filter))
}

// Resolve delegates to the inner service.
func (f FilteredAddressLookup) Resolve(ctx context.Context, id key.EndpointId) <-chan Result {
	return f.inner.Resolve(ctx, id)
}
