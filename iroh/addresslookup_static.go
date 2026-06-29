package iroh

import (
	"context"
	"iter"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// StaticProvenance is the default provenance string for [StaticLookup] items.
const StaticProvenance = "static_lookup"

// StaticLookup is an immutable [AddressResolver] for addressing information
// fixed at construction time.
//
// The zero value is not usable; create one with [NewStaticLookup],
// [NewStaticLookupWithProvenance], or [StaticLookupFromAddrs]. A StaticLookup is
// safe for concurrent use.
type StaticLookup struct {
	endpoints   map[key.EndpointID]staticInfo
	provenance  string
	lastUpdated uint64
}

type staticInfo struct {
	data dns.EndpointData
}

// NewStaticLookup returns a StaticLookup for infos using [StaticProvenance].
func NewStaticLookup(infos ...dns.EndpointInfo) *StaticLookup {
	return NewStaticLookupWithProvenance(StaticProvenance, infos...)
}

// NewStaticLookupWithProvenance returns a StaticLookup for infos whose resolved
// [Item]s report the given provenance.
func NewStaticLookupWithProvenance(provenance string, infos ...dns.EndpointInfo) *StaticLookup {
	s := &StaticLookup{
		endpoints:   make(map[key.EndpointID]staticInfo, len(infos)),
		provenance:  provenance,
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	for _, info := range infos {
		s.endpoints[info.ID] = staticInfo{data: cloneEndpointData(info.Data)}
	}
	return s
}

// StaticLookupFromAddrs returns a StaticLookup for endpoint addresses using
// [StaticProvenance].
func StaticLookupFromAddrs(addrs ...netaddr.EndpointAddr) *StaticLookup {
	infos := make([]dns.EndpointInfo, 0, len(addrs))
	for _, addr := range addrs {
		infos = append(infos, dns.EndpointInfoFromAddr(addr))
	}
	return NewStaticLookup(infos...)
}

// Resolve returns the static info for id, or nil if there is no entry.
func (s *StaticLookup) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
	if s == nil {
		return nil
	}
	info, ok := s.endpoints[id]
	if !ok {
		return nil
	}
	item := NewItem(dns.EndpointInfo{ID: id, Data: cloneEndpointData(info.data)}, s.provenance, &s.lastUpdated)
	return func(yield func(Item, error) bool) {
		if ctx.Err() == nil {
			yield(item, nil)
		}
	}
}

func cloneEndpointData(data dns.EndpointData) dns.EndpointData {
	out := dns.NewEndpointData(data.Addrs()...)
	if userData := data.UserData(); userData != nil {
		u := *userData
		out.SetUserData(&u)
	}
	return out
}
