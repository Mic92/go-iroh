package iroh

import (
	"context"
	"iter"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
)

// DNSProvenance is the provenance string for [DNSAddressLookup] items.
const DNSProvenance = "dns"

// dnsStaggerMs are the delays, in milliseconds, after which additional DNS
// lookups are issued while earlier ones are still in flight. Each query has its
// own 3s timeout, so a lookup aborts after at most 6s.
//
// iroh/src/address_lookup/dns.rs DNS_STAGGERING_MS.
var dnsStaggerMs = []int{200, 300, 600, 1000, 2000, 3000}

// DNSAddressLookup resolves endpoint addressing information from DNS. It queries
// TXT records under "_iroh.<z32-endpoint-id>.<origin>" using the endpoint's DNS
// resolver, where <origin> is the discovery origin domain.
//
// Publishing to a DNS-backed service is done with a [PkarrPublisher] pointing at
// a pkarr relay that also serves DNS, so DNSAddressLookup does not publish.
//
// The zero value is not usable; create one with [NewDNSAddressLookup] or
// [N0DNSAddressLookup].
//
// It is the Go analog of iroh's DNSAddressLookup.
type DNSAddressLookup struct {
	origin   string
	resolver *dns.Resolver
}

// NewDNSAddressLookup returns a DNSAddressLookup querying origin (for example
// [dns.N0DNSEndpointOriginProd]) using resolver. If resolver is nil, a default
// [dns.Resolver] backed by the system DNS configuration is used.
func NewDNSAddressLookup(origin string, resolver *dns.Resolver) *DNSAddressLookup {
	if resolver == nil {
		resolver = &dns.Resolver{}
	}
	return &DNSAddressLookup{origin: origin, resolver: resolver}
}

// N0DNSAddressLookup returns a DNSAddressLookup using the number0 production
// discovery origin ([dns.N0DNSEndpointOriginProd]).
func N0DNSAddressLookup(resolver *dns.Resolver) *DNSAddressLookup {
	return NewDNSAddressLookup(dns.N0DNSEndpointOriginProd, resolver)
}

// Publish is a no-op: DNS records are published indirectly through a
// [PkarrPublisher].
func (d *DNSAddressLookup) Publish(dns.EndpointData) {}

// Resolve looks up id in DNS, issuing staggered concurrent queries and yielding
// the first successful result or an error.
func (d *DNSAddressLookup) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
	return func(yield func(Item, error) bool) {
		info, err := d.lookupStaggered(ctx, id)
		if err != nil {
			if ctx.Err() == nil {
				yield(Item{}, lookupErr(DNSProvenance, err))
			}
			return
		}
		if ctx.Err() == nil {
			yield(NewItem(info, DNSProvenance, nil), nil)
		}
	}
}

// lookupStaggered issues a first DNS lookup immediately and additional ones
// after each delay in [dnsStaggerMs] while earlier attempts are still in
// flight, returning the first success or the last error once all attempts fail.
func (d *DNSAddressLookup) lookupStaggered(ctx context.Context, id key.EndpointID) (dns.EndpointInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type attempt struct {
		info dns.EndpointInfo
		err  error
	}
	total := len(dnsStaggerMs) + 1
	results := make(chan attempt, total)

	launch := func() {
		go func() {
			info, err := d.resolver.LookupEndpointByID(ctx, id, d.origin)
			results <- attempt{info: info, err: err}
		}()
	}

	launch()
	timers := make([]*time.Timer, len(dnsStaggerMs))
	for i, ms := range dnsStaggerMs {
		timers[i] = time.AfterFunc(time.Duration(ms)*time.Millisecond, launch)
	}
	defer func() {
		for _, t := range timers {
			t.Stop()
		}
	}()

	var lastErr error
	for i := 0; i < total; i++ {
		select {
		case r := <-results:
			if r.err == nil {
				return r.info, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return dns.EndpointInfo{}, ctx.Err()
		}
	}
	return dns.EndpointInfo{}, lastErr
}
