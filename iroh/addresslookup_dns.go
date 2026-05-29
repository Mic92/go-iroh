package iroh

import (
	"context"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
)

// DNSProvenance is the provenance string for [DnsAddressLookup] items.
const DNSProvenance = "dns"

// dnsStaggerMs are the delays, in milliseconds, after which additional DNS
// lookups are issued while earlier ones are still in flight. Each query has its
// own 3s timeout, so a lookup aborts after at most 6s.
//
// iroh/src/address_lookup/dns.rs DNS_STAGGERING_MS.
var dnsStaggerMs = []int{200, 300, 600, 1000, 2000, 3000}

// DnsAddressLookup resolves endpoint addressing information from DNS. It queries
// TXT records under "_iroh.<z32-endpoint-id>.<origin>" using the endpoint's DNS
// resolver, where <origin> is the discovery origin domain.
//
// Publishing to a DNS-backed service is done with a [PkarrPublisher] pointing at
// a pkarr relay that also serves DNS, so DnsAddressLookup does not publish.
//
// The zero value is not usable; create one with [NewDnsAddressLookup] or
// [N0DnsAddressLookup].
//
// It is the Go analog of iroh's DnsAddressLookup.
type DnsAddressLookup struct {
	origin   string
	resolver *dns.Resolver
}

// NewDnsAddressLookup returns a DnsAddressLookup querying origin (for example
// [dns.N0DNSEndpointOriginProd]) using resolver. If resolver is nil, a default
// [dns.Resolver] backed by the system DNS configuration is used.
func NewDnsAddressLookup(origin string, resolver *dns.Resolver) DnsAddressLookup {
	if resolver == nil {
		resolver = dns.NewResolver()
	}
	return DnsAddressLookup{origin: origin, resolver: resolver}
}

// N0DnsAddressLookup returns a DnsAddressLookup using the number0 production
// discovery origin ([dns.N0DNSEndpointOriginProd]).
func N0DnsAddressLookup(resolver *dns.Resolver) DnsAddressLookup {
	return NewDnsAddressLookup(dns.N0DNSEndpointOriginProd, resolver)
}

// Publish is a no-op: DNS records are published indirectly through a
// [PkarrPublisher].
func (d DnsAddressLookup) Publish(dns.EndpointData) {}

// Resolve looks up id in DNS, issuing staggered concurrent queries and
// returning the first successful result. The returned channel yields a single
// [Result] (success or error) and is then closed.
func (d DnsAddressLookup) Resolve(ctx context.Context, id base.EndpointId) <-chan Result {
	out := make(chan Result, 1)
	go func() {
		defer close(out)
		info, err := d.lookupStaggered(ctx, id)
		if err != nil {
			select {
			case out <- Result{Err: lookupErr(DNSProvenance, err)}:
			case <-ctx.Done():
			}
			return
		}
		select {
		case out <- Result{Item: NewItem(info, DNSProvenance, nil)}:
		case <-ctx.Done():
		}
	}()
	return out
}

// lookupStaggered issues a first DNS lookup immediately and additional ones
// after each delay in [dnsStaggerMs] while earlier attempts are still in
// flight, returning the first success or the last error once all attempts fail.
func (d DnsAddressLookup) lookupStaggered(ctx context.Context, id base.EndpointId) (dns.EndpointInfo, error) {
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
			info, err := d.resolver.LookupEndpointById(ctx, id, d.origin)
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
