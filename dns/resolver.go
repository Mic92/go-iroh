package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tmc/go-iroh/key"
)

// DNS origin and timeout defaults, matching iroh-dns/src/dns.rs.
const (
	// DNSTimeout is the default per-lookup timeout.
	DNSTimeout = 3 * time.Second
	// N0DNSEndpointOriginProd is the number0 production discovery origin.
	N0DNSEndpointOriginProd = "dns.iroh.link."
	// N0DNSEndpointOriginStaging is the number0 staging discovery origin.
	N0DNSEndpointOriginStaging = "staging-dns.iroh.link."
)

// TxtLookuper looks up the TXT records for a DNS name. It is the minimal
// resolver seam: any implementation (the stdlib-backed [Resolver], a DoH/DoT
// client, or a test fake) satisfies it.
//
// It is the Go analog of iroh's Resolver trait, narrowed to the TXT lookup that
// endpoint discovery needs.
type TxtLookuper interface {
	// LookupTXT returns the TXT record string values for name.
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// TxtLookuperFunc adapts a function to [TxtLookuper].
type TxtLookuperFunc func(ctx context.Context, name string) ([]string, error)

// LookupTXT calls f(ctx, name).
func (f TxtLookuperFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

// Resolver resolves iroh endpoint information from DNS. The zero value uses the
// host's default DNS configuration; set [Resolver.Lookuper] to override.
type Resolver struct {
	// Lookuper performs the underlying TXT lookups. If nil, a [net.Resolver]
	// with the default configuration is used.
	Lookuper TxtLookuper
}

func (r *Resolver) lookuper() TxtLookuper {
	if r.Lookuper != nil {
		return r.Lookuper
	}
	return netLookuper{}
}

// LookupEndpointByID resolves the endpoint info for id published under
// "_iroh.<z32-id>.<origin>". Pass [N0DNSEndpointOriginProd] for the number0
// production service.
func (r *Resolver) LookupEndpointByID(ctx context.Context, id key.EndpointID, origin string) (EndpointInfo, error) {
	name := IrohTxtName + "." + id.Z32() + "." + ensureTrailingDot(origin)
	return r.LookupEndpointByDomainName(ctx, name)
}

// LookupEndpointByDomainName resolves the endpoint info from the TXT records at
// name, which must be of the form "_iroh.<z32-id>.<origin>".
func (r *Resolver) LookupEndpointByDomainName(ctx context.Context, name string) (EndpointInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, DNSTimeout)
	defer cancel()
	values, err := r.lookuper().LookupTXT(ctx, name)
	if err != nil {
		return EndpointInfo{}, fmt.Errorf("lookup %q: %w", name, err)
	}
	return EndpointInfoFromTxtLookup(name, values)
}

// netLookuper is the default TxtLookuper, backed by the stdlib net.Resolver.
type netLookuper struct{}

func (netLookuper) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, strings.TrimSuffix(name, "."))
}

func ensureTrailingDot(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
