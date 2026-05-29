package iroh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tmc/go-iroh/base"
	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/internal/pkarr"
	"github.com/tmc/go-iroh/watch"
)

// PkarrProvenance is the provenance string for [PkarrResolver] items.
const PkarrProvenance = "pkarr"

// pkarr relay URLs and publishing defaults.
//
// iroh/src/address_lookup/pkarr.rs.
const (
	// N0DNSPkarrRelayProd is the number0 production pkarr relay, which also
	// serves the records over DNS.
	N0DNSPkarrRelayProd = "https://dns.iroh.link/pkarr"
	// N0DNSPkarrRelayStaging is the number0 staging pkarr relay.
	N0DNSPkarrRelayStaging = "https://staging-dns.iroh.link/pkarr"

	// DefaultPkarrTTL is the default record TTL, in seconds, of published pkarr
	// signed packets.
	DefaultPkarrTTL uint32 = 30
	// DefaultRepublishInterval is how often the publisher republishes the
	// endpoint info even when unchanged.
	DefaultRepublishInterval = 5 * time.Minute
)

// PkarrPublisher publishes endpoint addressing information to a pkarr relay
// over HTTP. It implements [AddressLookup] as a publish-only service; pair it
// with a [PkarrResolver] or [DnsAddressLookup] to resolve.
//
// Publishing is fire-and-forget: [PkarrPublisher.Publish] updates an internal
// value and returns immediately while a background goroutine performs the HTTP
// PUT. The publisher republishes every [DefaultRepublishInterval] even when the
// data is unchanged, and retries with backoff on failure. By default only relay
// addresses are published (see [RelayOnlyFilter]).
//
// The zero value is not usable; create one with a [PkarrPublisherBuilder] from
// [NewPkarrPublisher] or [N0PkarrPublisher]. Stop the background goroutine with
// [PkarrPublisher.Close].
//
// It is the Go analog of iroh's PkarrPublisher.
type PkarrPublisher struct {
	endpointID base.EndpointId
	addrFilter AddrFilter
	value      *watch.Value[*dns.EndpointInfo]
	cancel     context.CancelFunc
	done       chan struct{}
}

// PkarrPublisherBuilder configures a [PkarrPublisher]. Create it with
// [NewPkarrPublisher] or [N0PkarrPublisher], set options, then call
// [PkarrPublisherBuilder.Build].
type PkarrPublisherBuilder struct {
	relayURL          string
	ttl               uint32
	republishInterval time.Duration
	filter            AddrFilter
	httpClient        *http.Client
}

// NewPkarrPublisher returns a builder publishing to the pkarr relay at
// relayURL.
func NewPkarrPublisher(relayURL string) *PkarrPublisherBuilder {
	return &PkarrPublisherBuilder{
		relayURL:          relayURL,
		ttl:               DefaultPkarrTTL,
		republishInterval: DefaultRepublishInterval,
		filter:            RelayOnlyFilter,
	}
}

// N0PkarrPublisher returns a builder publishing to the number0 production pkarr
// relay ([N0DNSPkarrRelayProd]).
func N0PkarrPublisher() *PkarrPublisherBuilder {
	return NewPkarrPublisher(N0DNSPkarrRelayProd)
}

// WithTTL sets the record TTL, in seconds, of published packets. The default is
// [DefaultPkarrTTL].
func (b *PkarrPublisherBuilder) WithTTL(ttl uint32) *PkarrPublisherBuilder {
	b.ttl = ttl
	return b
}

// WithRepublishInterval sets how often packets are republished even when
// unchanged. The default is [DefaultRepublishInterval].
func (b *PkarrPublisherBuilder) WithRepublishInterval(d time.Duration) *PkarrPublisherBuilder {
	b.republishInterval = d
	return b
}

// WithAddrFilter sets the address filter controlling which addresses are
// published. The default is [RelayOnlyFilter]. Pass nil to publish all
// addresses.
func (b *PkarrPublisherBuilder) WithAddrFilter(f AddrFilter) *PkarrPublisherBuilder {
	b.filter = f
	return b
}

// WithHTTPClient sets the HTTP client used for relay requests. The default is a
// client with a per-request timeout.
func (b *PkarrPublisherBuilder) WithHTTPClient(c *http.Client) *PkarrPublisherBuilder {
	b.httpClient = c
	return b
}

// Build creates the publisher, signing packets with secretKey, and starts its
// background publish goroutine.
func (b *PkarrPublisherBuilder) Build(secretKey base.SecretKey) (*PkarrPublisher, error) {
	client, err := newPkarrRelayClient(b.relayURL, b.httpClient)
	if err != nil {
		return nil, fmt.Errorf("pkarr publisher: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &PkarrPublisher{
		endpointID: secretKey.Public(),
		addrFilter: b.filter,
		value:      watch.NewValue[*dns.EndpointInfo](nil),
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	svc := &publisherService{
		secretKey:         secretKey,
		client:            client,
		watcher:           p.value.Watch(),
		ttl:               b.ttl,
		republishInterval: b.republishInterval,
	}
	go func() {
		defer close(p.done)
		svc.run(ctx)
	}()
	return p, nil
}

// Publish records data to publish to the pkarr relay. It applies the
// publisher's address filter and returns immediately; the HTTP PUT runs in the
// background.
func (p *PkarrPublisher) Publish(data dns.EndpointData) {
	filtered := applyFilter(data, p.addrFilter)
	info := dns.EndpointInfoFromParts(p.endpointID, filtered)
	p.value.Set(&info, nil)
}

// Resolve always returns nil: a publisher does not resolve.
func (p *PkarrPublisher) Resolve(context.Context, base.EndpointId) <-chan Result { return nil }

// Close stops the background publish goroutine and waits for it to exit.
func (p *PkarrPublisher) Close() {
	p.cancel()
	<-p.done
}

// publisherService runs the publisher's background loop: it publishes whenever
// the endpoint info changes and republishes on a fixed interval, with backoff
// on failure.
type publisherService struct {
	secretKey         base.SecretKey
	client            *pkarrRelayClient
	watcher           watch.Watcher[*dns.EndpointInfo]
	ttl               uint32
	republishInterval time.Duration
}

func (s *publisherService) run(ctx context.Context) {
	// A single goroutine watches for endpoint-info changes and signals them on
	// changed, so the loop below never spawns a watcher goroutine per iteration.
	changed := make(chan struct{}, 1)
	go func() {
		for {
			if _, err := s.watcher.Updated(ctx); err != nil {
				return // ctx cancelled
			}
			select {
			case changed <- struct{}{}:
			default: // a pending signal already covers this change
			}
		}
	}()

	var failedAttempts int
	republish := time.NewTimer(time.Duration(1 << 62))
	defer republish.Stop()
	for {
		if info := s.watcher.Get(); info != nil {
			if err := s.publishCurrent(ctx, *info); err != nil {
				if ctx.Err() != nil {
					return
				}
				failedAttempts++
				resetTimer(republish, time.Duration(failedAttempts)*time.Second)
			} else {
				failedAttempts = 0
				resetTimer(republish, s.republishInterval)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-republish.C:
		case <-changed:
		}
	}
}

func (s *publisherService) publishCurrent(ctx context.Context, info dns.EndpointInfo) error {
	packet, err := info.ToPkarrSignedPacket(s.secretKey, s.ttl)
	if err != nil {
		return fmt.Errorf("encode signed packet: %w", err)
	}
	return s.client.publish(ctx, packet)
}

// resetTimer stops and resets t to fire after d, draining any pending tick.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// PkarrResolver resolves endpoint addressing information from a pkarr relay over
// HTTP. It implements [AddressLookup] as a resolve-only service.
//
// The zero value is not usable; create one with a [PkarrResolverBuilder] from
// [NewPkarrResolver] or [N0PkarrResolver].
//
// It is the Go analog of iroh's PkarrResolver.
type PkarrResolver struct {
	client *pkarrRelayClient
}

// PkarrResolverBuilder configures a [PkarrResolver].
type PkarrResolverBuilder struct {
	relayURL   string
	httpClient *http.Client
}

// NewPkarrResolver returns a builder resolving from the pkarr relay at relayURL.
func NewPkarrResolver(relayURL string) *PkarrResolverBuilder {
	return &PkarrResolverBuilder{relayURL: relayURL}
}

// N0PkarrResolver returns a builder resolving from the number0 production pkarr
// relay ([N0DNSPkarrRelayProd]).
func N0PkarrResolver() *PkarrResolverBuilder {
	return NewPkarrResolver(N0DNSPkarrRelayProd)
}

// WithHTTPClient sets the HTTP client used for relay requests.
func (b *PkarrResolverBuilder) WithHTTPClient(c *http.Client) *PkarrResolverBuilder {
	b.httpClient = c
	return b
}

// Build creates the resolver.
func (b *PkarrResolverBuilder) Build() (*PkarrResolver, error) {
	client, err := newPkarrRelayClient(b.relayURL, b.httpClient)
	if err != nil {
		return nil, fmt.Errorf("pkarr resolver: %w", err)
	}
	return &PkarrResolver{client: client}, nil
}

// Publish is a no-op: a resolver does not publish.
func (r *PkarrResolver) Publish(dns.EndpointData) {}

// Resolve fetches the signed packet for id from the pkarr relay and decodes its
// endpoint info. The returned channel yields a single [Result] and is closed.
func (r *PkarrResolver) Resolve(ctx context.Context, id base.EndpointId) <-chan Result {
	out := make(chan Result, 1)
	go func() {
		defer close(out)
		packet, err := r.client.resolve(ctx, id)
		if err != nil {
			send(ctx, out, Result{Err: lookupErr(PkarrProvenance, err)})
			return
		}
		info, err := dns.EndpointInfoFromPkarrSignedPacket(packet)
		if err != nil {
			send(ctx, out, Result{Err: lookupErr(PkarrProvenance, err)})
			return
		}
		send(ctx, out, Result{Item: NewItem(info, PkarrProvenance, nil)})
	}()
	return out
}

func send(ctx context.Context, ch chan<- Result, r Result) {
	select {
	case ch <- r:
	case <-ctx.Done():
	}
}

// pkarrRelayClient publishes and resolves pkarr signed packets to a pkarr relay
// using HTTP PUT and GET on "<relay>/<z32-endpoint-id>".
//
// iroh/src/address_lookup/pkarr.rs PkarrRelayClient; the route and body match
// iroh-dns-server/src/http/pkarr.rs (put/get).
type pkarrRelayClient struct {
	httpClient *http.Client
	relayURL   *url.URL
}

func newPkarrRelayClient(relayURL string, client *http.Client) (*pkarrRelayClient, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay url: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &pkarrRelayClient{httpClient: client, relayURL: u}, nil
}

// keyURL returns "<relay>/<z32>" for the endpoint id's z-base-32 encoding.
func (c *pkarrRelayClient) keyURL(z32 string) string {
	u := *c.relayURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + z32
	return u.String()
}

// publish PUTs the signed packet's relay payload (signature + timestamp + DNS
// wire bytes, i.e. everything after the public key) to "<relay>/<z32>".
func (c *pkarrRelayClient) publish(ctx context.Context, packet *pkarr.SignedPacket) error {
	body := packet.RelayPayload()
	target := c.keyURL(packet.PublicKey().Z32())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http put: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pkarr relay returned status %d", resp.StatusCode)
	}
	return nil
}

// resolve GETs the relay payload from "<relay>/<z32>" and reconstructs (and
// verifies) the signed packet from the public key and payload.
func (c *pkarrRelayClient) resolve(ctx context.Context, id base.EndpointId) (*pkarr.SignedPacket, error) {
	target := c.keyURL(id.Z32())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("pkarr relay returned status %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	packet, err := pkarr.FromRelayPayload(id, payload)
	if err != nil {
		return nil, fmt.Errorf("decode signed packet: %w", err)
	}
	return packet, nil
}
