package netreport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/net/dns/dnsmessage"
)

// tlsInsecure returns a standard-library *tls.Config that skips verification,
// for the HTTPS probe client (which uses crypto/tls, not internal/itls).
func tlsInsecure() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

// newProbeClient builds an HTTP client that never follows redirects and applies
// a TLS config when one is supplied.
func TestNewProbeClient(t *testing.T) {
	// With no TLS config the transport leaves TLSClientConfig unset.
	plain := newProbeClient(nil)
	tr, ok := plain.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", plain.Transport)
	}
	if tr.TLSClientConfig != nil {
		t.Error("TLSClientConfig set without a config")
	}

	// CheckRedirect must refuse to follow redirects (matches reqwest
	// redirect::Policy::none in reportgen.rs).
	if plain.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil, want a no-follow policy")
	}
	if err := plain.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}

	// A supplied TLS config is wired onto the transport.
	cfg := tlsInsecure()
	withTLS := newProbeClient(cfg)
	tr2 := withTLS.Transport.(*http.Transport)
	if tr2.TLSClientConfig != cfg {
		t.Error("TLSClientConfig not applied from config")
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		name    string
		relay   netaddr.RelayUrl
		path    string
		want    string
		wantErr bool
		errText string
	}{
		{
			name:  "resolves probe path against relay",
			relay: mustRelay(t, "https://relay.example/"),
			path:  relayProbePath,
			want:  "https://relay.example/ping",
		},
		{
			name:    "zero relay has no url",
			relay:   netaddr.RelayUrl{},
			path:    relayProbePath,
			wantErr: true,
			errText: "host",
		},
		{
			name:    "malformed path reference fails to parse",
			relay:   mustRelay(t, "https://relay.example/"),
			path:    "%zz",
			wantErr: true,
			errText: "invalid URL escape",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := joinPath(tt.relay, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("joinPath = %q, want error", got)
				}
				if !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("error = %v, want containing %q", err, tt.errText)
				}
				return
			}
			if err != nil {
				t.Fatalf("joinPath: %v", err)
			}
			if got != tt.want {
				t.Errorf("joinPath = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJoinPathMissingHostIsMissingHostError(t *testing.T) {
	_, err := joinPath(netaddr.RelayUrl{}, relayProbePath)
	if !errors.Is(err, errMissingHost) {
		t.Errorf("joinPath(zero) err = %v, want wrapping errMissingHost", err)
	}
}

func TestRunHTTPSProbeMissingHost(t *testing.T) {
	// A relay URL with no host component cannot be probed; the error must wrap
	// errMissingHost (mentions "host"). reportgen.rs:817 / joinPath.
	_, err := runHTTPSProbe(context.Background(), netaddr.RelayUrl{}, nil)
	if err == nil {
		t.Fatal("expected error for hostless relay URL")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error = %v, want containing 'host'", err)
	}
}

func TestCheckCaptivePortalMissingHost(t *testing.T) {
	// A "custom:" relay URL parses but has an empty host; the captive-portal
	// check cannot build a challenge and returns errMissingHost. probes.go:55.
	custom, err := netaddr.ParseRelayUrl("custom:relay")
	if err != nil {
		t.Fatalf("parse custom url: %v", err)
	}
	if custom.Host() != "" {
		t.Fatalf("precondition: custom url host = %q, want empty", custom.Host())
	}
	_, cperr := checkCaptivePortal(context.Background(), custom, nil)
	if !errors.Is(cperr, errMissingHost) {
		t.Errorf("checkCaptivePortal err = %v, want wrapping errMissingHost", cperr)
	}
	if !strings.Contains(cperr.Error(), "host") {
		t.Errorf("error = %v, want containing 'host'", cperr)
	}
}

func TestLookupIPStaggeredFirstSuccessWins(t *testing.T) {
	// A staggered lookup against a loopback DNS server that answers immediately
	// must resolve and record one query. The stagger schedule means later
	// attempts are still pending when the first wins.
	var queries atomic.Int64
	srv := newLoopbackDNS(t, func(name string, qtype dnsmessage.Type) ([]net.IP, time.Duration) {
		queries.Add(1)
		if name != "relay.test." {
			return nil, 0
		}
		if qtype == dnsmessage.TypeA {
			return []net.IP{net.IPv4(203, 0, 113, 7)}, 0
		}
		return nil, 0
	})

	res := srv.resolver()
	addrs, err := lookupIPStaggered(context.Background(), res, "relay.test")
	if err != nil {
		t.Fatalf("lookupIPStaggered: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses returned")
	}
	found := false
	for _, a := range addrs {
		if a.IP.Equal(net.IPv4(203, 0, 113, 7)) {
			found = true
		}
	}
	if !found {
		t.Errorf("addrs = %v, want containing 203.0.113.7", addrs)
	}
}

func TestLookupIPStaggeredHonorsContextCancel(t *testing.T) {
	// When the resolver never answers, the staggered lookup must respect a
	// canceled context rather than block for dnsTimeout.
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	srv := newLoopbackDNS(t, func(string, dnsmessage.Type) ([]net.IP, time.Duration) {
		<-blocked // never answer within the test
		return nil, 0
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := lookupIPStaggered(ctx, srv.resolver(), "relay.test")
	if err == nil {
		t.Fatal("expected error when resolver never answers")
	}
	if elapsed := time.Since(start); elapsed > dnsTimeout {
		t.Errorf("lookup took %v, want bounded near the context deadline", elapsed)
	}
}

// loopbackDNS is a minimal UDP DNS server for testing lookupIPStaggered against
// a real net.Resolver, rather than mocking the resolver.
type loopbackDNS struct {
	t    *testing.T
	conn *net.UDPConn
	addr string
}

// newLoopbackDNS starts a loopback DNS server. answer returns the A/AAAA
// records for a query name (with an optional delay before responding).
func newLoopbackDNS(t *testing.T, answer func(name string, qtype dnsmessage.Type) ([]net.IP, time.Duration)) *loopbackDNS {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	s := &loopbackDNS{t: t, conn: pc, addr: pc.LocalAddr().String()}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := make([]byte, n)
			copy(req, buf[:n])
			go s.serve(req, raddr, answer)
		}
	}()
	return s
}

func (s *loopbackDNS) serve(req []byte, raddr *net.UDPAddr, answer func(string, dnsmessage.Type) ([]net.IP, time.Duration)) {
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	ips, delay := answer(q.Name.String(), q.Type)
	if delay > 0 {
		time.Sleep(delay)
	}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, RecursionAvailable: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return
	}
	b.Question(q)
	if err := b.StartAnswers(); err != nil {
		return
	}
	for _, ip := range ips {
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		if ip4 := ip.To4(); ip4 != nil && q.Type == dnsmessage.TypeA {
			var a [4]byte
			copy(a[:], ip4)
			b.AResource(rh, dnsmessage.AResource{A: a})
		} else if ip16 := ip.To16(); ip16 != nil && q.Type == dnsmessage.TypeAAAA && ip.To4() == nil {
			var aaaa [16]byte
			copy(aaaa[:], ip16)
			b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: aaaa})
		}
	}
	msg, err := b.Finish()
	if err != nil {
		return
	}
	s.conn.WriteToUDP(msg, raddr)
}

// resolver returns a net.Resolver that sends all queries to this loopback DNS
// server, exercising the pure-Go resolver path.
func (s *loopbackDNS) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", s.addr)
		},
	}
}
