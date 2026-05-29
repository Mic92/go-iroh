package iroh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// Endpoint is a bound iroh node: it owns a secret key, a UDP socket, and the
// QUIC transport used to dial and accept connections. Create one with [Bind].
//
// An Endpoint is safe for concurrent use. Close it with [Endpoint.Close].
type Endpoint struct {
	secretKey base.SecretKey
	alpns     [][]byte

	udp       *net.UDPConn
	transport *quic.Transport
	listener  *quic.Listener
	quicConf  *quic.Config

	mu     sync.Mutex
	closed bool
}

// config holds the options assembled by [Option] values before [Bind].
type config struct {
	secretKey    base.SecretKey
	haveKey      bool
	alpns        [][]byte
	bindAddr     netip.AddrPort
	haveBindAddr bool
}

// Option configures an [Endpoint] at [Bind] time.
type Option func(*config) error

// WithSecretKey sets the endpoint's identity. If unset, [Bind] generates a
// random key.
func WithSecretKey(sk base.SecretKey) Option {
	return func(c *config) error {
		c.secretKey = sk
		c.haveKey = true
		return nil
	}
}

// WithALPNs sets the ALPN protocols this endpoint accepts on incoming
// connections. Each ALPN is an arbitrary byte string.
func WithALPNs(alpns ...[]byte) Option {
	return func(c *config) error {
		c.alpns = append(c.alpns, alpns...)
		return nil
	}
}

// WithBindAddr sets the local UDP address to bind. The default is an
// OS-assigned port on the unspecified address.
func WithBindAddr(addr netip.AddrPort) Option {
	return func(c *config) error {
		c.bindAddr = addr
		c.haveBindAddr = true
		return nil
	}
}

// Bind binds a UDP socket and returns a ready [Endpoint].
//
// In this build the endpoint dials and accepts over direct UDP addresses only;
// relay transport, address discovery, and hole-punching are added by later
// slices of the connectivity engine (see iroh/DESIGN.md).
func Bind(ctx context.Context, opts ...Option) (*Endpoint, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}
	if !c.haveKey {
		sk, err := base.GenerateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("iroh: generate key: %w", err)
		}
		c.secretKey = sk
	}

	bind := c.bindAddr
	if !c.haveBindAddr {
		bind = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bind))
	if err != nil {
		return nil, fmt.Errorf("iroh: bind udp: %w", err)
	}

	quicConf := &quic.Config{
		KeepAlivePeriod: HeartbeatInterval,
		MaxIdleTimeout:  RelayPathMaxIdleTimeout,
		EnableDatagrams: true,
	}

	ep := &Endpoint{
		secretKey: c.secretKey,
		alpns:     c.alpns,
		udp:       udp,
		transport: &quic.Transport{Conn: udp},
		quicConf:  quicConf,
	}

	if len(c.alpns) > 0 {
		if err := ep.startListener(); err != nil {
			udp.Close()
			return nil, err
		}
	}
	return ep, nil
}

// startListener begins accepting incoming connections with the current ALPNs.
func (e *Endpoint) startListener() error {
	serverTLS, err := serverTLSConfig(e.secretKey, alpnsToStrings(e.alpns))
	if err != nil {
		return err
	}
	ln, err := e.transport.Listen(serverTLS, e.quicConf)
	if err != nil {
		return fmt.Errorf("iroh: listen: %w", err)
	}
	e.listener = ln
	return nil
}

// ID returns the endpoint's identifier (its ed25519 public key).
func (e *Endpoint) ID() base.EndpointId { return e.secretKey.Public() }

// SecretKey returns the endpoint's secret key.
func (e *Endpoint) SecretKey() base.SecretKey { return e.secretKey }

// LocalAddr returns the bound UDP address.
func (e *Endpoint) LocalAddr() netip.AddrPort {
	return e.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Addr returns the endpoint's [base.EndpointAddr] from currently-known local
// information: its id plus the bound direct address. Later slices add relay and
// reflexive addresses.
func (e *Endpoint) Addr() base.EndpointAddr {
	return base.NewEndpointAddr(e.ID()).WithIP(e.LocalAddr())
}

// ErrEndpointClosed is returned by operations on a closed [Endpoint].
var ErrEndpointClosed = errors.New("iroh: endpoint closed")

// ErrSelfConnect is returned by [Endpoint.Connect] when asked to dial the
// endpoint's own id.
var ErrSelfConnect = errors.New("iroh: cannot connect to self")

// ErrNoAddress is returned when an [base.EndpointAddr] has no usable address
// for this build (no direct IP, since relay dialing is not yet implemented).
var ErrNoAddress = errors.New("iroh: no reachable address for endpoint")

// Connect dials the endpoint identified by addr and negotiates alpn, returning
// an established [Conn]. It tries the direct IP addresses in addr in order.
func (e *Endpoint) Connect(ctx context.Context, addr base.EndpointAddr, alpn []byte) (*Conn, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if addr.Id.Equal(e.ID()) {
		return nil, ErrSelfConnect
	}
	ips := addr.IPAddrs()
	if len(ips) == 0 {
		return nil, ErrNoAddress
	}

	clientTLS, err := clientTLSConfig(e.secretKey, addr.Id, []string{string(alpn)})
	if err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}

	var firstErr error
	for _, ip := range ips {
		udpAddr := net.UDPAddrFromAddrPort(ip)
		qc, err := e.transport.Dial(ctx, udpAddr, clientTLS, e.quicConf)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return newConn(qc, addr.Id, alpn, SideClient)
	}
	return nil, fmt.Errorf("iroh: connect to %s: %w", addr.Id, firstErr)
}

// Accept blocks until an incoming connection completes its handshake, then
// returns it as a [Conn]. It returns an error if the endpoint is closed or has
// no configured ALPNs. ctx cancels the wait.
//
// In this build Accept returns a fully-established connection; the pre-handshake
// Incoming/Connecting controls in iroh/DESIGN.md arrive with a later slice.
func (e *Endpoint) Accept(ctx context.Context) (*Conn, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if e.listener == nil {
		return nil, errors.New("iroh: no ALPNs configured; nothing to accept")
	}
	qc, err := e.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	remote, err := peerEndpointId(qc.ConnectionState().TLS)
	if err != nil {
		qc.CloseWithError(0, "bad peer certificate")
		return nil, err
	}
	alpn := []byte(qc.ConnectionState().TLS.NegotiatedProtocol)
	return newConn(qc, remote, alpn, SideServer)
}

// Close shuts down the endpoint: it stops accepting, closes the QUIC transport,
// and releases the UDP socket. In-flight connections are not forcibly closed.
func (e *Endpoint) Close(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	e.mu.Unlock()

	var firstErr error
	if e.listener != nil {
		if err := e.listener.Close(); err != nil {
			firstErr = err
		}
	}
	if err := e.transport.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := e.udp.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (e *Endpoint) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// alpnsToStrings converts ALPN byte strings to the []string the TLS config
// expects. Go strings hold arbitrary bytes, so the conversion is lossless.
func alpnsToStrings(alpns [][]byte) []string {
	out := make([]string, len(alpns))
	for i, a := range alpns {
		out[i] = string(a)
	}
	return out
}
