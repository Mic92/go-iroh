//go:build !js

package mdns

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	iroh "github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// DefaultServiceName is the Rust iroh-mdns-address-lookup service name.
	DefaultServiceName = "irohv1"
	// Provenance is the provenance reported on resolved mDNS items.
	Provenance = "mdns"

	defaultLookupTimeout = 10 * time.Second
	mdnsPort             = 5353
	// DefaultQueryInterval is how often the service is browsed so peers that
	// joined later, or whose announcement was lost, are still found.
	DefaultQueryInterval = time.Minute
)

var (
	ipv4Multicast = netip.MustParseAddrPort("224.0.0.251:5353")
	ipv6Multicast = netip.MustParseAddrPort("[ff02::fb]:5353")

	errNoAddresses = errors.New("mdns: endpoint data has no IP addresses")
)

// Discovery publishes and resolves iroh endpoint addressing information over
// multicast DNS. The zero value is not usable; create one with [New].
type Discovery struct {
	id          key.EndpointID
	serviceName string
	passive     bool
	timeout     time.Duration

	interval time.Duration

	mu      sync.RWMutex
	peers   map[key.EndpointID]peerInfo
	conn4   *net.UDPConn
	conn6   *net.UDPConn
	last    []byte // most recent announcement, answered to queries
	updated chan struct{}
}

type peerInfo struct {
	data        dns.EndpointData
	lastUpdated uint64
}

// Option configures a Discovery.
type Option func(*Discovery)

// WithServiceName changes the DNS-SD service name. The default is "irohv1",
// yielding records under _irohv1._udp.local.
func WithServiceName(name string) Option {
	return func(d *Discovery) {
		if name != "" {
			d.serviceName = name
		}
	}
}

// WithPassive disables publishing. The Discovery still listens and resolves.
func WithPassive(passive bool) Option {
	return func(d *Discovery) {
		d.passive = passive
	}
}

// WithLookupTimeout sets how long Resolve waits for a multicast response after
// a cache miss. Non-positive values use the default.
func WithLookupTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		if timeout > 0 {
			d.timeout = timeout
		}
	}
}

// WithQueryInterval sets how often the local network is browsed for the
// service while Start runs. Non-positive values use [DefaultQueryInterval].
func WithQueryInterval(every time.Duration) Option {
	return func(d *Discovery) {
		if every > 0 {
			d.interval = every
		}
	}
}

// New returns a Discovery for id using the default iroh local-network service
// name.
func New(id key.EndpointID, opts ...Option) *Discovery {
	d := &Discovery{
		id:          id,
		serviceName: DefaultServiceName,
		timeout:     defaultLookupTimeout,
		interval:    DefaultQueryInterval,
		peers:       make(map[key.EndpointID]peerInfo),
		updated:     make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Start listens for mDNS packets on IPv4 and IPv6 until ctx is cancelled,
// answers queries for this endpoint's instance, and browses the service every
// query interval. It is safe to call Publish before Start, but Resolve and
// Peers only observe remote responses while Start is running.
func (d *Discovery) Start(ctx context.Context) error {
	if d == nil {
		return errors.New("mdns: nil Discovery")
	}
	conn4, err4 := listenMDNS(ctx, false)
	conn6, err6 := listenMDNS(ctx, true)
	if err4 != nil && err6 != nil {
		return errors.Join(err4, err6)
	}
	d.mu.Lock()
	d.conn4, d.conn6 = conn4, conn6
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.conn4, d.conn6 = nil, nil
		d.mu.Unlock()
	}()
	errc := make(chan error, 2)
	for _, c := range []*net.UDPConn{conn4, conn6} {
		if c != nil {
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stop()
			go func() { errc <- d.readLoop(ctx, c) }()
		}
	}

	// RFC 6762 §8.3: announce at least twice, one second apart. Then browse
	// so already-running peers answer.
	d.reannounce()
	d.browse()
	second := time.After(time.Second)
	tick := time.NewTicker(d.interval)
	defer tick.Stop()
	for {
		select {
		case err := <-errc:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-second:
			d.reannounce()
		case <-tick.C:
			d.browse()
		}
	}
}

func (d *Discovery) reannounce() {
	d.mu.RLock()
	last := d.last
	d.mu.RUnlock()
	d.writeMulticast(last)
}

func (d *Discovery) readLoop(ctx context.Context, conn *net.UDPConn) error {
	buf := make([]byte, 9000)
	for {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("mdns: read: %w", err)
		}
		d.handlePacket(buf[:n])
	}
}

// Peers returns the endpoints heard on the local network so far.
func (d *Discovery) Peers() []key.EndpointID {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]key.EndpointID, 0, len(d.peers))
	for id := range d.peers {
		out = append(out, id)
	}
	return out
}

// Updated is signalled (coalesced) when Peers gains a member or a member's
// addresses change.
func (d *Discovery) Updated() <-chan struct{} { return d.updated }

func listenMDNS(ctx context.Context, v6 bool) (*net.UDPConn, error) {
	network, host := "udp4", "0.0.0.0"
	if v6 {
		network, host = "udp6", "::"
	}
	lc := net.ListenConfig{Control: reusePortControl}
	pc, err := lc.ListenPacket(ctx, network, net.JoinHostPort(host, fmt.Sprint(mdnsPort)))
	if err != nil {
		return nil, fmt.Errorf("mdns: listen %s: %w", network, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("mdns: listen did not return UDPConn")
	}
	join := func(ifi *net.Interface) error {
		if v6 {
			p := ipv6.NewPacketConn(conn)
			_ = p.SetMulticastLoopback(true)
			return p.JoinGroup(ifi, &net.UDPAddr{IP: ipv6Multicast.Addr().AsSlice()})
		}
		p := ipv4.NewPacketConn(conn)
		_ = p.SetMulticastLoopback(true)
		return p.JoinGroup(ifi, &net.UDPAddr{IP: ipv4Multicast.Addr().AsSlice()})
	}
	joined := false
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagMulticast == 0 {
			continue
		}
		if err := join(&ifaces[i]); err == nil {
			joined = true
		}
	}
	if !joined {
		if err := join(nil); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("mdns: join %s multicast: %w", network, err)
		}
	}
	return conn, nil
}

// Publish advertises data on the local network. It is fire-and-forget and
// returns immediately, matching iroh.AddressPublisher.
func (d *Discovery) Publish(data dns.EndpointData) {
	if d == nil || d.passive {
		return
	}
	packet, err := d.announcement(data)
	if err != nil {
		return
	}
	d.mu.Lock()
	d.last = packet
	d.mu.Unlock()
	go d.writeMulticast(packet)
}

// Resolve returns the cached item for id, if present, and otherwise sends a
// multicast query and waits for a matching response until ctx or the lookup
// timeout fires.
func (d *Discovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	if d == nil {
		return nil
	}
	return func(yield func(iroh.Item, error) bool) {
		if item, ok := d.item(id); ok {
			yield(item, nil)
			return
		}
		d.query(id)
		timer := time.NewTimer(d.timeout)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				yield(iroh.Item{}, ctx.Err())
				return
			case <-timer.C:
				return
			case <-tick.C:
				if item, ok := d.item(id); ok {
					yield(item, nil)
					return
				}
			}
		}
	}
}

func (d *Discovery) item(id key.EndpointID) (iroh.Item, bool) {
	d.mu.RLock()
	peer, ok := d.peers[id]
	d.mu.RUnlock()
	if !ok {
		return iroh.Item{}, false
	}
	info := dns.EndpointInfo{ID: id, Data: cloneEndpointData(peer.data)}
	return iroh.NewItem(info, Provenance, &peer.lastUpdated), true
}

func (d *Discovery) handlePacket(packet []byte) {
	msg, err := parseDNS(packet)
	if err != nil {
		return
	}
	if !msg.response {
		d.answer(msg.questions)
		return
	}
	info, ok := infoFromMessage(msg, d.serviceName)
	if !ok || info.ID.Equal(d.id) {
		return
	}
	d.mu.Lock()
	prev, known := d.peers[info.ID]
	d.peers[info.ID] = peerInfo{
		data:        cloneEndpointData(info.Data),
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	d.mu.Unlock()
	same := func(a, b netaddr.TransportAddr) bool { return a.Compare(b) == 0 }
	if !known || !slices.EqualFunc(prev.data.Addrs(), info.Data.Addrs(), same) {
		select {
		case d.updated <- struct{}{}:
		default:
		}
	}
}

// answer responds with our announcement when a query names our service or
// our instance.
func (d *Discovery) answer(questions []string) {
	if d.passive {
		return
	}
	svc := strings.ToLower(serviceName(d.serviceName))
	inst := strings.ToLower(instanceName(d.serviceName, d.id))
	if slices.Contains(questions, svc) || slices.Contains(questions, inst) {
		d.reannounce()
	}
}

// browse asks every instance of the service to announce itself.
func (d *Discovery) browse() {
	packet, err := buildQuery(serviceName(d.serviceName))
	if err != nil {
		return
	}
	d.writeMulticast(packet)
}

func (d *Discovery) query(id key.EndpointID) {
	name := instanceName(d.serviceName, id)
	packet, err := buildQuery(serviceName(d.serviceName), name)
	if err != nil {
		return
	}
	go d.writeMulticast(packet)
}

func (d *Discovery) writeMulticast(packet []byte) {
	if len(packet) == 0 {
		return
	}
	d.mu.RLock()
	conn4, conn6 := d.conn4, d.conn6
	d.mu.RUnlock()
	if conn4 == nil && conn6 == nil {
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.WriteToUDPAddrPort(packet, ipv4Multicast)
		return
	}
	if conn4 != nil {
		_, _ = conn4.WriteToUDPAddrPort(packet, ipv4Multicast)
	}
	if conn6 != nil {
		// ff02::fb is link-scoped, so send once per multicast interface.
		sent := false
		ifaces, _ := net.Interfaces()
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
				continue
			}
			dst := netip.AddrPortFrom(ipv6Multicast.Addr().WithZone(ifi.Name), mdnsPort)
			if _, err := conn6.WriteToUDPAddrPort(packet, dst); err == nil {
				sent = true
			}
		}
		if !sent {
			_, _ = conn6.WriteToUDPAddrPort(packet, ipv6Multicast)
		}
	}
}

func (d *Discovery) announcement(data dns.EndpointData) ([]byte, error) {
	info, err := d.announcementInfo(data)
	if err != nil {
		return nil, err
	}
	return buildAnnouncement(d.serviceName, info)
}

type announcementData struct {
	id       key.EndpointID
	port     uint16
	ips      []netip.AddrPort
	relay    string
	userData string
}

func (d *Discovery) announcementInfo(data dns.EndpointData) (announcementData, error) {
	ipAddrs := data.IPAddrs()
	if len(ipAddrs) == 0 {
		return announcementData{}, errNoAddresses
	}
	out := announcementData{id: d.id}
	port := ipAddrs[0].Port()
	out.port = port
	for _, addr := range ipAddrs {
		if addr.Port() != port || !addr.Addr().IsValid() {
			continue
		}
		out.ips = append(out.ips, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
	}
	if len(out.ips) == 0 {
		return announcementData{}, errNoAddresses
	}
	if relays := data.RelayURLs(); len(relays) != 0 {
		if s := relays[0].String(); len(s) <= 249 {
			out.relay = s
		}
	}
	if u := data.UserData(); u != nil {
		out.userData = u.String()
	}
	return out, nil
}

func cloneEndpointData(data dns.EndpointData) dns.EndpointData {
	out := dns.NewEndpointData(data.Addrs()...)
	if u := data.UserData(); u != nil {
		c := *u
		out.SetUserData(&c)
	}
	return out
}

func endpointLabel(id key.EndpointID) string {
	b := id.Bytes()
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

func parseEndpointLabel(label string) (key.EndpointID, error) {
	return key.ParseEndpointID(label)
}

func serviceName(service string) string {
	service = strings.Trim(service, ".")
	if !strings.HasPrefix(service, "_") {
		service = "_" + service
	}
	return service + "._udp.local"
}

func instanceName(service string, id key.EndpointID) string {
	return endpointLabel(id) + "." + serviceName(service)
}

func hostName(id key.EndpointID) string {
	return endpointLabel(id) + ".local"
}

func infoFromAnnouncement(a announcementData) dns.EndpointInfo {
	data := dns.NewEndpointData()
	addrs := append([]netip.AddrPort(nil), a.ips...)
	data.AddIPAddrs(addrs...)
	if a.relay != "" {
		if relay, err := netaddr.ParseRelayURL(a.relay); err == nil {
			data.AddRelayURL(relay)
		}
	}
	if a.userData != "" {
		if u, err := dns.NewUserData(a.userData); err == nil {
			data.SetUserData(&u)
		}
	}
	return dns.EndpointInfo{ID: a.id, Data: data}
}

var (
	_ iroh.AddressPublisher = (*Discovery)(nil)
	_ iroh.AddressResolver  = (*Discovery)(nil)
)
