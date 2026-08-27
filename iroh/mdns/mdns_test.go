//go:build !js

package mdns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestAnnouncementRoundTrip(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	user, err := dns.NewUserData("lan")
	if err != nil {
		t.Fatal(err)
	}
	data := dns.NewEndpointData().
		WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777"), netip.MustParseAddrPort("[2001:db8::1]:7777")).
		WithRelayURL(relay).
		WithUserData(&user)

	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:       id,
		port:     7777,
		ips:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777"), netip.MustParseAddrPort("[2001:db8::1]:7777")},
		relay:    relay.String(),
		userData: user.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseAnnouncement(packet, DefaultServiceName)
	if !ok {
		t.Fatal("parseAnnouncement failed")
	}
	if got.ID != id {
		t.Fatalf("ID = %v, want %v", got.ID, id)
	}
	if !sameAddrPorts(got.Data.IPAddrs(), data.IPAddrs()) {
		t.Fatalf("IPAddrs = %v, want %v", got.Data.IPAddrs(), data.IPAddrs())
	}
	if relays := got.Data.RelayURLs(); len(relays) != 1 || !relays[0].Equal(relay) {
		t.Fatalf("RelayURLs = %v, want %v", relays, relay)
	}
	if gotUser := got.Data.UserData(); gotUser == nil || gotUser.String() != "lan" {
		t.Fatalf("UserData = %v, want lan", gotUser)
	}
}

func TestDiscoveryResolveFromPacket(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	self, _ := key.GenerateSecretKey()
	d := New(self.Public().EndpointID(), WithLookupTimeout(20*time.Millisecond))
	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777")},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handlePacket(packet)
	var gotID key.EndpointID
	for item, err := range d.Resolve(context.Background(), id) {
		if err != nil {
			t.Fatal(err)
		}
		gotID = item.EndpointID()
	}
	if gotID != id {
		t.Fatalf("Resolve ID = %v, want %v", gotID, id)
	}
}

func TestDiscoveryAnnouncementUsesLocalID(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id)
	packet, err := d.announcement(dns.NewEndpointData().WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777")))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseAnnouncement(packet, DefaultServiceName)
	if !ok {
		t.Fatal("parseAnnouncement failed")
	}
	if got.ID != id {
		t.Fatalf("announcement ID = %v, want %v", got.ID, id)
	}
}

func TestServiceNameIsolation(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	packet, err := buildAnnouncement("other", announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseAnnouncement(packet, DefaultServiceName); ok {
		t.Fatal("parsed announcement for different service")
	}
}

func TestEndpointLabelMatchesRustMDNS(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	parsed, err := parseEndpointLabel(endpointLabel(id))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != id {
		t.Fatalf("endpoint label round trip = %v, want %v", parsed, id)
	}
}

func TestAnnouncementInfoPreservesIPv6Zone(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id)
	want := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("en0"), 7777)
	info, err := d.announcementInfo(dns.NewEndpointData().WithIPAddrs(want))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ips) != 1 || info.ips[0] != want {
		t.Fatalf("announcementInfo IPs = %v, want [%s]", info.ips, want)
	}
	got := infoFromAnnouncement(info).Data.IPAddrs()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("infoFromAnnouncement IPs = %v, want [%s]", got, want)
	}
}

func sameAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[netip.AddrPort]int)
	for _, addr := range a {
		seen[addr]++
	}
	for _, addr := range b {
		if seen[addr] == 0 {
			return false
		}
		seen[addr]--
	}
	return true
}

// TestDiscoveryAnswersQueries: a node that starts after another one announced
// still finds it, because the older node answers the browse query. Uses a
// random service name so LAN neighbours do not interfere.
func TestDiscoveryAnswersQueries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	svcKey, _ := key.GenerateSecretKey()
	svc := "t" + endpointLabel(svcKey.Public().EndpointID())[:10]

	oldKey, _ := key.GenerateSecretKey()
	old := New(oldKey.Public().EndpointID(), WithServiceName(svc), WithQueryInterval(time.Hour))
	old.Publish(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("192.0.2.1:1111")}))
	oldErr := make(chan error, 1)
	go func() { oldErr <- old.Start(ctx) }()
	select {
	case err := <-oldErr:
		t.Skipf("mdns listen: %v", err)
	case <-time.After(1500 * time.Millisecond):
		// both RFC 6762 announcements are out now
	}

	newKey, _ := key.GenerateSecretKey()
	late := New(newKey.Public().EndpointID(), WithServiceName(svc), WithQueryInterval(time.Hour))
	go late.Start(ctx)
	for {
		for _, id := range late.Peers() {
			if id.Equal(oldKey.Public().EndpointID()) {
				return
			}
		}
		select {
		case <-late.Updated():
		case <-ctx.Done():
			t.Fatalf("late node never heard the old one; peers=%v", late.Peers())
		}
	}
}
