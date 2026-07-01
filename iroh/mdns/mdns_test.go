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
		ips:      []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
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
	d := New(id, WithLookupTimeout(20*time.Millisecond))
	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
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
		ips:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
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
