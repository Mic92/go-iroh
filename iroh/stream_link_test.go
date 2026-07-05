package iroh

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/tmc/go-iroh/netaddr"
)

func TestClassifyTransportLinkAddrs(t *testing.T) {
	fixtures := []net.Interface{
		{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
		{Name: "bridge0", Flags: net.FlagUp | net.FlagMulticast},
		{Name: "en5", Flags: net.FlagUp | net.FlagMulticast},
		{Name: "awdl0", Flags: net.FlagUp | net.FlagMulticast},
		{Name: "en0", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast},
		{Name: "wlan0", Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast},
		{Name: "utun0", Flags: net.FlagUp | net.FlagMulticast},
		{Name: "down0", Flags: net.FlagBroadcast | net.FlagMulticast},
	}
	addrByName := map[string][]net.Addr{
		"lo0":     {ipNet("127.0.0.1/8")},
		"bridge0": {&net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "bridge0"}},
		"en5":     {&net.IPAddr{IP: net.ParseIP("fe80::5"), Zone: "en5"}},
		"awdl0":   {&net.IPAddr{IP: net.ParseIP("fe80::2"), Zone: "awdl0"}},
		"en0":     {ipNet("192.0.2.10/24")},
		"wlan0":   {ipNet("192.0.2.11/24")},
		"utun0":   {ipNet("198.51.100.7/24")},
		"down0":   {ipNet("192.0.2.12/24")},
	}

	got, err := classifyTransportLinkAddrs(fixtures, func(iface net.Interface) ([]net.Addr, error) {
		return addrByName[iface.Name], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []TransportLinkAddr{
		{Interface: "lo0", Addr: ipNet("127.0.0.1/8"), Class: TransportLinkLoopback},
		{Interface: "bridge0", Addr: &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "bridge0"}, Class: TransportLinkThunderbolt},
		{Interface: "en5", Addr: &net.IPAddr{IP: net.ParseIP("fe80::5"), Zone: "en5"}, Class: TransportLinkThunderbolt},
		{Interface: "awdl0", Addr: &net.IPAddr{IP: net.ParseIP("fe80::2"), Zone: "awdl0"}, Class: TransportLinkAWDL},
		{Interface: "en0", Addr: ipNet("192.0.2.10/24"), Class: TransportLinkWiredLAN},
		{Interface: "wlan0", Addr: ipNet("192.0.2.11/24"), Class: TransportLinkWiFiLAN},
		{Interface: "utun0", Addr: ipNet("198.51.100.7/24"), Class: TransportLinkLAN},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("classes = %#v, want %#v", got, want)
	}
	if got[1].Addr.(*net.IPAddr).Zone != "bridge0" {
		t.Fatalf("zone = %q, want bridge0", got[1].Addr.(*net.IPAddr).Zone)
	}
	if got[2].Addr.(*net.IPAddr).Zone != "en5" {
		t.Fatalf("zone = %q, want en5", got[2].Addr.(*net.IPAddr).Zone)
	}
}

func TestClassifyTransportLinkAddrsReturnsAddrError(t *testing.T) {
	wantErr := errors.New("addr failure")
	_, err := classifyTransportLinkAddrs([]net.Interface{
		{Name: "en0", Flags: net.FlagUp | net.FlagMulticast},
	}, func(net.Interface) ([]net.Addr, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("classifyTransportLinkAddrs = %v, want %v", err, wantErr)
	}
}

func TestPreferredTransportLink(t *testing.T) {
	cases := []struct {
		name string
		a    []TransportLinkClass
		b    []TransportLinkClass
		want TransportLinkClass
	}{
		{
			name: "thunderbolt beats lower common class",
			a:    []TransportLinkClass{TransportLinkThunderbolt, TransportLinkWiFiLAN},
			b:    []TransportLinkClass{TransportLinkThunderbolt, TransportLinkWiredLAN},
			want: TransportLinkThunderbolt,
		},
		{
			name: "rdma is fastest shared class",
			a:    []TransportLinkClass{TransportLinkRDMA, TransportLinkThunderbolt},
			b:    []TransportLinkClass{TransportLinkRDMA, TransportLinkWiredLAN},
			want: TransportLinkRDMA,
		},
		{
			name: "disjoint falls back to lan",
			a:    []TransportLinkClass{TransportLinkWiFiLAN},
			b:    []TransportLinkClass{TransportLinkWiredLAN},
			want: TransportLinkLAN,
		},
		{
			name: "deterministic regardless of order",
			a:    []TransportLinkClass{TransportLinkLAN, TransportLinkThunderbolt, TransportLinkWiFiLAN},
			b:    []TransportLinkClass{TransportLinkWiFiLAN, TransportLinkThunderbolt, TransportLinkLAN},
			want: TransportLinkThunderbolt,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gotAB := PreferredTransportLink(tt.a, tt.b)
			gotBA := PreferredTransportLink(tt.b, tt.a)
			if gotAB != tt.want || gotBA != tt.want {
				t.Fatalf("PreferredTransportLink = %v/%v, want %v", gotAB, gotBA, tt.want)
			}
		})
	}
}

func TestPreferredTransportLinkChangesWithInterfaces(t *testing.T) {
	peer := []TransportLinkAddr{
		{Interface: "en0", Class: TransportLinkWiredLAN},
		{Interface: "bridge0", Class: TransportLinkThunderbolt},
	}
	before := []TransportLinkAddr{
		{Interface: "en0", Class: TransportLinkWiredLAN},
	}
	after := []TransportLinkAddr{
		{Interface: "en0", Class: TransportLinkWiredLAN},
		{Interface: "bridge0", Class: TransportLinkThunderbolt},
	}

	if got := PreferredTransportLinkAddr(before, peer); got != TransportLinkWiredLAN {
		t.Fatalf("before = %v, want %v", got, TransportLinkWiredLAN)
	}
	if got := PreferredTransportLinkAddr(after, peer); got != TransportLinkThunderbolt {
		t.Fatalf("after = %v, want %v", got, TransportLinkThunderbolt)
	}
}

func TestStreamLinkAddrRoundTrip(t *testing.T) {
	addr := NewStreamLinkAddr(12, TransportLinkThunderbolt, "en5", "[fe80::1%en5]:4433")
	got, err := ParseStreamLinkAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr.Compare(addr) != 0 {
		t.Fatalf("addr = %v, want %v", got.Addr, addr)
	}
	if got.Interface != "en5" || got.DialAddr != "[fe80::1%en5]:4433" || got.Class != TransportLinkThunderbolt {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestStreamLinkAddrParsesRawTCPAddress(t *testing.T) {
	addr := netaddr.NewCustomAddr(12, []byte("127.0.0.1:4433"))
	got, err := ParseStreamLinkAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.DialAddr != "127.0.0.1:4433" || got.Class != TransportLinkUnknown {
		t.Fatalf("parsed = %+v", got)
	}
}

func BenchmarkParseStreamLinkAddr(b *testing.B) {
	addr := NewStreamLinkAddr(12, TransportLinkThunderbolt, "bridge0", "[fe80::1%bridge0]:4433")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, err := ParseStreamLinkAddr(addr)
		if err != nil {
			b.Fatal(err)
		}
		if got.Class != TransportLinkThunderbolt || got.Interface != "bridge0" || got.DialAddr != "[fe80::1%bridge0]:4433" {
			b.Fatalf("parsed = %+v", got)
		}
	}
}

func TestSelectStreamLink(t *testing.T) {
	local := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiFiLAN, "wlan0", "192.0.2.11:1"),
		NewStreamLinkAddr(7, TransportLinkThunderbolt, "bridge0", "[fe80::1%bridge0]:1"),
	}
	remote := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.20:1"),
		NewStreamLinkAddr(7, TransportLinkThunderbolt, "bridge0", "[fe80::2%bridge0]:1"),
	}
	got, ok := SelectStreamLink(local, remote)
	if !ok {
		t.Fatal("SelectStreamLink failed")
	}
	if got.Class != TransportLinkThunderbolt {
		t.Fatalf("class = %v, want %v", got.Class, TransportLinkThunderbolt)
	}
	remoteLink, err := ParseStreamLinkAddr(got.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if remoteLink.DialAddr != "[fe80::2%bridge0]:1" {
		t.Fatalf("remote = %q, want thunderbolt addr", remoteLink.DialAddr)
	}
}

func TestSelectStreamLinkTieBreaksByAddress(t *testing.T) {
	local := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en1", "192.0.2.12:1"),
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.11:1"),
	}
	remote := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en1", "192.0.2.22:1"),
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.21:1"),
	}
	got, ok := SelectStreamLink(local, remote)
	if !ok {
		t.Fatal("SelectStreamLink failed")
	}
	link, err := ParseStreamLinkAddr(got.Remote)
	if err != nil {
		t.Fatal(err)
	}
	if link.DialAddr != "192.0.2.21:1" {
		t.Fatalf("remote = %q, want lowest encoded address", link.DialAddr)
	}
}

func TestSelectStreamLinkChangesWithAdvertisedAddrs(t *testing.T) {
	local := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.11:1"),
	}
	remoteBefore := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.20:1"),
	}
	remoteAfter := []netaddr.CustomAddr{
		NewStreamLinkAddr(7, TransportLinkWiredLAN, "en0", "192.0.2.20:1"),
		NewStreamLinkAddr(7, TransportLinkRDMA, "rdma0", "rdma://peer"),
	}
	localAfter := append(local, NewStreamLinkAddr(7, TransportLinkRDMA, "rdma0", "rdma://local"))

	before, ok := SelectStreamLink(local, remoteBefore)
	if !ok {
		t.Fatal("SelectStreamLink before failed")
	}
	after, ok := SelectStreamLink(localAfter, remoteAfter)
	if !ok {
		t.Fatal("SelectStreamLink after failed")
	}
	if before.Class != TransportLinkWiredLAN || after.Class != TransportLinkRDMA {
		t.Fatalf("class = %v then %v, want wired then rdma", before.Class, after.Class)
	}
}

func TestTCPDialAddrFromNetAddrPreservesZone(t *testing.T) {
	got, ok := tcpDialAddrFromNetAddr("ignored", &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "en5"}, 4433)
	if !ok {
		t.Fatal("tcpDialAddrFromNetAddr failed")
	}
	if got != "[fe80::1%en5]:4433" {
		t.Fatalf("addr = %q, want scoped link-local dial addr", got)
	}
}

func TestTCPDialAddrFromLinkAddrUsesInterfaceZone(t *testing.T) {
	got, ok := tcpDialAddrFromLinkAddr(TransportLinkAddr{
		Interface: "bridge0",
		Addr:      ipNet("fe80::1/64"),
		Class:     TransportLinkThunderbolt,
	}, 4433)
	if !ok {
		t.Fatal("tcpDialAddrFromLinkAddr failed")
	}
	if got != "[fe80::1%bridge0]:4433" {
		t.Fatalf("addr = %q, want scoped link-local dial addr", got)
	}
}

func TestRDMAStreamTransportUnsupported(t *testing.T) {
	tr, err := NewRDMAStreamTransport(99)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if tr.LinkClass() != TransportLinkRDMA {
		t.Fatalf("LinkClass = %v, want %v", tr.LinkClass(), TransportLinkRDMA)
	}
	if _, err := tr.DialStream(nil, netaddr.NewCustomAddr(99, []byte("rdma")), StreamOptions{}); !errors.Is(err, ErrRDMAUnsupported) {
		t.Fatalf("DialStream = %v, want %v", err, ErrRDMAUnsupported)
	}
}

func ipNet(s string) *net.IPNet {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}
