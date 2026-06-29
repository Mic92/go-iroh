package iroh

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/netaddr"
)

func TestNetReportAccessor(t *testing.T) {
	var ep Endpoint
	if _, ok := ep.NetReport(); ok {
		t.Fatal("NetReport before report = ok, want false")
	}

	varies := true
	captive := false
	global := netip.MustParseAddrPort("203.0.113.1:1234")
	ep.applyNetReport(netreport.Report{
		UDPv4:                 true,
		MappingVariesByDestV4: &varies,
		GlobalV4:              global,
		CaptivePortal:         &captive,
	})
	got, ok := ep.NetReport()
	if !ok {
		t.Fatal("NetReport after report = false, want true")
	}
	if !got.HasUDP() || got.GlobalV4 != global {
		t.Fatalf("NetReport = %+v", got)
	}
	if got.MappingVariesByDestV4 == nil || !*got.MappingVariesByDestV4 {
		t.Fatalf("MappingVariesByDestV4 = %v, want true", got.MappingVariesByDestV4)
	}
	*got.MappingVariesByDestV4 = false
	again, ok := ep.NetReport()
	if !ok || again.MappingVariesByDestV4 == nil || !*again.MappingVariesByDestV4 {
		t.Fatalf("NetReport was mutated through returned pointer: %+v", again)
	}
}

func TestNetReportRelayLatenciesClone(t *testing.T) {
	u, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{
		lastReport: &NetReport{
			RelayLatencies: map[netaddr.RelayURL]time.Duration{u: 25 * time.Millisecond},
		},
	}

	got, ok := ep.NetReport()
	if !ok {
		t.Fatal("NetReport = false, want true")
	}
	got.RelayLatencies[u] = time.Hour
	again, ok := ep.NetReport()
	if !ok {
		t.Fatal("NetReport after mutation = false, want true")
	}
	if again.RelayLatencies[u] != 25*time.Millisecond {
		t.Fatalf("RelayLatencies alias endpoint state: got %v, want 25ms", again.RelayLatencies[u])
	}
}

func TestNetReportTimeout(t *testing.T) {
	if NetReportTimeout != 5*time.Second {
		t.Fatalf("NetReportTimeout = %v, want 5s", NetReportTimeout)
	}
}
