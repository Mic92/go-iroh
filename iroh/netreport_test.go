package iroh

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
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

func TestNetReportTimeout(t *testing.T) {
	if NetReportTimeout != 5*time.Second {
		t.Fatalf("NetReportTimeout = %v, want 5s", NetReportTimeout)
	}
}
