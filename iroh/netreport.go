package iroh

import (
	"net/netip"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/netaddr"
)

// NetReportTimeout is the timeout for a complete network report.
const NetReportTimeout = 5 * time.Second

// NetReport is the public snapshot of the endpoint's most recent network
// report. The active probing client remains internal.
type NetReport struct {
	// UDPv4 reports whether a QAD IPv4 round trip completed and reported an
	// observed IPv4 address.
	UDPv4 bool
	// UDPv6 reports whether a QAD IPv6 round trip completed and reported an
	// observed IPv6 address.
	UDPv6 bool

	// MappingVariesByDestV4 reports whether the observed public IPv4 address
	// differs across relays, when known.
	MappingVariesByDestV4 *bool
	// MappingVariesByDestV6 reports whether the observed public IPv6 address
	// differs across relays, when known.
	MappingVariesByDestV6 *bool

	// PreferredRelay is the relay with the best recent latency, chosen with
	// hysteresis. It is the zero RelayURL when no relay responded.
	PreferredRelay netaddr.RelayURL
	// RelayLatencies is the lowest latency recorded for each relay.
	RelayLatencies map[netaddr.RelayURL]time.Duration

	// GlobalV4 is the host's public IPv4 address as seen by a relay.
	GlobalV4 netip.AddrPort
	// GlobalV6 is the host's public IPv6 address as seen by a relay.
	GlobalV6 netip.AddrPort

	// CaptivePortal reports whether a captive portal is intercepting HTTP, when
	// the check ran.
	CaptivePortal *bool
}

// HasUDP reports whether any QAD round trip succeeded.
func (r NetReport) HasUDP() bool { return r.UDPv4 || r.UDPv6 }

func netReportFromInternal(r netreport.Report) NetReport {
	return NetReport{
		UDPv4:                 r.UDPv4,
		UDPv6:                 r.UDPv6,
		MappingVariesByDestV4: boolCopy(r.MappingVariesByDestV4),
		MappingVariesByDestV6: boolCopy(r.MappingVariesByDestV6),
		PreferredRelay:        r.PreferredRelay,
		RelayLatencies:        cloneRelayLatencies(r.RelayLatency.Snapshot()),
		GlobalV4:              r.GlobalV4,
		GlobalV6:              r.GlobalV6,
		CaptivePortal:         boolCopy(r.CaptivePortal),
	}
}

func (r NetReport) clone() NetReport {
	r.MappingVariesByDestV4 = boolCopy(r.MappingVariesByDestV4)
	r.MappingVariesByDestV6 = boolCopy(r.MappingVariesByDestV6)
	r.CaptivePortal = boolCopy(r.CaptivePortal)
	r.RelayLatencies = cloneRelayLatencies(r.RelayLatencies)
	return r
}

func boolCopy(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneRelayLatencies(in map[netaddr.RelayURL]time.Duration) map[netaddr.RelayURL]time.Duration {
	if len(in) == 0 {
		return nil
	}
	out := make(map[netaddr.RelayURL]time.Duration, len(in))
	for url, latency := range in {
		out[url] = latency
	}
	return out
}
