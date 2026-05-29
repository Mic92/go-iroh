package netreport

import (
	"net/netip"
	"time"

	"github.com/tmc/go-iroh/base"
)

// Report describes the network environment as measured by a single
// [Client.GetReport] run. It is a port of iroh's net_report::Report
// (iroh/src/net_report/report.rs:14).
//
// The zero Report is a valid empty report.
type Report struct {
	// UDPv4 reports whether a QAD IPv4 round trip completed. Always false until
	// the qng observed-address extension lands; see the package doc.
	UDPv4 bool
	// UDPv6 reports whether a QAD IPv6 round trip completed. Always false until
	// the qng observed-address extension lands; see the package doc.
	UDPv6 bool

	// MappingVariesByDestV4 reports whether the observed public IPv4 address
	// differs across relays, when known.
	MappingVariesByDestV4 *bool
	// MappingVariesByDestV6 reports whether the observed public IPv6 address
	// differs across relays, when known.
	MappingVariesByDestV6 *bool

	// PreferredRelay is the relay with the best recent latency, chosen with
	// hysteresis. It is the zero RelayUrl when no relay responded.
	PreferredRelay base.RelayUrl

	// RelayLatency holds per-relay, per-probe latencies.
	RelayLatency RelayLatencies

	// GlobalV4 is the host's public IPv4 address as seen by a relay. Always
	// absent until the qng observed-address extension lands; see the package
	// doc.
	GlobalV4 netip.AddrPort
	// GlobalV6 is the host's public IPv6 address as seen by a relay. Always
	// absent until the qng observed-address extension lands; see the package
	// doc.
	GlobalV6 netip.AddrPort

	// CaptivePortal reports whether a captive portal is intercepting HTTP, when
	// the check ran (full reports only).
	CaptivePortal *bool
}

// HasUDP reports whether any QAD round trip succeeded.
func (r *Report) HasUDP() bool { return r.UDPv4 || r.UDPv6 }

// probeReport is the result of one probe, fed to [Report.update].
type probeReport struct {
	probe   Probe
	relay   base.RelayUrl
	latency time.Duration

	// addr is the reflexive address observed by a QAD probe. It is the zero
	// AddrPort until the qng observed-address extension lands, in which case the
	// QAD branch records latency only.
	addr netip.AddrPort
}

// update folds a probeReport into the report, mirroring Report::update
// (iroh/src/net_report/report.rs:63).
func (r *Report) update(report *probeReport) {
	r.RelayLatency.updateRelay(report.relay, report.latency, report.probe)

	switch report.probe {
	case ProbeQADv4:
		// Without the observed-address extension a QAD probe yields no addr, so
		// we cannot set UDPv4 or GlobalV4. Latency was already recorded above.
		if !report.addr.IsValid() {
			return
		}
		ipp := canonicalAddrPort(report.addr)
		if !ipp.Addr().Is4() {
			return // received IPv6 address from IPv4 QAD; ignore.
		}
		r.UDPv4 = true
		if r.GlobalV4.IsValid() {
			if r.GlobalV4 == ipp {
				if r.MappingVariesByDestV4 == nil {
					r.MappingVariesByDestV4 = boolPtr(false)
				}
			} else {
				r.MappingVariesByDestV4 = boolPtr(true)
			}
		} else {
			r.GlobalV4 = ipp
		}
	case ProbeQADv6:
		if !report.addr.IsValid() {
			return
		}
		ipp := report.addr
		if !ipp.Addr().Is6() || ipp.Addr().Is4In6() {
			return // received IPv4 address from IPv6 QAD; ignore.
		}
		r.UDPv6 = true
		if r.GlobalV6.IsValid() {
			if r.GlobalV6 == ipp {
				if r.MappingVariesByDestV6 == nil {
					r.MappingVariesByDestV6 = boolPtr(false)
				}
			} else {
				r.MappingVariesByDestV6 = boolPtr(true)
			}
		} else {
			r.GlobalV6 = ipp
		}
	}
}

// canonicalAddrPort unmaps an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to a
// plain IPv4 address, mirroring SocketAddr::ip().to_canonical()
// (iroh/src/net_report.rs:806, reportgen.rs:819).
func canonicalAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func boolPtr(b bool) *bool { return &b }

// RelayLatencies records the lowest latency seen per relay for each probe type.
// It is a port of net_report::RelayLatencies (report.rs:130). The zero value is
// empty and ready to use.
type RelayLatencies struct {
	ipv4  map[string]time.Duration // key: RelayUrl.String()
	ipv6  map[string]time.Duration
	https map[string]time.Duration
	// urls remembers the RelayUrl behind each key so iteration and lookup can
	// return a base.RelayUrl without re-parsing.
	urls map[string]base.RelayUrl
}

// updateRelay records latency for url under probe, keeping the minimum seen.
// Mirrors RelayLatencies::update_relay (report.rs:132).
func (rl *RelayLatencies) updateRelay(url base.RelayUrl, latency time.Duration, probe Probe) {
	if rl.urls == nil {
		rl.urls = map[string]base.RelayUrl{}
	}
	key := url.String()
	rl.urls[key] = url

	m := rl.bucket(probe, true)
	if old, ok := m[key]; !ok || latency < old {
		m[key] = latency
	}
}

// merge folds other into rl, keeping the minimum latency per (url, probe).
// Mirrors RelayLatencies::merge (report.rs:150).
func (rl *RelayLatencies) merge(other *RelayLatencies) {
	for key, l := range other.https {
		rl.updateRelay(other.urls[key], l, ProbeHTTPS)
	}
	for key, l := range other.ipv4 {
		rl.updateRelay(other.urls[key], l, ProbeQADv4)
	}
	for key, l := range other.ipv6 {
		rl.updateRelay(other.urls[key], l, ProbeQADv6)
	}
}

// get returns the lowest latency recorded for url across all probe types and
// whether any was recorded. Mirrors RelayLatencies::get (report.rs:200).
func (rl *RelayLatencies) get(url base.RelayUrl) (time.Duration, bool) {
	key := url.String()
	best := time.Duration(0)
	found := false
	for _, m := range []map[string]time.Duration{rl.https, rl.ipv4, rl.ipv6} {
		if l, ok := m[key]; ok && (!found || l < best) {
			best = l
			found = true
		}
	}
	return best, found
}

// isEmpty reports whether no latencies have been recorded.
func (rl *RelayLatencies) isEmpty() bool {
	return len(rl.https) == 0 && len(rl.ipv4) == 0 && len(rl.ipv6) == 0
}

// urlsByKey returns each relay url that has at least one recorded latency, in
// no particular order. Callers needing determinism must sort.
func (rl *RelayLatencies) relays() []base.RelayUrl {
	seen := map[string]struct{}{}
	var out []base.RelayUrl
	for _, m := range []map[string]time.Duration{rl.https, rl.ipv4, rl.ipv6} {
		for key := range m {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, rl.urls[key])
		}
	}
	return out
}

func (rl *RelayLatencies) bucket(probe Probe, create bool) map[string]time.Duration {
	var p *map[string]time.Duration
	switch probe {
	case ProbeHTTPS:
		p = &rl.https
	case ProbeQADv4:
		p = &rl.ipv4
	case ProbeQADv6:
		p = &rl.ipv6
	default:
		p = &rl.https
	}
	if *p == nil && create {
		*p = map[string]time.Duration{}
	}
	return *p
}
