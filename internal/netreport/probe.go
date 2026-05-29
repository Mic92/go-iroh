package netreport

// Probe identifies how a relay's latency was measured. The order matches the
// Rust enum (iroh/src/net_report/probes.rs:22) so a [Probe] sorts and prints
// consistently across the port.
type Probe int

const (
	// ProbeHTTPS times an HTTPS GET of the relay's probe path.
	ProbeHTTPS Probe = iota
	// ProbeQADv4 times a QUIC Address Discovery connection over IPv4.
	ProbeQADv4
	// ProbeQADv6 times a QUIC Address Discovery connection over IPv6.
	ProbeQADv6
)

// String returns the probe name, matching the Rust Display impl.
func (p Probe) String() string {
	switch p {
	case ProbeHTTPS:
		return "Https"
	case ProbeQADv4:
		return "QadIpv4"
	case ProbeQADv6:
		return "QadIpv6"
	default:
		return "Probe(?)"
	}
}
