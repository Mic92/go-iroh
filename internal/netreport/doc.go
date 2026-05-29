// Package netreport probes the local network environment to build a [Report]
// describing relay latencies and (where available) the public reflexive address
// of the host.
//
// It is a port of iroh's net_report module (iroh/src/net_report). A [Client]
// runs three kinds of probes against the configured relays:
//
//   - HTTPS probes fetch the relay's "/ping" path and time the round trip.
//   - QAD probes open a QUIC Address Discovery connection (ALPN "/iroh-qad/0",
//     QUIC port 7842) and read the connection RTT.
//   - A captive-portal check fetches "/generate_204" with an X-Iroh-Challenge
//     header and verifies the X-Iroh-Response echo, but only on full reports.
//
// From those probes the client picks a preferred relay, applying hysteresis so a
// responsive relay is not abandoned unless a new one is meaningfully faster.
//
// # Reflexive address discovery is degraded
//
// In Rust, a QAD connection also learns the host's public address from the
// relay via the QUIC observed-address extension. The forked quic-go in
// [github.com/tmc/go-iroh/internal/qng] does not yet implement that extension
// (tracked as slice X3), so QAD here yields latency only: [Report.GlobalV4] and
// [Report.GlobalV6] are always absent and [Report.UDPv4]/[Report.UDPv6] are
// never set. Relay selection and latency measurement are unaffected. When the
// extension lands this package can fill in the reflexive addresses without an
// API change.
package netreport
