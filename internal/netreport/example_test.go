package netreport_test

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/relay"
)

// Example shows running a net_report against an empty relay map, which performs
// no probes and yields an empty report. With real relays configured, the report
// would carry per-relay latencies and a preferred relay.
func Example() {
	client := netreport.NewClient(relay.NewMap())

	report, err := client.GetReport(context.Background(), netreport.IfStateDetails{HaveV4: true}, true)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("has udp:", report.HasUDP())
	fmt.Println("preferred relay set:", !report.PreferredRelay.IsZero())
	// Output:
	// has udp: false
	// preferred relay set: false
}

// ExampleProbe_String prints the wire-stable probe names.
func ExampleProbe_String() {
	fmt.Println(netreport.ProbeHTTPS)
	fmt.Println(netreport.ProbeQADv4)
	fmt.Println(netreport.ProbeQADv6)
	// Output:
	// Https
	// QadIpv4
	// QadIpv6
}
