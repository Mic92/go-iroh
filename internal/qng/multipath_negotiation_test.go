package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// TestMultipathNegotiated checks the negotiation gate: multipath is negotiated
// (draft-ietf-quic-multipath) only when both peers advertise the
// initial_max_path_id transport parameter — locally via Config.InitialMaxPathID
// and remotely in the peer's received parameters.
func TestMultipathNegotiated(t *testing.T) {
	pid := protocol.PathID(8)
	local := uint32(8)

	tests := []struct {
		name      string
		localSet  bool
		peerSet   bool
		peerNil   bool // peerParams itself is nil (peer params not yet processed)
		negotiate bool
	}{
		{name: "both", localSet: true, peerSet: true, negotiate: true},
		{name: "local only", localSet: true, peerSet: false, negotiate: false},
		{name: "peer only", localSet: false, peerSet: true, negotiate: false},
		{name: "neither", localSet: false, peerSet: false, negotiate: false},
		{name: "peer params absent", localSet: true, peerNil: true, negotiate: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			if tc.localSet {
				v := local
				cfg.InitialMaxPathID = &v
			}
			var peer *wire.TransportParameters
			if !tc.peerNil {
				peer = &wire.TransportParameters{}
				if tc.peerSet {
					p := pid
					peer.InitialMaxPathID = &p
				}
			}
			c := &Conn{config: cfg, peerParams: peer}
			if got := c.multipathNegotiated(); got != tc.negotiate {
				t.Fatalf("multipathNegotiated() = %v, want %v", got, tc.negotiate)
			}
		})
	}
}

// TestInitialMaxPathIDParam checks the Config(*uint32) -> TP(*protocol.PathID)
// conversion that populates the local transport parameter.
func TestInitialMaxPathIDParam(t *testing.T) {
	if got := initialMaxPathIDParam(nil); got != nil {
		t.Fatalf("initialMaxPathIDParam(nil) = %v, want nil", got)
	}
	v := uint32(123)
	got := initialMaxPathIDParam(&v)
	if got == nil {
		t.Fatalf("initialMaxPathIDParam(&123) = nil")
	}
	if *got != protocol.PathID(123) {
		t.Fatalf("initialMaxPathIDParam(&123) = %d, want 123", *got)
	}
}
