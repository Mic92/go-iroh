package quic

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/flowcontrol"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// TestQNTNegotiated checks the negotiation gate: n0 NAT traversal is negotiated
// only when both peers advertise the n0_nat_traversal transport parameter with a
// non-zero address limit. Connection-level parser admission remains disabled in
// this slice because the operational state machine is still fail-closed.
func TestQNTNegotiated(t *testing.T) {
	const local = uint8(8)
	const peerLimit = uint8(16)

	tests := []struct {
		name    string
		local   *uint8
		peer    *uint8
		peerNil bool
		want    bool
	}{
		{name: "both", local: ptrTo(local), peer: ptrTo(peerLimit), want: true},
		{name: "local only", local: ptrTo(local), want: false},
		{name: "peer only", peer: ptrTo(peerLimit), want: false},
		{name: "neither", want: false},
		{name: "local zero", local: ptrTo(uint8(0)), peer: ptrTo(peerLimit), want: false},
		{name: "peer zero", local: ptrTo(local), peer: ptrTo(uint8(0)), want: false},
		{name: "peer params absent", local: ptrTo(local), peerNil: true, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{MaxRemoteNATTraversalAddresses: tc.local}
			var peer *wire.TransportParameters
			if !tc.peerNil {
				peer = &wire.TransportParameters{MaxRemoteNATTraversalAddresses: tc.peer}
			}
			c := &Conn{config: cfg, peerParams: peer}
			if got := c.qntNegotiated(); got != tc.want {
				t.Fatalf("qntNegotiated() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMaxRemoteNATTraversalAddressesParam(t *testing.T) {
	if got := maxRemoteNATTraversalAddressesParam(nil); got != nil {
		t.Fatalf("nil config = %v, want nil", *got)
	}
	zero := uint8(0)
	if got := maxRemoteNATTraversalAddressesParam(&zero); got != nil {
		t.Fatalf("zero config = %v, want nil", *got)
	}
	limit := uint8(8)
	got := maxRemoteNATTraversalAddressesParam(&limit)
	if got == nil || *got != limit {
		t.Fatalf("limit config = %v, want %d", got, limit)
	}
	limit = 9
	if *got != 8 {
		t.Fatalf("returned pointer aliases config value, got %d after mutation", *got)
	}
}

func TestQNTConfigClone(t *testing.T) {
	limit := uint8(8)
	cfg := populateConfig(&Config{MaxRemoteNATTraversalAddresses: &limit})
	if cfg.MaxRemoteNATTraversalAddresses == nil {
		t.Fatal("MaxRemoteNATTraversalAddresses lost in populateConfig")
	}
	if *cfg.MaxRemoteNATTraversalAddresses != limit {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %d, want %d", *cfg.MaxRemoteNATTraversalAddresses, limit)
	}
}

func TestQNTApplyTransportParametersDoesNotAdmitFrames(t *testing.T) {
	const limit = uint8(8)
	c := newQNTTransportParameterConn(limit, limit)
	c.applyTransportParameters()
	if !c.qntNegotiated() {
		t.Fatal("qntNegotiated() = false, want true")
	}
	for _, ft := range []wire.FrameType{
		wire.FrameTypeAddIPv4Address,
		wire.FrameTypeAddIPv6Address,
		wire.FrameTypeReachOutAtIPv4,
		wire.FrameTypeReachOutAtIPv6,
		wire.FrameTypeRemoveAddress,
	} {
		b := quicvarint.Append(nil, uint64(ft))
		if _, _, err := c.frameParser.ParseType(b, protocol.Encryption1RTT); err == nil {
			t.Fatalf("ParseType(%#x) admitted QNT frame after negotiation", uint64(ft))
		}
	}
}

func newQNTTransportParameterConn(local, peer uint8) *Conn {
	cfg := populateConfig(&Config{MaxRemoteNATTraversalAddresses: &local})
	c := &Conn{
		config:     cfg,
		peerParams: &wire.TransportParameters{MaxRemoteNATTraversalAddresses: &peer},
		rttStats:   utils.NewRTTStats(),
		frameParser: *wire.NewFrameParser(
			cfg.EnableDatagrams,
			cfg.EnableStreamResetPartialDelivery,
			false,
			false,
		),
	}
	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.ByteCount(cfg.InitialConnectionReceiveWindow),
		protocol.ByteCount(cfg.MaxConnectionReceiveWindow),
		nil,
		c.rttStats,
		nil,
	)
	c.streamsMap = newStreamsMap(
		context.Background(),
		c,
		func(wire.Frame) {},
		c.newFlowController,
		uint64(cfg.MaxIncomingStreams),
		uint64(cfg.MaxIncomingUniStreams),
		protocol.PerspectiveClient,
	)
	c.connIDGenerator = newConnIDGenerator(
		stubConnRunner{},
		protocol.ConnectionID{},
		nil,
		nil,
		connRunnerCallbacks{},
		func(wire.Frame) {},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 0},
	)
	return c
}

func ptrTo[T any](v T) *T {
	return &v
}
