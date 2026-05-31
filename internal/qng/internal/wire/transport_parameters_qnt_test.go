package wire

import (
	"bytes"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests pin the inert n0_nat_traversal transport parameter codec against
// internal/qng/n0ext/reference/transport_parameters.rs. This parameter is the
// QNT negotiation gate only; decoding it does not flip the parser gate.
//
// Reference: N0NatTraversal = 0x3d7f91120401, encoded as
// id | len(1) | NonZeroU8(max_remote_nat_traversal_addresses).

func TestN0NATTraversalParameterGolden(t *testing.T) {
	const limit = uint8(32)
	want := []byte{
		0xc0, 0x00, 0x3d, 0x7f, 0x91, 0x12, 0x04, 0x01, // id 0x3d7f91120401
		0x01, // len
		0x20, // max_remote_nat_traversal_addresses
	}

	got := (&TransportParameters{}).marshalN0NATTraversalParam(nil, limit)
	if !bytes.Equal(got, want) {
		t.Fatalf("marshal n0_nat_traversal = % x, want % x", got, want)
	}

	p, err := decodeBareTP(t, want)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.MaxRemoteNATTraversalAddresses == nil {
		t.Fatal("MaxRemoteNATTraversalAddresses not set")
	}
	if *p.MaxRemoteNATTraversalAddresses != limit {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %d, want %d", *p.MaxRemoteNATTraversalAddresses, limit)
	}
}

func TestN0NATTraversalParameterRoundTrip(t *testing.T) {
	limit := uint8(8)
	in := &TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		ActiveConnectionIDLimit:         protocol.MaxActiveConnectionIDs,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
		MaxRemoteNATTraversalAddresses:  &limit,
	}
	b := in.Marshal(protocol.PerspectiveServer)
	var out TransportParameters
	if err := out.Unmarshal(b, protocol.PerspectiveServer); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.MaxRemoteNATTraversalAddresses == nil {
		t.Fatal("MaxRemoteNATTraversalAddresses lost in round-trip")
	}
	if *out.MaxRemoteNATTraversalAddresses != limit {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %d, want %d", *out.MaxRemoteNATTraversalAddresses, limit)
	}
}

func TestN0NATTraversalParameterAbsent(t *testing.T) {
	in := &TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		ActiveConnectionIDLimit:         protocol.MaxActiveConnectionIDs,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
	}
	b := in.Marshal(protocol.PerspectiveServer)
	var out TransportParameters
	if err := out.Unmarshal(b, protocol.PerspectiveServer); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.MaxRemoteNATTraversalAddresses != nil {
		t.Fatalf("MaxRemoteNATTraversalAddresses = %d, want nil", *out.MaxRemoteNATTraversalAddresses)
	}
}

func TestN0NATTraversalParameterMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{
			name: "zero",
			b:    (&TransportParameters{}).marshalN0NATTraversalParam(nil, 0),
		},
		{
			name: "empty",
			b:    append(quicvarint.Append(nil, uint64(n0NATTraversalParameterID)), 0),
		},
		{
			name: "overlong",
			b:    append(quicvarint.Append(quicvarint.Append(nil, uint64(n0NATTraversalParameterID)), 2), 1, 0),
		},
		{
			name: "duplicate",
			b: append((&TransportParameters{}).marshalN0NATTraversalParam(nil, 1),
				(&TransportParameters{}).marshalN0NATTraversalParam(nil, 2)...),
		},
	}
	for _, tc := range cases {
		if _, err := decodeBareTP(t, tc.b); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestN0NATTraversalDoesNotAdmitFrames(t *testing.T) {
	p := &TransportParameters{}
	b := p.marshalN0NATTraversalParam(nil, 8)
	if _, err := decodeBareTP(t, b); err != nil {
		t.Fatalf("decode n0_nat_traversal: %v", err)
	}

	parser := NewFrameParser(false, false, false, false)
	// QNT frame types begin at 0x3d7f90 (COMPLETE-DRIVER-PROMPT.md). The inert
	// transport parameter codec must not change parser admission.
	frameType := quicvarint.Append(nil, 0x3d7f90)
	if _, _, err := parser.ParseType(frameType, protocol.Encryption1RTT); err == nil {
		t.Fatal("QNT frame type admitted after transport parameter decode")
	}
}
