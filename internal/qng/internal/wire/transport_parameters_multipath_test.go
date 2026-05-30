package wire

import (
	"bytes"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests pin the initial_max_path_id transport parameter (the QUIC
// multipath negotiation gate, draft-ietf-quic-multipath) against the
// authoritative noq-proto reference
// (internal/qng/n0ext/reference/transport_parameters.rs).
//
//   - The id is 0x3e (transport_parameters.rs:729 InitialMaxPathId = 0x3e).
//     0x3e = 62 < 64, so it encodes as a single-byte QUIC varint 0x3e.
//   - The value is a PathId (u32) written as a varint; the declared length is
//     that varint's size (transport_parameters.rs:412-418 write,
//     transport_parameters.rs:537-548 read which requires len == value.size()).

// decodeBareTP decodes a hand-built transport-parameter byte string in
// isolation, skipping the mandatory-field checks (initial_source_connection_id
// etc.) the way the session-ticket path does, so a single parameter can be
// pinned without constructing a full handshake's worth of parameters.
func decodeBareTP(t *testing.T, b []byte) (*TransportParameters, error) {
	t.Helper()
	var p TransportParameters
	err := p.unmarshal(b, protocol.PerspectiveServer, true)
	return &p, err
}

func TestInitialMaxPathIDParameterGolden(t *testing.T) {
	cases := []struct {
		name  string
		pid   protocol.PathID
		bytes []byte // id (0x3e) | len | value-varint
	}{
		// PathID 5: id 0x3e, len 0x01, value 0x05.
		{"small", 5, []byte{0x3e, 0x01, 0x05}},
		// PathID::MAX (transport_parameters.rs:844 uses PathId::MAX): u32::MAX
		// is a 4-byte varint payload, encoded in the 8-byte varint form, so the
		// declared length is 0x08.
		{"max", protocol.PathIDMax, []byte{0x3e, 0x08, 0xc0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode just this parameter by hand-shaping the Marshal output:
			// build a TransportParameters carrying only InitialMaxPathID and
			// confirm the parameter appears with the expected bytes.
			got := (&TransportParameters{}).marshalVarintParam(nil, initialMaxPathIDParameterID, uint64(tc.pid))
			if !bytes.Equal(got, tc.bytes) {
				t.Fatalf("marshal initial_max_path_id(%d) = % x, want % x", tc.pid, got, tc.bytes)
			}
			// Decode the golden bytes back.
			p, err := decodeBareTP(t, tc.bytes)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.InitialMaxPathID == nil {
				t.Fatalf("InitialMaxPathID not set")
			}
			if *p.InitialMaxPathID != tc.pid {
				t.Fatalf("InitialMaxPathID = %d, want %d", *p.InitialMaxPathID, tc.pid)
			}
		})
	}
}

func TestInitialMaxPathIDRoundTrip(t *testing.T) {
	pid := protocol.PathID(42)
	in := &TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		ActiveConnectionIDLimit:         protocol.MaxActiveConnectionIDs,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
		InitialMaxPathID:                &pid,
	}
	// A server marshals params (incl. original_destination_connection_id); the
	// peer reads them with sentBy=PerspectiveServer.
	b := in.Marshal(protocol.PerspectiveServer)
	var out TransportParameters
	if err := out.Unmarshal(b, protocol.PerspectiveServer); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.InitialMaxPathID == nil {
		t.Fatalf("InitialMaxPathID lost in round-trip")
	}
	if *out.InitialMaxPathID != pid {
		t.Fatalf("InitialMaxPathID = %d, want %d", *out.InitialMaxPathID, pid)
	}
}

func TestInitialMaxPathIDAbsent(t *testing.T) {
	// With multipath disabled, the parameter must not be emitted and must decode
	// as nil (single-path unchanged).
	in := &TransportParameters{
		OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{5, 6, 7, 8}),
		InitialSourceConnectionID:       protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		ActiveConnectionIDLimit:         protocol.MaxActiveConnectionIDs,
		MaxDatagramFrameSize:            protocol.InvalidByteCount,
	}
	b := in.Marshal(protocol.PerspectiveServer)
	// The id byte 0x3e must not appear as a parameter id. It can legitimately
	// appear inside other varint payloads, so decode and assert the field stays
	// nil instead of scanning bytes.
	var out TransportParameters
	if err := out.Unmarshal(b, protocol.PerspectiveServer); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.InitialMaxPathID != nil {
		t.Fatalf("InitialMaxPathID = %d, want nil (parameter absent)", *out.InitialMaxPathID)
	}
}

func TestInitialMaxPathIDRejectsOverU32(t *testing.T) {
	// transport_parameters.rs:542 decodes via PathId::get, which (paths.rs:38)
	// errors on values > u32::MAX. Build a parameter whose value varint is
	// u32::MAX+1 (0x1_0000_0000), an 8-byte varint, len 0x08.
	b := []byte{0x3e, 0x08, 0xc0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	if _, err := decodeBareTP(t, b); err == nil {
		t.Fatalf("expected error for path id > u32::MAX")
	}
}

func TestInitialMaxPathIDRejectsBadLength(t *testing.T) {
	// transport_parameters.rs:543-545: len must equal value.size(). Here the
	// value 0x05 is a 1-byte varint but the declared length is 0x02.
	b := []byte{0x3e, 0x02, 0x05, 0x00}
	if _, err := decodeBareTP(t, b); err == nil {
		t.Fatalf("expected error for declared length != varint size")
	}
}

func TestInitialMaxPathIDRejectsDuplicate(t *testing.T) {
	// transport_parameters.rs:538-540: a second initial_max_path_id is malformed.
	b := []byte{0x3e, 0x01, 0x05, 0x3e, 0x01, 0x06}
	if _, err := decodeBareTP(t, b); err == nil {
		t.Fatalf("expected error for duplicate initial_max_path_id")
	}
}

// TestMultipathParserGating asserts the negotiation gate end-to-end at the
// parser: a multipath frame type is admitted by ParseType only when
// supportsMultipath is set (set after both peers advertise initial_max_path_id)
// and only at the 1-RTT encryption level.
func TestMultipathParserGating(t *testing.T) {
	// PATH_ABANDON type 0x3e75 -> 2-byte varint 0x7e 0x75.
	frame := []byte{0x7e, 0x75}

	// Default parser (single-path): multipath frame is unknown.
	def := NewFrameParser(false, false, false, false)
	if _, _, err := def.ParseType(frame, protocol.Encryption1RTT); err == nil {
		t.Fatalf("single-path parser admitted a multipath frame type")
	}

	// Multipath negotiated: admitted at 1-RTT.
	mp := NewFrameParser(false, false, false, true)
	ft, _, err := mp.ParseType(frame, protocol.Encryption1RTT)
	if err != nil {
		t.Fatalf("multipath parser rejected PATH_ABANDON at 1-RTT: %v", err)
	}
	if ft != FrameTypePathAbandon {
		t.Fatalf("ParseType = %#x, want PATH_ABANDON %#x", uint64(ft), uint64(FrameTypePathAbandon))
	}

	// Multipath negotiated but wrong encryption level: rejected (frame.rs:528-535,
	// multipath frames are 1-RTT only).
	if _, _, err := mp.ParseType(frame, protocol.EncryptionHandshake); err == nil {
		t.Fatalf("multipath frame admitted outside 1-RTT")
	}

	// SetSupportsMultipath toggles the gate at runtime, as the connection does
	// once the peer's transport parameters are processed.
	toggled := NewFrameParser(false, false, false, false)
	if _, _, err := toggled.ParseType(frame, protocol.Encryption1RTT); err == nil {
		t.Fatalf("toggled parser admitted multipath frame before SetSupportsMultipath(true)")
	}
	toggled.SetSupportsMultipath(true)
	if _, _, err := toggled.ParseType(frame, protocol.Encryption1RTT); err != nil {
		t.Fatalf("toggled parser rejected multipath frame after SetSupportsMultipath(true): %v", err)
	}
}

// TestInitialMaxPathIDLenMatchesVarint guards that the declared length the
// encoder writes is exactly the PathId varint size for representative values,
// matching the Rust val.size() (paths.rs:57-59).
func TestInitialMaxPathIDLenMatchesVarint(t *testing.T) {
	for _, pid := range []protocol.PathID{0, 1, 63, 64, 16383, 16384, protocol.PathIDMax} {
		b := (&TransportParameters{}).marshalVarintParam(nil, initialMaxPathIDParameterID, uint64(pid))
		// b = [id=0x3e][len][value...]; len must equal quicvarint.Len(pid).
		if b[0] != 0x3e {
			t.Fatalf("pid %d: id byte = %#x, want 0x3e", pid, b[0])
		}
		declaredLen := int(b[1])
		if want := quicvarint.Len(uint64(pid)); declaredLen != want {
			t.Fatalf("pid %d: declared len %d, want %d", pid, declaredLen, want)
		}
		if got := len(b) - 2; got != declaredLen {
			t.Fatalf("pid %d: actual value bytes %d, declared %d", pid, got, declaredLen)
		}
	}
}
