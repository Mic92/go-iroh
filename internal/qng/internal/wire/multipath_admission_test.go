package wire

import (
	"bytes"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests cover Stage 2 of the QUIC multipath port: frame admission gated on
// supportsMultipath, the 1-RTT-only enforcement, and the path-qualified
// connection-id frames. The wire layouts are pinned against the authoritative
// noq-proto reference (internal/qng/n0ext/reference/frame.rs).

func ptrPathID(p protocol.PathID) *protocol.PathID { return &p }

// TestPathNewConnectionIDFrameGolden pins PATH_NEW_CONNECTION_ID (0x3e78): the
// path id is encoded right after the frame type, before the sequence number,
// then the rest is a normal NEW_CONNECTION_ID body (frame.rs:2015-2030,
// NewConnectionId::encode with Option<PathId>).
func TestPathNewConnectionIDFrameGolden(t *testing.T) {
	var token protocol.StatelessResetToken
	for i := range token {
		token[i] = byte(0xf0 + i)
	}
	f := &NewConnectionIDFrame{
		PathID:              ptrPathID(2),
		SequenceNumber:      1,
		RetirePriorTo:       0,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xaa, 0xbb, 0xcc, 0xdd}),
		StatelessResetToken: token,
	}
	// 7e 78 (type 0x3e78) | 02 (path_id) | 01 (seq) | 00 (retire_prior_to) |
	// 04 (cid len) | aa bb cc dd (cid) | 16-byte reset token.
	want := []byte{0x7e, 0x78, 0x02, 0x01, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd}
	want = append(want, token[:]...)

	got, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	if l := f.Length(protocol.Version1); int(l) != len(got) {
		t.Fatalf("Length() = %d, encoded %d bytes", l, len(got))
	}

	// Decode reads the path id because readPath is true.
	parsed, n, err := parseNewConnectionIDFrame(got[2:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(got)-2 {
		t.Fatalf("parse consumed %d, want %d", n, len(got)-2)
	}
	if parsed.PathID == nil || *parsed.PathID != 2 || parsed.SequenceNumber != 1 ||
		parsed.RetirePriorTo != 0 || parsed.ConnectionID != f.ConnectionID || parsed.StatelessResetToken != token {
		t.Fatalf("parse = %+v", parsed)
	}
}

// TestPathRetireConnectionIDFrameGolden pins PATH_RETIRE_CONNECTION_ID (0x3e79):
// frame type, path id, then sequence (frame.rs:817-826,
// RetireConnectionId::encode with Option<PathId>).
func TestPathRetireConnectionIDFrameGolden(t *testing.T) {
	f := &RetireConnectionIDFrame{PathID: ptrPathID(3), SequenceNumber: 7}
	// 7e 79 (type 0x3e79) | 03 (path_id) | 07 (seq)
	want := []byte{0x7e, 0x79, 0x03, 0x07}
	got, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	if l := f.Length(protocol.Version1); int(l) != len(got) {
		t.Fatalf("Length() = %d, encoded %d bytes", l, len(got))
	}

	parsed, n, err := parseRetireConnectionIDFrame(got[2:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(got)-2 {
		t.Fatalf("parse consumed %d, want %d", n, len(got)-2)
	}
	if parsed.PathID == nil || *parsed.PathID != 3 || parsed.SequenceNumber != 7 {
		t.Fatalf("parse = %+v", parsed)
	}
}

// TestConnectionIDFramesUnchangedWithoutPathID checks the non-multipath path is
// byte-identical: a nil PathID encodes the plain RFC 9000 NEW_CONNECTION_ID
// (0x18) / RETIRE_CONNECTION_ID (0x19) exactly as before Stage 2.
func TestConnectionIDFramesUnchangedWithoutPathID(t *testing.T) {
	var token protocol.StatelessResetToken
	nc := &NewConnectionIDFrame{
		SequenceNumber:      9,
		RetirePriorTo:       2,
		ConnectionID:        protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03}),
		StatelessResetToken: token,
	}
	got, err := nc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != byte(FrameTypeNewConnectionID) {
		t.Fatalf("nil-PathID NEW_CONNECTION_ID type = %#x, want %#x", got[0], byte(FrameTypeNewConnectionID))
	}
	if int(nc.Length(protocol.Version1)) != len(got) {
		t.Fatalf("Length() = %d, encoded %d", nc.Length(protocol.Version1), len(got))
	}
	parsed, _, err := parseNewConnectionIDFrame(got[1:], false, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PathID != nil {
		t.Fatalf("non-multipath NEW_CONNECTION_ID parsed PathID = %v, want nil", *parsed.PathID)
	}

	rc := &RetireConnectionIDFrame{SequenceNumber: 5}
	got, err = rc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{byte(FrameTypeRetireConnectionID), 0x05}) {
		t.Fatalf("nil-PathID RETIRE_CONNECTION_ID = % x", got)
	}
	rparsed, _, err := parseRetireConnectionIDFrame(got[1:], false, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if rparsed.PathID != nil {
		t.Fatalf("non-multipath RETIRE_CONNECTION_ID parsed PathID = %v, want nil", *rparsed.PathID)
	}
}

// allMultipathFrameTypes is the full set of QUIC multipath frame types
// (frame.rs:104-124).
var allMultipathFrameTypes = []FrameType{
	FrameTypePathAck,
	FrameTypePathAckECN,
	FrameTypePathAbandon,
	FrameTypePathStatusBackup,
	FrameTypePathStatusAvailable,
	FrameTypePathNewConnectionID,
	FrameTypePathRetireConnectionID,
	FrameTypeMaxPathID,
	FrameTypePathsBlocked,
	FrameTypePathCIDsBlocked,
}

// TestMultipathFrameAdmissionGated proves the gate: with supportsMultipath=false
// every multipath frame type is rejected by ParseType as an unknown frame type,
// and with supportsMultipath=true every type is admitted at 1-RTT.
func TestMultipathFrameAdmissionGated(t *testing.T) {
	off := NewFrameParser(false, false, false, false)
	on := NewFrameParser(false, false, false, true)

	for _, ft := range allMultipathFrameTypes {
		typeBytes := quicvarint.Append(nil, uint64(ft))

		// Gate off: rejected as an unknown frame type.
		_, _, err := off.ParseType(typeBytes, protocol.Encryption1RTT)
		var transErr *qerr.TransportError
		if !errAsTransport(err, &transErr) || transErr.ErrorCode != qerr.FrameEncodingError {
			t.Errorf("type %#x gate-off: err = %v, want FrameEncodingError", uint64(ft), err)
		}

		// Gate on: admitted.
		got, _, err := on.ParseType(typeBytes, protocol.Encryption1RTT)
		if err != nil {
			t.Errorf("type %#x gate-on at 1-RTT: %v", uint64(ft), err)
			continue
		}
		if got != ft {
			t.Errorf("type %#x gate-on: ParseType = %#x", uint64(ft), uint64(got))
		}
	}
}

// TestMultipathFramesOneRTTOnly checks the draft-multipath rule that all
// multipath frames MUST only be sent in 1-RTT packets: ParseType rejects them at
// every other encryption level even when multipath is negotiated
// (frame.rs:524-535, Frame::is_1rtt).
func TestMultipathFramesOneRTTOnly(t *testing.T) {
	on := NewFrameParser(false, false, false, true)
	levels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
	}
	for _, ft := range allMultipathFrameTypes {
		typeBytes := quicvarint.Append(nil, uint64(ft))
		for _, lvl := range levels {
			_, _, err := on.ParseType(typeBytes, lvl)
			if err == nil {
				t.Errorf("type %#x admitted at %s, want rejected (1-RTT only)", uint64(ft), lvl)
			}
		}
		// 1-RTT is allowed.
		if !ft.isAllowedAtEncLevel(protocol.Encryption1RTT) {
			t.Errorf("type %#x not allowed at 1-RTT", uint64(ft))
		}
	}
}

// TestMultipathFrameParseDispatch checks that, with the gate on, a serialized
// multipath frame round-trips through ParseLessCommonFrame back to the right
// concrete type. PATH_ACK/PATH_ACK_ECN are not base ACK types, so they too land
// in ParseLessCommonFrame.
func TestMultipathFrameParseDispatch(t *testing.T) {
	on := NewFrameParser(false, false, false, true)
	on.SetAckDelayExponent(protocol.AckDelayExponent)

	encodeBody := func(t *testing.T, f interface {
		Append([]byte, protocol.Version) ([]byte, error)
	}) (FrameType, []byte) {
		t.Helper()
		b, err := f.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		ft, l, err := on.ParseType(b, protocol.Encryption1RTT)
		if err != nil {
			t.Fatalf("ParseType: %v", err)
		}
		return ft, b[l:]
	}

	type wantType struct {
		name string
		f    interface {
			Append([]byte, protocol.Version) ([]byte, error)
		}
		check func(Frame) bool
	}
	pathAck := &PathAckFrame{PathID: 1, Ack: AckFrame{AckRanges: []AckRange{{Smallest: 10, Largest: 20}}}}
	pathAckECN := &PathAckFrame{PathID: 1, Ack: AckFrame{AckRanges: []AckRange{{Smallest: 10, Largest: 20}}, ECT0: 1}}
	cases := []wantType{
		{"path_ack", pathAck, func(f Frame) bool { p, ok := f.(*PathAckFrame); return ok && p.PathID == 1 }},
		{"path_ack_ecn", pathAckECN, func(f Frame) bool { p, ok := f.(*PathAckFrame); return ok && p.Ack.ECT0 == 1 }},
		{"path_abandon", &PathAbandonFrame{PathID: 4, ErrorCode: 9}, func(f Frame) bool { p, ok := f.(*PathAbandonFrame); return ok && p.PathID == 4 && p.ErrorCode == 9 }},
		{"path_status_backup", &PathStatusBackupFrame{PathID: 2, SeqNo: 3}, func(f Frame) bool { p, ok := f.(*PathStatusBackupFrame); return ok && p.PathID == 2 }},
		{"path_status_available", &PathStatusAvailableFrame{PathID: 2, SeqNo: 3}, func(f Frame) bool { p, ok := f.(*PathStatusAvailableFrame); return ok && p.PathID == 2 }},
		{"path_new_cid", &NewConnectionIDFrame{PathID: ptrPathID(6), SequenceNumber: 1, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})}, func(f Frame) bool { p, ok := f.(*NewConnectionIDFrame); return ok && p.PathID != nil && *p.PathID == 6 }},
		{"path_retire_cid", &RetireConnectionIDFrame{PathID: ptrPathID(6), SequenceNumber: 2}, func(f Frame) bool {
			p, ok := f.(*RetireConnectionIDFrame)
			return ok && p.PathID != nil && *p.PathID == 6
		}},
		{"max_path_id", &MaxPathIDFrame{PathID: 11}, func(f Frame) bool { p, ok := f.(*MaxPathIDFrame); return ok && p.PathID == 11 }},
		{"paths_blocked", &PathsBlockedFrame{MaxPathID: 12}, func(f Frame) bool { p, ok := f.(*PathsBlockedFrame); return ok && p.MaxPathID == 12 }},
		{"path_cids_blocked", &PathCIDsBlockedFrame{PathID: 1, NextSeq: 5}, func(f Frame) bool { p, ok := f.(*PathCIDsBlockedFrame); return ok && p.NextSeq == 5 }},
	}
	for _, c := range cases {
		ft, body := encodeBody(t, c.f)
		frame, _, err := on.ParseLessCommonFrame(ft, body, protocol.Version1)
		if err != nil {
			t.Errorf("%s: ParseLessCommonFrame: %v", c.name, err)
			continue
		}
		if !c.check(frame) {
			t.Errorf("%s: parsed frame %#v failed check", c.name, frame)
		}
	}
}

// errAsTransport reports whether err is a *qerr.TransportError, storing it in
// dst. It avoids importing errors just for errors.As in a single call site.
func errAsTransport(err error, dst **qerr.TransportError) bool {
	te, ok := err.(*qerr.TransportError)
	if ok {
		*dst = te
	}
	return ok
}
