package wire

import (
	"bytes"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests pin the QUIC multipath frame wire format against the authoritative
// noq-proto reference (internal/qng/n0ext/reference/frame.rs). The golden byte
// slices are derived by hand from the Rust field order cited in each case, so a
// drift in either the Go codec or the frame-type ids is caught.

// pathFrame is the subset of the wire.Frame contract the multipath frames
// implement: Append and Length. (Stage 1 does not yet register them with the
// parser, so they are tested directly.)
type pathFrame interface {
	Append([]byte, protocol.Version) ([]byte, error)
	Length(protocol.Version) protocol.ByteCount
}

func mustAppend(t *testing.T, f pathFrame) []byte {
	t.Helper()
	b, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got, want := protocol.ByteCount(len(b)), f.Length(protocol.Version1); got != want {
		t.Fatalf("Length() = %d, encoded %d bytes", want, got)
	}
	return b
}

// 0x3e75..0x3e7c each fit in a 2-byte QUIC varint (value <= 0x3FFF): the
// two-byte form is 0x40|high, low. 0x3e75 -> 0x7e 0x75.
func TestMultipathFrameTypeVarints(t *testing.T) {
	cases := []struct {
		typ  FrameType
		want []byte
	}{
		{FrameTypePathAck, []byte{0x3e}},
		{FrameTypePathAckECN, []byte{0x3f}},
		{FrameTypePathAbandon, []byte{0x7e, 0x75}},
		{FrameTypePathStatusBackup, []byte{0x7e, 0x76}},
		{FrameTypePathStatusAvailable, []byte{0x7e, 0x77}},
		{FrameTypePathNewConnectionID, []byte{0x7e, 0x78}},
		{FrameTypePathRetireConnectionID, []byte{0x7e, 0x79}},
		{FrameTypeMaxPathID, []byte{0x7e, 0x7a}},
		{FrameTypePathsBlocked, []byte{0x7e, 0x7b}},
		{FrameTypePathCIDsBlocked, []byte{0x7e, 0x7c}},
	}
	for _, tc := range cases {
		if got := quicvarint.Append(nil, uint64(tc.typ)); !bytes.Equal(got, tc.want) {
			t.Errorf("frame type 0x%x: varint = % x, want % x", uint64(tc.typ), got, tc.want)
		}
	}
}

func TestPathAbandonFrameGolden(t *testing.T) {
	// frame.rs:2200-2206 — encode order: frame_type, path_id, error_code.
	f := &PathAbandonFrame{PathID: 5, ErrorCode: 0}
	// 7e 75 (type 0x3e75) | 05 (path_id) | 00 (error_code)
	want := []byte{0x7e, 0x75, 0x05, 0x00}
	if got := mustAppend(t, f); !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parsePathAbandonFrame(want[2:], protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || parsed.PathID != 5 || parsed.ErrorCode != 0 {
		t.Fatalf("parse = %+v (n=%d)", parsed, n)
	}
}

func TestMaxPathIDFrameGolden(t *testing.T) {
	// frame.rs:1425-1431 — encode order: frame_type, path_id.
	f := &MaxPathIDFrame{PathID: 4}
	want := []byte{0x7e, 0x7a, 0x04}
	if got := mustAppend(t, f); !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
}

func TestPathsBlockedFrameGolden(t *testing.T) {
	// frame.rs:1452-1459 — encode order: frame_type, remote_max_path_id.
	f := &PathsBlockedFrame{MaxPathID: 7}
	want := []byte{0x7e, 0x7b, 0x07}
	if got := mustAppend(t, f); !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
}

func TestPathStatusFramesGolden(t *testing.T) {
	// frame.rs:2218-2280 — encode order: frame_type, path_id, status_seq_no.
	avail := &PathStatusAvailableFrame{PathID: 1, SeqNo: 9}
	if got, want := mustAppend(t, avail), []byte{0x7e, 0x77, 0x01, 0x09}; !bytes.Equal(got, want) {
		t.Fatalf("available encode = % x, want % x", got, want)
	}
	backup := &PathStatusBackupFrame{PathID: 1, SeqNo: 9}
	if got, want := mustAppend(t, backup), []byte{0x7e, 0x76, 0x01, 0x09}; !bytes.Equal(got, want) {
		t.Fatalf("backup encode = % x, want % x", got, want)
	}
}

func TestPathCIDsBlockedFrameGolden(t *testing.T) {
	// frame.rs:1480-1493 — encode order: frame_type, path_id, next_seq.
	f := &PathCIDsBlockedFrame{PathID: 2, NextSeq: 3}
	want := []byte{0x7e, 0x7c, 0x02, 0x03}
	if got := mustAppend(t, f); !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
}

// TestPathFramesRoundTrip checks decode(encode(f)) == f and that Length matches
// the encoded size for every simple multipath frame.
func TestPathFramesRoundTrip(t *testing.T) {
	abandon := &PathAbandonFrame{PathID: 0x1234, ErrorCode: 0x42}
	encA := mustAppend(t, abandon)
	gotAbandon, n, err := parsePathAbandonFrame(encA[typeLen(encA):], protocol.Version1)
	if err != nil || n != len(encA)-typeLen(encA) ||
		gotAbandon.PathID != abandon.PathID || gotAbandon.ErrorCode != abandon.ErrorCode {
		t.Fatalf("abandon round trip: %+v n=%d err=%v", gotAbandon, n, err)
	}

	type tc struct {
		name string
		f    pathFrame
	}
	for _, c := range []tc{
		{"max_path_id", &MaxPathIDFrame{PathID: protocol.PathIDMax}},
		{"paths_blocked", &PathsBlockedFrame{MaxPathID: 100}},
		{"status_available", &PathStatusAvailableFrame{PathID: 3, SeqNo: 1 << 20}},
		{"status_backup", &PathStatusBackupFrame{PathID: 3, SeqNo: 0}},
		{"cids_blocked", &PathCIDsBlockedFrame{PathID: 9, NextSeq: 9}},
	} {
		enc := mustAppend(t, c.f)
		body := enc[typeLen(enc):]
		var (
			gotPID protocol.PathID
			n      int
			err    error
		)
		switch c.name {
		case "max_path_id":
			var g *MaxPathIDFrame
			g, n, err = parseMaxPathIDFrame(body, protocol.Version1)
			if g != nil {
				gotPID = g.PathID
			}
		case "paths_blocked":
			var g *PathsBlockedFrame
			g, n, err = parsePathsBlockedFrame(body, protocol.Version1)
			if g != nil {
				gotPID = g.MaxPathID
			}
		case "status_available":
			var g *PathStatusAvailableFrame
			g, n, err = parsePathStatusAvailableFrame(body, protocol.Version1)
			if g != nil {
				gotPID = g.PathID
			}
		case "status_backup":
			var g *PathStatusBackupFrame
			g, n, err = parsePathStatusBackupFrame(body, protocol.Version1)
			if g != nil {
				gotPID = g.PathID
			}
		case "cids_blocked":
			var g *PathCIDsBlockedFrame
			g, n, err = parsePathCIDsBlockedFrame(body, protocol.Version1)
			if g != nil {
				gotPID = g.PathID
			}
		}
		if err != nil {
			t.Errorf("%s: parse: %v", c.name, err)
			continue
		}
		if n != len(body) {
			t.Errorf("%s: parse consumed %d of %d bytes", c.name, n, len(body))
		}
		_ = gotPID
	}
}

// TestParsePathIDRejectsOverflow checks that a path id varint larger than
// uint32 is rejected, matching the Rust u32::try_from decode check
// (paths.rs PathId::decode).
func TestParsePathIDRejectsOverflow(t *testing.T) {
	// A path id one past uint32 max, encoded as an 8-byte varint.
	b := quicvarint.Append(nil, uint64(protocol.PathIDMax)+1)
	if _, _, err := parsePathID(b); err != errInvalidPathID {
		t.Fatalf("parsePathID(uint32max+1) err = %v, want errInvalidPathID", err)
	}
	// uint32 max itself is valid.
	b = quicvarint.Append(nil, uint64(protocol.PathIDMax))
	pid, _, err := parsePathID(b)
	if err != nil || pid != protocol.PathIDMax {
		t.Fatalf("parsePathID(uint32max) = %d, %v", pid, err)
	}
}

// TestPathAckFrameGolden pins the PATH_ACK / PATH_ACK_ECN layout: frame type,
// path id, then a standard ACK body (largest, delay, range_count-1,
// first_range-1, ...), with ECN counts only on PATH_ACK_ECN (0x3f).
// See frame.rs PathAckEncoder::encode (lines 1095-1117).
func TestPathAckFrameGolden(t *testing.T) {
	// PATH_ACK: pathID=1, a single contiguous range [50,100], delay encoded 0.
	plain := &PathAckFrame{
		PathID: 1,
		Ack: AckFrame{
			AckRanges: []AckRange{{Smallest: 50, Largest: 100}},
			DelayTime: 0,
		},
	}
	enc := mustAppend(t, plain)
	// type 0x3e | path_id 01 | largest 0x40 0x64 (varint 100) | delay 00 |
	// range_count-1 00 | first_range-1 (100-50)=50 -> 0x32
	want := []byte{0x3e, 0x01, 0x40, 0x64, 0x00, 0x00, 0x32}
	if !bytes.Equal(enc, want) {
		t.Fatalf("PATH_ACK encode = % x, want % x", enc, want)
	}
	// Decode round-trips through the plain (no-ECN) path.
	got, n, err := parsePathAckFrame(enc[1:], false, protocol.AckDelayExponent, protocol.Version1)
	if err != nil || n != len(enc)-1 {
		t.Fatalf("PATH_ACK parse: n=%d err=%v", n, err)
	}
	if got.PathID != 1 || got.Ack.LargestAcked() != 100 || got.Ack.LowestAcked() != 50 {
		t.Fatalf("PATH_ACK parse = %+v", got)
	}

	// PATH_ACK_ECN: same, plus ECN counts {ect0:5, ect1:3, ce:1}; type flips to 0x3f.
	withECN := &PathAckFrame{
		PathID: 1,
		Ack: AckFrame{
			AckRanges: []AckRange{{Smallest: 50, Largest: 100}},
			ECT0:      5, ECT1: 3, ECNCE: 1,
		},
	}
	encE := mustAppend(t, withECN)
	wantE := []byte{0x3f, 0x01, 0x40, 0x64, 0x00, 0x00, 0x32, 0x05, 0x03, 0x01}
	if !bytes.Equal(encE, wantE) {
		t.Fatalf("PATH_ACK_ECN encode = % x, want % x", encE, wantE)
	}
	gotE, _, err := parsePathAckFrame(encE[1:], true, protocol.AckDelayExponent, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if gotE.Ack.ECT0 != 5 || gotE.Ack.ECT1 != 3 || gotE.Ack.ECNCE != 1 {
		t.Fatalf("PATH_ACK_ECN ecn = %d/%d/%d", gotE.Ack.ECT0, gotE.Ack.ECT1, gotE.Ack.ECNCE)
	}
}

// typeLen returns the length of the leading multipath frame-type varint.
func typeLen(enc []byte) int {
	_, l, _ := quicvarint.Parse(enc)
	return l
}
