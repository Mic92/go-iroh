package qlog

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/qlogwriter/jsontext"
)

func TestExtensionFrameEncoding(t *testing.T) {
	pathID := protocol.PathID(6)
	cid := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
	resetToken := protocol.StatelessResetToken{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	tests := []struct {
		name      string
		frame     any
		frameType string
		fields    map[string]any
	}{
		{
			name:      "path_ack",
			frame:     &wire.PathAckFrame{PathID: 1, Ack: wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 10, Largest: 20}}, ECT0: 1}},
			frameType: "path_ack",
			fields:    map[string]any{"path_id": float64(1), "ect0": float64(1)},
		},
		{
			name:      "path_abandon",
			frame:     &wire.PathAbandonFrame{PathID: 4, ErrorCode: 9},
			frameType: "path_abandon",
			fields:    map[string]any{"path_id": float64(4), "error_code": float64(9)},
		},
		{
			name:      "path_status_available",
			frame:     &wire.PathStatusAvailableFrame{PathID: 2, SeqNo: 3},
			frameType: "path_status_available",
			fields:    map[string]any{"path_id": float64(2), "sequence_number": float64(3)},
		},
		{
			name:      "path_status_backup",
			frame:     &wire.PathStatusBackupFrame{PathID: 2, SeqNo: 4},
			frameType: "path_status_backup",
			fields:    map[string]any{"path_id": float64(2), "sequence_number": float64(4)},
		},
		{
			name:      "path_new_connection_id",
			frame:     &wire.NewConnectionIDFrame{PathID: &pathID, SequenceNumber: 1, ConnectionID: cid, StatelessResetToken: resetToken},
			frameType: "path_new_connection_id",
			fields:    map[string]any{"path_id": float64(6), "sequence_number": float64(1), "connection_id": "01020304"},
		},
		{
			name:      "path_retire_connection_id",
			frame:     &wire.RetireConnectionIDFrame{PathID: &pathID, SequenceNumber: 2},
			frameType: "path_retire_connection_id",
			fields:    map[string]any{"path_id": float64(6), "sequence_number": float64(2)},
		},
		{
			name:      "max_path_id",
			frame:     &wire.MaxPathIDFrame{PathID: 11},
			frameType: "max_path_id",
			fields:    map[string]any{"path_id": float64(11)},
		},
		{
			name:      "paths_blocked",
			frame:     &wire.PathsBlockedFrame{MaxPathID: 12},
			frameType: "paths_blocked",
			fields:    map[string]any{"max_path_id": float64(12)},
		},
		{
			name:      "path_cids_blocked",
			frame:     &wire.PathCIDsBlockedFrame{PathID: 1, NextSeq: 5},
			frameType: "path_cids_blocked",
			fields:    map[string]any{"path_id": float64(1), "next_sequence_number": float64(5)},
		},
		{
			name:      "observed_address",
			frame:     &wire.ObservedAddrFrame{SeqNo: 7, Addr: netip.MustParseAddr("203.0.113.9"), Port: 4433},
			frameType: "observed_address",
			fields:    map[string]any{"sequence_number": float64(7), "ip": "203.0.113.9", "port": float64(4433)},
		},
		{
			name:      "add_address",
			frame:     &wire.AddAddressFrame{SeqNo: 8, Addr: netip.MustParseAddr("192.0.2.1"), Port: 1000},
			frameType: "add_address",
			fields:    map[string]any{"sequence_number": float64(8), "ip": "192.0.2.1", "port": float64(1000)},
		},
		{
			name:      "remove_address",
			frame:     &wire.RemoveAddressFrame{SeqNo: 8},
			frameType: "remove_address",
			fields:    map[string]any{"sequence_number": float64(8)},
		},
		{
			name:      "reach_out",
			frame:     &wire.ReachOutFrame{Round: 9, Addr: netip.MustParseAddr("198.51.100.7"), Port: 4434},
			frameType: "reach_out",
			fields:    map[string]any{"round": float64(9), "ip": "198.51.100.7", "port": float64(4434)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeFrameMap(t, tt.frame)
			if got["frame_type"] != tt.frameType {
				t.Fatalf("frame_type = %v, want %q", got["frame_type"], tt.frameType)
			}
			for k, v := range tt.fields {
				if got[k] != v {
					t.Fatalf("%s = %v, want %v", k, got[k], v)
				}
			}
			if tt.name == "path_ack" {
				wantRanges := []any{[]any{float64(10), float64(20)}}
				if !reflect.DeepEqual(got["acked_ranges"], wantRanges) {
					t.Fatalf("acked_ranges = %v, want %v", got["acked_ranges"], wantRanges)
				}
			}
		})
	}
}

func TestPacketSentEncodesExtensionFrames(t *testing.T) {
	got := encodePacketSentMap(t, PacketSent{
		Header: PacketHeader{PacketType: PacketType1RTT, PacketNumber: 1},
		Raw:    RawInfo{Length: 42, PayloadLength: 20},
		Frames: []Frame{
			{Frame: &wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 1000}},
			{Frame: &wire.ObservedAddrFrame{SeqNo: 2, Addr: netip.MustParseAddr("203.0.113.9"), Port: 4433}},
		},
	})

	frames, ok := got["frames"].([]any)
	if !ok || len(frames) != 2 {
		t.Fatalf("frames = %v, want two frame objects", got["frames"])
	}
	add, ok := frames[0].(map[string]any)
	if !ok {
		t.Fatalf("first frame = %T, want object", frames[0])
	}
	if add["frame_type"] != "add_address" {
		t.Fatalf("first frame_type = %v, want add_address", add["frame_type"])
	}
	observed, ok := frames[1].(map[string]any)
	if !ok {
		t.Fatalf("second frame = %T, want object", frames[1])
	}
	if observed["frame_type"] != "observed_address" {
		t.Fatalf("second frame_type = %v, want observed_address", observed["frame_type"])
	}
}

func encodeFrameMap(t *testing.T, frame any) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := (Frame{Frame: frame}).Encode(jsontext.NewEncoder(&buf)); err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return decodeObject(t, buf.Bytes())
}

func encodePacketSentMap(t *testing.T, ev PacketSent) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := ev.Encode(jsontext.NewEncoder(&buf), time.Time{}); err != nil {
		t.Fatalf("encode packet sent: %v", err)
	}
	return decodeObject(t, buf.Bytes())
}

func decodeObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode %q: %v", data, err)
	}
	return m
}
