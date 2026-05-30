package wire

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// A RetireConnectionIDFrame is a RETIRE_CONNECTION_ID frame.
//
// When PathID is non-nil the frame is the QUIC multipath path-qualified variant
// PATH_RETIRE_CONNECTION_ID (0x3e79): the path id is encoded immediately after
// the frame type, before the sequence number (frame.rs:811-819, RetireConnectionId
// encode with Option<PathId>). A nil PathID encodes a plain
// RETIRE_CONNECTION_ID (0x19) byte-for-byte as before.
type RetireConnectionIDFrame struct {
	PathID         *protocol.PathID
	SequenceNumber uint64
}

// parseRetireConnectionIDFrame parses a RETIRE_CONNECTION_ID frame. readPath
// selects the path-qualified PATH_RETIRE_CONNECTION_ID variant, in which a path
// id varint precedes the sequence number (frame.rs:785-793,
// RetireConnectionId::decode).
func parseRetireConnectionIDFrame(b []byte, readPath bool, _ protocol.Version) (*RetireConnectionIDFrame, int, error) {
	startLen := len(b)
	var pathID *protocol.PathID
	if readPath {
		pid, l, err := parsePathID(b)
		if err != nil {
			return nil, 0, err
		}
		b = b[l:]
		pathID = &pid
	}
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return &RetireConnectionIDFrame{PathID: pathID, SequenceNumber: seq}, startLen - len(b), nil
}

func (f *RetireConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.PathID != nil {
		b = quicvarint.Append(b, uint64(FrameTypePathRetireConnectionID))
		b = quicvarint.Append(b, uint64(*f.PathID))
	} else {
		b = append(b, byte(FrameTypeRetireConnectionID))
	}
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *RetireConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	typeLen := protocol.ByteCount(1)
	if f.PathID != nil {
		typeLen = protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathRetireConnectionID)) + quicvarint.Len(uint64(*f.PathID)))
	}
	return typeLen + protocol.ByteCount(quicvarint.Len(f.SequenceNumber))
}
