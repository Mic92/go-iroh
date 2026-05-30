package wire

import (
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// A NewConnectionIDFrame is a NEW_CONNECTION_ID frame.
//
// When PathID is non-nil the frame is the QUIC multipath path-qualified variant
// PATH_NEW_CONNECTION_ID (0x3e78): the path id is encoded immediately after the
// frame type, before the sequence number (frame.rs:2015-2030, NewConnectionId
// encode with Option<PathId>). A nil PathID encodes a plain NEW_CONNECTION_ID
// (0x18) byte-for-byte as before.
type NewConnectionIDFrame struct {
	PathID              *protocol.PathID
	SequenceNumber      uint64
	RetirePriorTo       uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

// parseNewConnectionIDFrame parses a NEW_CONNECTION_ID frame. readPath selects
// the path-qualified PATH_NEW_CONNECTION_ID variant, in which a path id varint
// precedes the sequence number (frame.rs:1973-2004, NewConnectionId::read).
func parseNewConnectionIDFrame(b []byte, readPath bool, _ protocol.Version) (*NewConnectionIDFrame, int, error) {
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
	ret, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if ret > seq {
		//nolint:staticcheck // SA1021: Retire Prior To is the name of the field
		return nil, 0, fmt.Errorf("Retire Prior To value (%d) larger than Sequence Number (%d)", ret, seq)
	}
	if len(b) == 0 {
		return nil, 0, io.EOF
	}
	connIDLen := int(b[0])
	b = b[1:]
	if connIDLen == 0 {
		return nil, 0, errors.New("invalid zero-length connection ID")
	}
	if connIDLen > protocol.MaxConnIDLen {
		return nil, 0, protocol.ErrInvalidConnectionIDLen
	}
	if len(b) < connIDLen {
		return nil, 0, io.EOF
	}
	frame := &NewConnectionIDFrame{
		PathID:         pathID,
		SequenceNumber: seq,
		RetirePriorTo:  ret,
		ConnectionID:   protocol.ParseConnectionID(b[:connIDLen]),
	}
	b = b[connIDLen:]
	if len(b) < len(frame.StatelessResetToken) {
		return nil, 0, io.EOF
	}
	copy(frame.StatelessResetToken[:], b)
	return frame, startLen - len(b) + len(frame.StatelessResetToken), nil
}

func (f *NewConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.PathID != nil {
		b = quicvarint.Append(b, uint64(FrameTypePathNewConnectionID))
		b = quicvarint.Append(b, uint64(*f.PathID))
	} else {
		b = append(b, byte(FrameTypeNewConnectionID))
	}
	b = quicvarint.Append(b, f.SequenceNumber)
	b = quicvarint.Append(b, f.RetirePriorTo)
	connIDLen := f.ConnectionID.Len()
	if connIDLen > protocol.MaxConnIDLen {
		return nil, fmt.Errorf("invalid connection ID length: %d", connIDLen)
	}
	b = append(b, uint8(connIDLen))
	b = append(b, f.ConnectionID.Bytes()...)
	b = append(b, f.StatelessResetToken[:]...)
	return b, nil
}

// Length of a written frame
func (f *NewConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	typeLen := protocol.ByteCount(1)
	if f.PathID != nil {
		typeLen = protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathNewConnectionID)) + quicvarint.Len(uint64(*f.PathID)))
	}
	return typeLen + protocol.ByteCount(quicvarint.Len(f.SequenceNumber)+quicvarint.Len(f.RetirePriorTo)+1 /* connection ID length */ +f.ConnectionID.Len()) + 16
}
