package wire

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// A PathAckFrame is the QUIC multipath PATH_ACK / PATH_ACK_ECN frame
// (draft-ietf-quic-multipath). It is an ACK frame qualified by a path id: the
// wire layout is the frame type, then the path id, then a standard ACK frame
// body (largest, delay, ack ranges, and optional ECN counts).
//
// The ECN counts are present iff the frame type is PATH_ACK_ECN (0x3f); a plain
// PATH_ACK (0x3e) carries no ECN counts. This mirrors the base ACK/ACK_ECN
// distinction. See internal/qng/n0ext/reference/frame.rs PathAck /
// PathAckEncoder (lines 992-1118): the body is byte-identical to a base ACK
// frame, with the path id inserted immediately after the frame type.
type PathAckFrame struct {
	PathID protocol.PathID
	Ack    AckFrame
}

// parsePathAckFrame parses a PATH_ACK or PATH_ACK_ECN frame. ecn selects which:
// the caller determines it from the frame type (0x3e vs 0x3f), exactly as the
// base ACK parser keys ECN off FrameTypeAckECN.
func parsePathAckFrame(b []byte, ecn bool, ackDelayExponent uint8, v protocol.Version) (*PathAckFrame, int, error) {
	startLen := len(b)
	pid, l, err := parsePathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]

	// The remainder is a standard ACK frame body. parseAckFrame keys ECN off the
	// frame type it is handed, so pass the matching base ACK type.
	f := &PathAckFrame{PathID: pid}
	typ := FrameTypeAck
	if ecn {
		typ = FrameTypeAckECN
	}
	n, err := parseAckFrame(&f.Ack, b, typ, ackDelayExponent, v)
	if err != nil {
		return nil, 0, err
	}
	b = b[n:]
	return f, startLen - len(b), nil
}

// hasECN reports whether this frame carries ECN counts, which selects the
// PATH_ACK_ECN frame type. Matches AckFrame.Append's hasECN check.
func (f *PathAckFrame) hasECN() bool {
	return f.Ack.ECT0 > 0 || f.Ack.ECT1 > 0 || f.Ack.ECNCE > 0
}

func (f *PathAckFrame) Append(b []byte, v protocol.Version) ([]byte, error) {
	if f.hasECN() {
		b = quicvarint.Append(b, uint64(FrameTypePathAckECN))
	} else {
		b = quicvarint.Append(b, uint64(FrameTypePathAck))
	}
	b = quicvarint.Append(b, uint64(f.PathID))

	// The ACK body matches AckFrame.Append exactly, minus the leading frame-type
	// byte (already written above as the multipath type).
	b = quicvarint.Append(b, uint64(f.Ack.LargestAcked()))
	b = quicvarint.Append(b, encodeAckDelay(f.Ack.DelayTime))

	numRanges := min(len(f.Ack.AckRanges), protocol.MaxNumAckRanges)
	b = quicvarint.Append(b, uint64(numRanges-1))

	_, firstRange := f.Ack.encodeAckRange(0)
	b = quicvarint.Append(b, firstRange)

	for i := 1; i < numRanges; i++ {
		gap, length := f.Ack.encodeAckRange(i)
		b = quicvarint.Append(b, gap)
		b = quicvarint.Append(b, length)
	}

	if f.hasECN() {
		b = quicvarint.Append(b, f.Ack.ECT0)
		b = quicvarint.Append(b, f.Ack.ECT1)
		b = quicvarint.Append(b, f.Ack.ECNCE)
	}
	return b, nil
}

func (f *PathAckFrame) Length(v protocol.Version) protocol.ByteCount {
	// AckFrame.Length counts a single leading type byte; the multipath type id
	// is multi-byte, so swap in its varint length.
	typ := FrameTypePathAck
	if f.hasECN() {
		typ = FrameTypePathAckECN
	}
	return f.Ack.Length(v) - 1 +
		protocol.ByteCount(quicvarint.Len(uint64(typ))+quicvarint.Len(uint64(f.PathID)))
}
