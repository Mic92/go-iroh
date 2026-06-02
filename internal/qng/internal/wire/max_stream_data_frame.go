package wire

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// A MaxStreamDataFrame is a MAX_STREAM_DATA frame
type MaxStreamDataFrame struct {
	StreamID          protocol.StreamID
	MaximumStreamData protocol.ByteCount
}

func parseMaxStreamDataFrame(b []byte, _ protocol.Version) (*MaxStreamDataFrame, int, error) {
	streamID, maximumStreamData, l, err := ParseMaxStreamDataFrame(b)
	if err != nil {
		return nil, 0, err
	}
	return &MaxStreamDataFrame{
		StreamID:          streamID,
		MaximumStreamData: maximumStreamData,
	}, l, nil
}

// ParseMaxStreamDataFrame parses the payload of a MAX_STREAM_DATA frame.
func ParseMaxStreamDataFrame(b []byte) (protocol.StreamID, protocol.ByteCount, int, error) {
	startLen := len(b)
	sid, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	offset, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	return protocol.StreamID(sid), protocol.ByteCount(offset), startLen - len(b), nil
}

func (f *MaxStreamDataFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, byte(FrameTypeMaxStreamData))
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.MaximumStreamData))
	return b, nil
}

// Length of a written frame
func (f *MaxStreamDataFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.MaximumStreamData)))
}
