package wire

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// A MaxDataFrame carries flow control information for the connection
type MaxDataFrame struct {
	MaximumData protocol.ByteCount
}

// parseMaxDataFrame parses a MAX_DATA frame
func parseMaxDataFrame(b []byte, _ protocol.Version) (*MaxDataFrame, int, error) {
	maximumData, l, err := ParseMaxDataFrame(b)
	if err != nil {
		return nil, 0, err
	}
	return &MaxDataFrame{MaximumData: maximumData}, l, nil
}

// ParseMaxDataFrame parses the payload of a MAX_DATA frame.
func ParseMaxDataFrame(b []byte) (protocol.ByteCount, int, error) {
	maximumData, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, replaceUnexpectedEOF(err)
	}
	return protocol.ByteCount(maximumData), l, nil
}

func (f *MaxDataFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, byte(FrameTypeMaxData))
	b = quicvarint.Append(b, uint64(f.MaximumData))
	return b, nil
}

// Length of a written frame
func (f *MaxDataFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.MaximumData)))
}
