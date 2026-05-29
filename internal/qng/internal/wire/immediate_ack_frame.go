package wire

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// An ImmediateAckFrame is an IMMEDIATE_ACK frame
type ImmediateAckFrame struct{}

func (f *ImmediateAckFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return quicvarint.Append(b, uint64(FrameTypeImmediateAck)), nil
}

// Length of a written frame
func (f *ImmediateAckFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeImmediateAck)))
}
