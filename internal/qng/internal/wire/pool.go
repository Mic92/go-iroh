package wire

import (
	"sync"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

var pool sync.Pool
var smallPool sync.Pool

func init() {
	pool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxPacketBufferSize),
			fromPool: true,
		}
	}
	smallPool.New = func() any {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MinStreamFrameBufferSize),
			fromPool: true,
		}
	}
}

func GetStreamFrame() *StreamFrame {
	f := pool.Get().(*StreamFrame)
	return f
}

func getSmallStreamFrame() *StreamFrame {
	f := smallPool.Get().(*StreamFrame)
	return f
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	switch protocol.ByteCount(cap(f.Data)) {
	case protocol.MaxPacketBufferSize:
		pool.Put(f)
	case protocol.MinStreamFrameBufferSize:
		smallPool.Put(f)
	default:
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
}
