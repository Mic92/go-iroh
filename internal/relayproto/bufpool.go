package relayproto

import "sync"

var (
	smallPool = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}
	largePool = sync.Pool{New: func() any { b := make([]byte, MaxPacketSize); return &b }}
)

// GetBuf returns a pooled buffer of length n (n <= MaxPacketSize).
func GetBuf(n int) *[]byte {
	var p *[]byte
	if n <= 2048 {
		p = smallPool.Get().(*[]byte)
	} else {
		p = largePool.Get().(*[]byte)
	}
	*p = (*p)[:n]
	return p
}

// PutBuf returns a buffer obtained from GetBuf.
func PutBuf(p *[]byte) {
	if cap(*p) <= 2048 {
		smallPool.Put(p)
	} else {
		largePool.Put(p)
	}
}
