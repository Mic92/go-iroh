package quic

import "sync/atomic"

// writeGate serializes calls to SendStream.Write. The common uncontended
// path uses the atomic word; the channel wakes an accidental concurrent
// caller without spinning.
type writeGate struct {
	locked atomic.Uint32
	wake   chan struct{}
}

func (g *writeGate) lock() {
	if g.locked.CompareAndSwap(0, 1) {
		return
	}
	for {
		<-g.wake
		if g.locked.CompareAndSwap(0, 1) {
			return
		}
	}
}

func (g *writeGate) unlock() {
	if !g.locked.CompareAndSwap(1, 0) {
		panic("unlock of unlocked write gate")
	}
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
