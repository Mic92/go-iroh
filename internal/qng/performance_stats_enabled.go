//go:build iroh_performance_stats

package quic

type performanceCounters struct {
	stats PerformanceStats
}

type performanceSnapshotRequest struct {
	dst *PerformanceStats
}

func (c *performanceCounters) recordPacket(p shortHeaderPacket) {
	if p.Ack != nil {
		c.stats.ACKFramesSent++
		if !p.HasStreamFrame && len(p.StreamFrames) == 0 && len(p.Frames) == 0 {
			c.stats.ACKOnlyPacketsSent++
		}
	}
	if p.HasStreamFrame {
		c.stats.StreamFramesSent++
		c.stats.StreamBytesSent += uint64(p.StreamFrame.Frame.DataLen())
	}
	for _, frame := range p.StreamFrames {
		c.stats.StreamFramesSent++
		c.stats.StreamBytesSent += uint64(frame.Frame.DataLen())
	}
}

func (c *performanceCounters) recordSendLoop() {
	c.stats.SendLoopRuns++
}

func (c *performanceCounters) recordStreamActivation() {
	c.stats.StreamActivations++
}

func (r performanceSnapshotRequest) fill(c *performanceCounters) {
	if r.dst != nil {
		*r.dst = c.stats
	}
}

// PerformanceStats returns a consistent snapshot of packetization counters.
func (c *Conn) PerformanceStats() PerformanceStats {
	dst := new(PerformanceStats)
	req := &pathSnapshotRequest{
		performance: performanceSnapshotRequest{dst: dst},
		done:        make(chan struct{}),
	}
	select {
	case c.pathSnapshotQueue <- req:
	case <-c.ctx.Done():
		return PerformanceStats{}
	}
	c.scheduleSending()
	select {
	case <-req.done:
		return *dst
	case <-c.ctx.Done():
		return PerformanceStats{}
	}
}
