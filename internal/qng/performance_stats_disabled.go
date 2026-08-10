//go:build !iroh_performance_stats

package quic

type performanceCounters struct{}
type performanceSnapshotRequest struct{}

func (*performanceCounters) recordPacket(shortHeaderPacket)  {}
func (*performanceCounters) recordSendLoop()                 {}
func (*performanceCounters) recordStreamActivation()         {}
func (performanceSnapshotRequest) fill(*performanceCounters) {}

// PerformanceStats returns zero counters in an ordinary build.
func (*Conn) PerformanceStats() PerformanceStats { return PerformanceStats{} }
