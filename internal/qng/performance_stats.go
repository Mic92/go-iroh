package quic

// PerformanceStats contains packetization counters collected by binaries built
// with the iroh_performance_stats build tag.
type PerformanceStats struct {
	StreamFramesSent   uint64
	StreamBytesSent    uint64
	ACKFramesSent      uint64
	ACKOnlyPacketsSent uint64
	StreamActivations  uint64
	SendLoopRuns       uint64
}
