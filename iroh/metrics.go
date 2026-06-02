package iroh

import (
	"encoding/json"
	"sync/atomic"
)

// Metrics is a snapshot of endpoint counters.
type Metrics struct {
	ConnectsStarted  uint64
	ConnectsAccepted uint64
	ConnectsFailed   uint64
	AcceptsStarted   uint64
	AcceptsAccepted  uint64
	AcceptsFailed    uint64
}

// String implements expvar.Var, returning the metrics snapshot as JSON.
func (m Metrics) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

type endpointMetrics struct {
	connectsStarted  atomic.Uint64
	connectsAccepted atomic.Uint64
	connectsFailed   atomic.Uint64
	acceptsStarted   atomic.Uint64
	acceptsAccepted  atomic.Uint64
	acceptsFailed    atomic.Uint64
}

func (m *endpointMetrics) snapshot() Metrics {
	return Metrics{
		ConnectsStarted:  m.connectsStarted.Load(),
		ConnectsAccepted: m.connectsAccepted.Load(),
		ConnectsFailed:   m.connectsFailed.Load(),
		AcceptsStarted:   m.acceptsStarted.Load(),
		AcceptsAccepted:  m.acceptsAccepted.Load(),
		AcceptsFailed:    m.acceptsFailed.Load(),
	}
}

// Metrics returns a point-in-time snapshot of endpoint counters.
func (e *Endpoint) Metrics() Metrics {
	return e.metrics.snapshot()
}
