package iroh

import (
	"encoding/json"
	"io"
	"sync/atomic"

	"github.com/tmc/go-iroh/metrics"
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

// Snapshot returns m as named counter values for [metrics.Registry].
func (m Metrics) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"connects_started":  m.ConnectsStarted,
		"connects_accepted": m.ConnectsAccepted,
		"connects_failed":   m.ConnectsFailed,
		"accepts_started":   m.AcceptsStarted,
		"accepts_accepted":  m.AcceptsAccepted,
		"accepts_failed":    m.AcceptsFailed,
	}
}

// WriteOpenMetrics writes m in OpenMetrics text format under the "endpoint"
// prefix.
func (m Metrics) WriteOpenMetrics(w io.Writer) error {
	r := metrics.NewRegistry()
	if err := r.Register("endpoint", m); err != nil {
		return err
	}
	return r.WriteOpenMetrics(w)
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
