package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Snapshot is a point-in-time set of unsigned counter values.
type Snapshot map[string]uint64

// MetricType is the OpenMetrics type of a metric value.
type MetricType string

const (
	// CounterMetric is a monotonically increasing counter.
	CounterMetric MetricType = "counter"
	// GaugeMetric is a point-in-time value that may increase or decrease.
	GaugeMetric MetricType = "gauge"
	// HistogramMetric is a cumulative histogram.
	HistogramMetric MetricType = "histogram"
)

// HistogramBucket is one cumulative histogram bucket.
type HistogramBucket struct {
	// Le is the inclusive upper bound. Use math.Inf(1) for +Inf.
	Le float64
	// Count is the cumulative count for this bucket.
	Count uint64
}

// MetricValue is one metric sample in a [StructuredSnapshot].
type MetricValue struct {
	Type    MetricType
	Counter uint64
	Gauge   float64
	Sum     float64
	Count   uint64
	Buckets []HistogramBucket
}

// Counter returns a counter metric value.
func Counter(v uint64) MetricValue { return MetricValue{Type: CounterMetric, Counter: v} }

// Gauge returns a gauge metric value.
func Gauge(v float64) MetricValue { return MetricValue{Type: GaugeMetric, Gauge: v} }

// Histogram returns a histogram metric value. Buckets are copied and sorted by
// upper bound before OpenMetrics output.
func Histogram(sum float64, count uint64, buckets []HistogramBucket) MetricValue {
	return MetricValue{Type: HistogramMetric, Sum: sum, Count: count, Buckets: append([]HistogramBucket(nil), buckets...)}
}

// StructuredSnapshot is a point-in-time set of typed metric values.
type StructuredSnapshot map[string]MetricValue

// String implements expvar.Var, returning the snapshot as JSON.
func (s Snapshot) String() string {
	b, _ := json.Marshal(map[string]uint64(s))
	return string(b)
}

// Source returns a point-in-time metrics snapshot.
type Source interface {
	Snapshot() Snapshot
}

// StructuredSource returns a point-in-time typed metrics snapshot.
type StructuredSource interface {
	StructuredSnapshot() StructuredSnapshot
}

// Registry collects named metric sources.
type Registry struct {
	mu      sync.Mutex
	sources map[string]any
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sources: make(map[string]any)}
}

// Register adds source under prefix. Prefix must be non-empty and unique.
func (r *Registry) Register(prefix string, source any) error {
	if r == nil {
		return errors.New("metrics: nil registry")
	}
	if prefix == "" {
		return errors.New("metrics: empty prefix")
	}
	if source == nil {
		return errors.New("metrics: nil source")
	}
	if _, ok := source.(Source); !ok {
		if _, ok := source.(StructuredSource); !ok {
			return errors.New("metrics: source must implement Source or StructuredSource")
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sources == nil {
		r.sources = make(map[string]any)
	}
	if _, ok := r.sources[prefix]; ok {
		return fmt.Errorf("metrics: duplicate prefix %q", prefix)
	}
	r.sources[prefix] = source
	return nil
}

// WriteOpenMetrics writes all registered counter snapshots in OpenMetrics text
// format.
func (r *Registry) WriteOpenMetrics(w io.Writer) error {
	if r == nil {
		return errors.New("metrics: nil registry")
	}
	r.mu.Lock()
	sources := make(map[string]any, len(r.sources))
	for prefix, source := range r.sources {
		sources[prefix] = source
	}
	r.mu.Unlock()

	prefixes := make([]string, 0, len(sources))
	for prefix := range sources {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		snap := structuredSnapshot(sources[prefix])
		names := make([]string, 0, len(snap))
		for name := range snap {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			metricName := cleanName(prefix + "_" + name)
			if err := writeMetric(w, metricName, snap[name]); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(w, "# EOF\n"); err != nil {
		return err
	}
	return nil
}

func structuredSnapshot(source any) StructuredSnapshot {
	if structured, ok := source.(StructuredSource); ok {
		return structured.StructuredSnapshot()
	}
	legacy, ok := source.(Source)
	if !ok {
		return nil
	}
	snap := legacy.Snapshot()
	out := make(StructuredSnapshot, len(snap))
	for name, value := range snap {
		out[name] = Counter(value)
	}
	return out
}

func writeMetric(w io.Writer, name string, value MetricValue) error {
	switch value.Type {
	case "", CounterMetric:
		_, err := fmt.Fprintf(w, "# TYPE %s counter\n%s_total %d\n", name, name, value.Counter)
		return err
	case GaugeMetric:
		_, err := fmt.Fprintf(w, "# TYPE %s gauge\n%s %s\n", name, name, formatFloat(value.Gauge))
		return err
	case HistogramMetric:
		return writeHistogram(w, name, value)
	default:
		return fmt.Errorf("metrics: unknown metric type %q", value.Type)
	}
}

func writeHistogram(w io.Writer, name string, value MetricValue) error {
	buckets := append([]HistogramBucket(nil), value.Buckets...)
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Le < buckets[j].Le
	})
	if _, err := fmt.Fprintf(w, "# TYPE %s histogram\n", name); err != nil {
		return err
	}
	for _, b := range buckets {
		if _, err := fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, formatBucket(b.Le), b.Count); err != nil {
			return err
		}
	}
	if len(buckets) == 0 || !math.IsInf(buckets[len(buckets)-1].Le, 1) {
		if _, err := fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, value.Count); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s_sum %s\n", name, formatFloat(value.Sum)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s_count %d\n", name, value.Count)
	return err
}

func formatBucket(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	return formatFloat(v)
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func cleanName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
