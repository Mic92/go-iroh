package metrics

import (
	"bytes"
	"encoding/json"
	"expvar"
	"io"
	"testing"
)

type source Snapshot

func (s source) Snapshot() Snapshot { return Snapshot(s) }

type structuredSource StructuredSnapshot

func (s structuredSource) StructuredSnapshot() StructuredSnapshot {
	return StructuredSnapshot(s)
}

func TestRegistryWriteOpenMetrics(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("endpoint", source{
		"connects_started": 2,
		"accepts_failed":   1,
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	want := "# TYPE endpoint_accepts_failed counter\n" +
		"endpoint_accepts_failed_total 1\n" +
		"# TYPE endpoint_connects_started counter\n" +
		"endpoint_connects_started_total 2\n" +
		"# EOF\n"
	if got := buf.String(); got != want {
		t.Fatalf("OpenMetrics = %q, want %q", got, want)
	}
}

func TestRegistryWriteStructuredOpenMetrics(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("runtime", structuredSource{
		"active_paths": Gauge(2),
		"probe_seconds": Histogram(1.5, 3, []HistogramBucket{
			{Le: 1, Count: 2},
			{Le: 5, Count: 3},
		}),
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := r.WriteOpenMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	want := "# TYPE runtime_active_paths gauge\n" +
		"runtime_active_paths 2\n" +
		"# TYPE runtime_probe_seconds histogram\n" +
		"runtime_probe_seconds_bucket{le=\"1\"} 2\n" +
		"runtime_probe_seconds_bucket{le=\"5\"} 3\n" +
		"runtime_probe_seconds_bucket{le=\"+Inf\"} 3\n" +
		"runtime_probe_seconds_sum 1.5\n" +
		"runtime_probe_seconds_count 3\n" +
		"# EOF\n"
	if got := buf.String(); got != want {
		t.Fatalf("OpenMetrics = %q, want %q", got, want)
	}
}

func TestRegistryRejectsUnknownMetricType(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("bad", structuredSource{"value": {Type: "unknown"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteOpenMetrics(io.Discard); err == nil {
		t.Fatal("WriteOpenMetrics with unknown metric type succeeded")
	}
}

func TestSnapshotStringExpvar(t *testing.T) {
	var _ expvar.Var = Snapshot{}
	s := Snapshot{"connects_started": 2}
	var got map[string]uint64
	if err := json.Unmarshal([]byte(s.String()), &got); err != nil {
		t.Fatalf("Snapshot.String is not JSON: %v", err)
	}
	if got["connects_started"] != 2 {
		t.Fatalf("Snapshot.String = %s", s.String())
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("endpoint", source{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("endpoint", source{}); err == nil {
		t.Fatal("duplicate Register succeeded")
	}
}

func TestRegistryRejectsInvalidSource(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("bad", "not a source"); err == nil {
		t.Fatal("Register accepted invalid source")
	}
}
