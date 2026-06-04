package metrics

import (
	"bytes"
	"encoding/json"
	"expvar"
	"testing"
)

type source Snapshot

func (s source) Snapshot() Snapshot { return Snapshot(s) }

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
