package compat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tmc/go-iroh/internal/qlogtest"
)

func TestQlogFrameTypes(t *testing.T) {
	dir := t.TempDir()

	sqlog := filepath.Join(dir, "go.sqlog")
	sqlogData := []byte{qlogtest.RecordSeparator}
	sqlogData = append(sqlogData, []byte(`{"name":"header"}`)...)
	sqlogData = append(sqlogData, qlogtest.RecordSeparator)
	sqlogData = append(sqlogData, []byte(`{"data":{"frames":[{"frame_type":"max_path_id"},{"frame_type":"ping"}]}}`)...)
	if err := os.WriteFile(sqlog, sqlogData, 0o644); err != nil {
		t.Fatal(err)
	}

	qlog := filepath.Join(dir, "rust.qlog")
	qlogData := []byte(`{"traces":[{"events":[{"data":{"frames":[{"frame_type":"add_address"},{"frame_type":17},{"nested":{"frame_type":"max_path_id"}}]}}]}]}`)
	if err := os.WriteFile(qlog, qlogData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte(`{"frame_type":"ignored"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := qlogtest.Files(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("qlog files = %v, want two", files)
	}

	frames, err := qlogtest.FrameTypes(files)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		want int
	}{
		{"add_address", 1},
		{"max_path_id", 2},
		{"ping", 1},
	}
	for _, tt := range tests {
		if frames[tt.name] != tt.want {
			t.Fatalf("frame %q count = %d, want %d; all frames %v", tt.name, frames[tt.name], tt.want, qlogtest.SortedFrameTypes(frames))
		}
	}
	if frames["ignored"] != 0 {
		t.Fatalf("ignored frame count = %d, want 0", frames["ignored"])
	}
}
