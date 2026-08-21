package iroh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The emitter opens its JSONL path with O_TRUNC to discard the b.N warm-up
// invocations and keep the final calibrated one. That is safe only under one
// invariant -- one cell, one repetition, one path, one process -- which
// checkLadderPathOwnership enforces.

func writeLadderSample(t *testing.T, path string, s layerLadderSample) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLadderPathOwnership pins both directions of the guard. The negatives are
// each a shape that destroys a measurement; the positives are the two the
// O_TRUNC exists to serve, and without them a check that rejected every
// existing file would pass every negative.
func TestLadderPathOwnership(t *testing.T) {
	pid := os.Getpid()
	mine := layerLadderSample{Rung: "full-steady", Sample: 3, PID: pid}

	tests := []struct {
		name    string
		setup   func(t *testing.T, path string)
		want    layerLadderSample
		wantErr bool
	}{{
		name: "another cell",
		setup: func(t *testing.T, p string) {
			writeLadderSample(t, p, layerLadderSample{Rung: "full-stream-msg-32", Sample: 3, PID: pid})
		},
		// Two cells batched into one process share a path.
		want:    mine,
		wantErr: true,
	}, {
		name: "another repetition",
		setup: func(t *testing.T, p string) {
			writeLadderSample(t, p, layerLadderSample{Rung: "full-steady", Sample: 7, PID: pid})
		},
		// A path without the repetition in it keeps only the last sample.
		want:    mine,
		wantErr: true,
	}, {
		name: "another process, same cell",
		setup: func(t *testing.T, p string) {
			writeLadderSample(t, p, layerLadderSample{Rung: "full-steady", Sample: 3, PID: pid + 1})
		},
		// Matching rung and sample do not make the record ours.
		want:    mine,
		wantErr: true,
	}, {
		name: "no process attribution",
		setup: func(t *testing.T, p string) {
			writeLadderSample(t, p, layerLadderSample{Rung: "full-steady", Sample: 3})
		},
		// A record predating the pid field cannot be shown to be ours.
		want:    mine,
		wantErr: true,
	}, {
		name:    "unparseable file",
		setup:   func(t *testing.T, p string) { mustWriteFile(t, p, "not json at all\n") },
		want:    mine,
		wantErr: true,
	}, {
		name:    "unreadable path",
		setup:   func(t *testing.T, p string) { mustMkdir(t, p) },
		want:    mine,
		wantErr: true,
	}, {
		name: "own warm-up",
		setup: func(t *testing.T, p string) {
			writeLadderSample(t, p, layerLadderSample{Rung: "full-steady", Sample: 3, PID: pid, Bytes: 1})
		},
		want: layerLadderSample{Rung: "full-steady", Sample: 3, PID: pid, Bytes: 999},
	}, {
		name:  "first write",
		setup: func(t *testing.T, p string) {},
		want:  mine,
	}, {
		name:  "empty file",
		setup: func(t *testing.T, p string) { mustWriteFile(t, p, "") },
		want:  mine,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "x.jsonl")
			tt.setup(t, p)
			err := checkLadderPathOwnership(p, tt.want)
			if tt.wantErr {
				if err == nil {
					t.Fatal("O_TRUNC was allowed to destroy the existing record")
				}
				t.Log(err)
				return
			}
			if err != nil {
				t.Errorf("the emitter was blocked from its own write: %v", err)
			}
		})
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
