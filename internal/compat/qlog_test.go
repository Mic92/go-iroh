package compat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const qlogRecordSeparator = byte(0x1e)

func TestQlogFrameTypes(t *testing.T) {
	dir := t.TempDir()

	sqlog := filepath.Join(dir, "go.sqlog")
	sqlogData := []byte{qlogRecordSeparator}
	sqlogData = append(sqlogData, []byte(`{"name":"header"}`)...)
	sqlogData = append(sqlogData, qlogRecordSeparator)
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

	files, err := qlogFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("qlog files = %v, want two", files)
	}

	frames, err := qlogFrameTypes(files)
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
			t.Fatalf("frame %q count = %d, want %d; all frames %v", tt.name, frames[tt.name], tt.want, sortedQlogFrameTypes(frames))
		}
	}
	if frames["ignored"] != 0 {
		t.Fatalf("ignored frame count = %d, want 0", frames["ignored"])
	}
}

func waitQlogFiles(ctx context.Context, dir string) ([]string, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		files, err := qlogFiles(dir)
		if err != nil {
			return nil, err
		}
		if len(files) > 0 {
			return files, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("found no qlog files in %s: %w", dir, ctx.Err())
		case <-ticker.C:
		}
	}
}

func qlogFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".sqlog") || strings.HasSuffix(entry.Name(), ".qlog") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func qlogFrameTypes(files []string) (map[string]int, error) {
	types := make(map[string]int)
	for _, file := range files {
		if err := scanQlogFile(file, types); err != nil {
			return nil, err
		}
	}
	return types, nil
}

func scanQlogFile(file string, types map[string]int) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte{qlogRecordSeparator}) {
		return scanQlogJSONSeq(file, data, types)
	}
	return scanQlogJSON(file, data, types)
}

func scanQlogJSONSeq(file string, data []byte, types map[string]int) error {
	for i, record := range bytes.Split(data, []byte{qlogRecordSeparator}) {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		if err := scanQlogRecord(record, types); err != nil {
			return fmt.Errorf("%s record %d: %w", file, i, err)
		}
	}
	return nil
}

func scanQlogJSON(file string, data []byte, types map[string]int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		var value any
		if err := dec.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", file, err)
		}
		collectQlogFrameTypes(value, types)
	}
}

func scanQlogRecord(data []byte, types map[string]int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return err
	}
	collectQlogFrameTypes(value, types)
	return nil
}

func collectQlogFrameTypes(value any, types map[string]int) {
	switch value := value.(type) {
	case map[string]any:
		if frameType, ok := value["frame_type"].(string); ok {
			types[frameType]++
		}
		for _, child := range value {
			collectQlogFrameTypes(child, types)
		}
	case []any:
		for _, child := range value {
			collectQlogFrameTypes(child, types)
		}
	}
}

func sortedQlogFrameTypes(types map[string]int) []string {
	out := make([]string, 0, len(types))
	for frameType, count := range types {
		out = append(out, fmt.Sprintf("%s=%d", frameType, count))
	}
	sort.Strings(out)
	return out
}
