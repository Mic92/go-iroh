package qlogtest

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
	"time"
)

const RecordSeparator = byte(0x1e)

func WaitFiles(ctx context.Context, dir string) ([]string, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		files, err := Files(dir)
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

func Files(dir string) ([]string, error) {
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

func FrameTypes(files []string) (map[string]int, error) {
	types := make(map[string]int)
	for _, file := range files {
		if err := scanFile(file, types); err != nil {
			return nil, err
		}
	}
	return types, nil
}

func scanFile(file string, types map[string]int) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if bytes.Contains(data, []byte{RecordSeparator}) {
		return scanJSONSeq(file, data, types)
	}
	return scanJSON(file, data, types)
}

func scanJSONSeq(file string, data []byte, types map[string]int) error {
	for i, record := range bytes.Split(data, []byte{RecordSeparator}) {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		if err := scanRecord(record, types); err != nil {
			return fmt.Errorf("%s record %d: %w", file, i, err)
		}
	}
	return nil
}

func scanJSON(file string, data []byte, types map[string]int) error {
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
		collectFrameTypes(value, types)
	}
}

func scanRecord(data []byte, types map[string]int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return err
	}
	collectFrameTypes(value, types)
	return nil
}

func collectFrameTypes(value any, types map[string]int) {
	switch value := value.(type) {
	case map[string]any:
		if frameType, ok := value["frame_type"].(string); ok {
			types[frameType]++
		}
		for _, child := range value {
			collectFrameTypes(child, types)
		}
	case []any:
		for _, child := range value {
			collectFrameTypes(child, types)
		}
	}
}

func SortedFrameTypes(types map[string]int) []string {
	out := make([]string, 0, len(types))
	for frameType, count := range types {
		out = append(out, fmt.Sprintf("%s=%d", frameType, count))
	}
	sort.Strings(out)
	return out
}
