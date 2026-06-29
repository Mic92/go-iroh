package blobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// TagInfo describes one named blob tag.
type TagInfo struct {
	Name  string
	Value HashAndFormat
}

// GCResult reports the result of a filesystem store garbage-collection sweep.
type GCResult struct {
	Deleted int
}

// SetTag sets name to value.
func (s *FSStore) SetTag(name string, value HashAndFormat) error {
	if s == nil {
		return errors.New("blobs: nil fs store")
	}
	if name == "" {
		return errors.New("blobs: empty tag name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tags == nil {
		s.tags = make(map[string]HashAndFormat)
	}
	s.tags[name] = value
	if err := s.saveTagsLocked(); err != nil {
		return err
	}
	return nil
}

// Tag returns the value for name.
func (s *FSStore) Tag(name string) (HashAndFormat, bool, error) {
	if s == nil {
		return HashAndFormat{}, false, errors.New("blobs: nil fs store")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.tags[name]
	return value, ok, nil
}

// DeleteTag deletes name.
func (s *FSStore) DeleteTag(name string) (bool, error) {
	if s == nil {
		return false, errors.New("blobs: nil fs store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tags[name]; !ok {
		return false, nil
	}
	delete(s.tags, name)
	if err := s.saveTagsLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// Tags returns all persistent tags sorted by name.
func (s *FSStore) Tags() ([]TagInfo, error) {
	if s == nil {
		return nil, errors.New("blobs: nil fs store")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TagInfo, 0, len(s.tags))
	for name, value := range s.tags {
		out = append(out, TagInfo{Name: name, Value: value})
	}
	slices.SortFunc(out, func(a, b TagInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// TempTag is a process-local tag removed when closed.
type TempTag struct {
	once  sync.Once
	store *FSStore
	id    uint64
}

// NewTempTag creates a process-local tag for value.
func (s *FSStore) NewTempTag(value HashAndFormat) (*TempTag, error) {
	if s == nil {
		return nil, errors.New("blobs: nil fs store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.temp == nil {
		s.temp = make(map[uint64]HashAndFormat)
	}
	s.nextTag++
	id := s.nextTag
	s.temp[id] = value
	return &TempTag{store: s, id: id}, nil
}

// Close removes t from its store.
func (t *TempTag) Close() error {
	if t == nil || t.store == nil {
		return nil
	}
	t.once.Do(func() {
		t.store.mu.Lock()
		delete(t.store.temp, t.id)
		t.store.mu.Unlock()
	})
	return nil
}

// GC deletes blobs that are not reachable from a persistent or temp tag.
func (s *FSStore) GC(ctx context.Context) (GCResult, error) {
	if s == nil {
		return GCResult{}, errors.New("blobs: nil fs store")
	}
	if err := ctxErr(ctx); err != nil {
		return GCResult{}, err
	}
	live := make(map[Hash]struct{})
	s.mu.RLock()
	for _, value := range s.tags {
		s.markLiveLocked(live, value)
	}
	for _, value := range s.temp {
		s.markLiveLocked(live, value)
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return GCResult{}, fmt.Errorf("blobs: read data dir: %w", err)
	}
	var deleted int
	for _, entry := range entries {
		if err := ctxErr(ctx); err != nil {
			return GCResult{}, err
		}
		if entry.IsDir() {
			continue
		}
		hash, err := ParseHash(entry.Name())
		if err != nil {
			continue
		}
		if _, ok := live[hash]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(s.dataDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return GCResult{}, fmt.Errorf("blobs: remove data: %w", err)
		}
		if err := os.Remove(filepath.Join(s.baoDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return GCResult{}, fmt.Errorf("blobs: remove outboard: %w", err)
		}
		deleted++
	}
	return GCResult{Deleted: deleted}, nil
}

func (s *FSStore) markLiveLocked(live map[Hash]struct{}, value HashAndFormat) {
	if value.Hash == EmptyHash {
		return
	}
	if _, ok := live[value.Hash]; ok {
		return
	}
	live[value.Hash] = struct{}{}
	if value.Format.IsRaw() {
		return
	}
	data, err := os.ReadFile(s.dataPath(value.Hash))
	if err != nil {
		return
	}
	seq, err := ParseHashSequence(data)
	if err != nil {
		return
	}
	for _, hash := range seq.Hashes() {
		live[hash] = struct{}{}
	}
}
