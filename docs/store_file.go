package docs

import (
	"fmt"
	"os"
	"path/filepath"
)

// SaveFile writes s to path atomically.
func (s *MemoryStore) SaveFile(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("docs: create store temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := s.WriteTo(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("docs: write store file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("docs: sync store file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("docs: close store file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("docs: rename store file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// LoadMemoryStoreFile loads a store snapshot from path.
func LoadMemoryStoreFile(path string) (*MemoryStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("docs: open store file: %w", err)
	}
	defer f.Close()

	store := NewMemoryStore()
	if _, err := store.ReadFrom(f); err != nil {
		return nil, err
	}
	return store, nil
}
