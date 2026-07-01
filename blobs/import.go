package blobs

import (
	"errors"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3/bao"
)

// ImportMode controls how [FSStore.ImportFile] stores file data.
type ImportMode uint8

const (
	// ImportCopy always copies bytes into the store.
	ImportCopy ImportMode = iota
	// ImportTryReference tries to reference the source with a hardlink, then
	// falls back to [ImportCopy]. Reflink support can be added behind this mode.
	ImportTryReference
)

// ImportFile imports path as a complete raw blob.
func (s *FSStore) ImportFile(path string, mode ImportMode) (Hash, error) {
	if s == nil {
		return Hash{}, errors.New("blobs: nil fs store")
	}
	if path == "" {
		return Hash{}, errors.New("blobs: empty import path")
	}
	switch mode {
	case ImportCopy:
		return s.importFileCopy(path)
	case ImportTryReference:
		hash, err := s.importFileLink(path)
		if err == nil {
			return hash, nil
		}
		return s.importFileCopy(path)
	default:
		return Hash{}, fmt.Errorf("blobs: unknown import mode %d", mode)
	}
}

func (s *FSStore) importFileCopy(path string) (Hash, error) {
	src, err := os.Open(path)
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: open import file: %w", err)
	}
	defer src.Close()

	dataTmp, err := os.CreateTemp(s.dataDir, ".import-data-*")
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: create import data: %w", err)
	}
	defer removeTemp(dataTmp.Name())
	if _, err := io.Copy(dataTmp, src); err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: copy import data: %w", err)
	}
	if _, err := dataTmp.Seek(0, io.SeekStart); err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: rewind import data: %w", err)
	}
	return s.finishImport(dataTmp, true)
}

func (s *FSStore) importFileLink(path string) (Hash, error) {
	dataTmp, err := os.CreateTemp(s.dataDir, ".import-data-*")
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: create import data: %w", err)
	}
	dataTmpName := dataTmp.Name()
	if err := dataTmp.Close(); err != nil {
		removeTemp(dataTmpName)
		return Hash{}, err
	}
	if err := os.Remove(dataTmpName); err != nil {
		return Hash{}, err
	}
	if err := os.Link(path, dataTmpName); err != nil {
		return Hash{}, err
	}
	dataTmp, err = os.OpenFile(dataTmpName, os.O_RDONLY, 0)
	if err != nil {
		removeTemp(dataTmpName)
		return Hash{}, fmt.Errorf("blobs: open linked import data: %w", err)
	}
	defer removeTemp(dataTmpName)
	return s.finishImport(dataTmp, false)
}

func (s *FSStore) finishImport(dataTmp *os.File, syncData bool) (Hash, error) {
	info, err := dataTmp.Stat()
	if err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: stat import data: %w", err)
	}
	outTmp, err := os.CreateTemp(s.baoDir, ".import-outboard-*")
	if err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: create import outboard: %w", err)
	}
	defer removeTemp(outTmp.Name())

	root, err := bao.Encode(outTmp, dataTmp, info.Size(), 4, true)
	if err != nil {
		outTmp.Close()
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: encode import outboard: %w", err)
	}
	hash := Hash(root)
	if syncData {
		if err := dataTmp.Sync(); err != nil {
			outTmp.Close()
			dataTmp.Close()
			return Hash{}, fmt.Errorf("blobs: sync import data: %w", err)
		}
	}
	if err := outTmp.Sync(); err != nil {
		outTmp.Close()
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: sync import outboard: %w", err)
	}
	if err := dataTmp.Close(); err != nil {
		outTmp.Close()
		return Hash{}, fmt.Errorf("blobs: close import data: %w", err)
	}
	if err := outTmp.Close(); err != nil {
		return Hash{}, fmt.Errorf("blobs: close import outboard: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if fileExists(s.dataPath(hash)) && fileExists(s.outboardPath(hash)) {
		return hash, nil
	}
	if err := os.Rename(dataTmp.Name(), s.dataPath(hash)); err != nil {
		return Hash{}, fmt.Errorf("blobs: install import data: %w", err)
	}
	if err := os.Rename(outTmp.Name(), s.outboardPath(hash)); err != nil {
		_ = os.Remove(s.dataPath(hash))
		return Hash{}, fmt.Errorf("blobs: install import outboard: %w", err)
	}
	return hash, nil
}

func removeTemp(name string) {
	_ = os.Remove(name)
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
