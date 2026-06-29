package docs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/internal/postcard"
)

var storeSnapshotMagic = []byte("go-iroh-docs-store\x00\x01")

const maxStoreEntrySize = 16 << 20
const maxStoreEntries = 1_000_000

// WriteTo writes a deterministic snapshot of s to w.
func (s *MemoryStore) WriteTo(w io.Writer) (int64, error) {
	cw := &countingWriter{w: w}
	if err := writeAll(cw, storeSnapshotMagic); err != nil {
		return cw.n, err
	}
	entries := s.Entries()
	if err := writeUvarint(cw, uint64(len(entries))); err != nil {
		return cw.n, err
	}
	for _, entry := range entries {
		b, err := postcard.Marshal(entry)
		if err != nil {
			return cw.n, fmt.Errorf("docs: encode store entry: %w", err)
		}
		if err := writeUvarint(cw, uint64(len(b))); err != nil {
			return cw.n, err
		}
		if err := writeAll(cw, b); err != nil {
			return cw.n, err
		}
	}
	return cw.n, nil
}

// ReadFrom reads a snapshot written by [MemoryStore.WriteTo] and inserts its
// entries into s. Entries are verified before insertion.
func (s *MemoryStore) ReadFrom(r io.Reader) (int64, error) {
	cr := &countingReader{r: bufio.NewReader(r)}
	magic := make([]byte, len(storeSnapshotMagic))
	if _, err := io.ReadFull(cr, magic); err != nil {
		return cr.n, fmt.Errorf("docs: read store header: %w", err)
	}
	if !bytes.Equal(magic, storeSnapshotMagic) {
		return cr.n, errors.New("docs: invalid store snapshot")
	}
	count, err := binary.ReadUvarint(cr)
	if err != nil {
		return cr.n, fmt.Errorf("docs: read store entry count: %w", err)
	}
	if count > maxStoreEntries {
		return cr.n, fmt.Errorf("docs: store entry count too large")
	}
	for i := uint64(0); i < count; i++ {
		n, err := binary.ReadUvarint(cr)
		if err != nil {
			return cr.n, fmt.Errorf("docs: read store entry length: %w", err)
		}
		if n > maxStoreEntrySize {
			return cr.n, fmt.Errorf("docs: store entry too large")
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(cr, b); err != nil {
			return cr.n, fmt.Errorf("docs: read store entry: %w", err)
		}
		var entry SignedEntry
		if err := postcard.Unmarshal(b, &entry); err != nil {
			return cr.n, fmt.Errorf("docs: decode store entry: %w", err)
		}
		if err := entry.Verify(); err != nil {
			return cr.n, fmt.Errorf("docs: verify store entry: %w", err)
		}
		s.put(entry)
	}
	return cr.n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

type countingReader struct {
	r interface {
		io.Reader
		io.ByteReader
	}
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

func (r *countingReader) ReadByte() (byte, error) {
	b, err := r.r.ReadByte()
	if err == nil {
		r.n++
	}
	return b, err
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func writeUvarint(w io.Writer, x uint64) error {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], x)
	return writeAll(w, buf[:n])
}
