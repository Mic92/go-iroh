package docs

import (
	"bytes"
	"slices"
	"sync"
)

// InsertOutcome reports the result of a store insert.
type InsertOutcome struct {
	inserted bool
	removed  int
}

// Inserted reports whether the entry was inserted.
func (o InsertOutcome) Inserted() bool { return o.inserted }

// Removed reports how many older descendant entries were removed.
func (o InsertOutcome) Removed() int { return o.removed }

// MemoryStore is an in-memory document entry store.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]SignedEntry
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]SignedEntry)}
}

// Len returns the number of entries in s.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// GetExact returns the entry for namespace, author, and key.
func (s *MemoryStore) GetExact(namespace NamespaceID, author AuthorID, key []byte, includeEmpty bool) (SignedEntry, bool) {
	id := NewRecordIdentifier(namespace, author, key)

	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[string(id.bytes())]
	if !ok || (!includeEmpty && entry.Entry.Record.IsEmpty()) {
		return SignedEntry{}, false
	}
	return entry, true
}

// Entries returns the store entries in document order.
func (s *MemoryStore) Entries() []SignedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]SignedEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b SignedEntry) int {
		return a.Compare(b)
	})
	return entries
}

// Put inserts entry if it is newer than all matching parent entries.
func (s *MemoryStore) Put(entry SignedEntry) InsertOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.entries == nil {
		s.entries = make(map[string]SignedEntry)
	}
	id := entry.Entry.ID
	key := id.bytes()
	for _, existing := range s.entries {
		if hasEntryPrefix(id, existing.Entry.ID) && entry.Entry.Record.Compare(existing.Entry.Record) <= 0 {
			return InsertOutcome{}
		}
	}
	removed := 0
	for k, existing := range s.entries {
		if hasEntryPrefix(existing.Entry.ID, id) && entry.Entry.Record.Compare(existing.Entry.Record) >= 0 {
			delete(s.entries, k)
			removed++
		}
	}
	s.entries[string(key)] = entry
	return InsertOutcome{inserted: true, removed: removed}
}

func hasEntryPrefix(id, prefix RecordIdentifier) bool {
	return id.namespace == prefix.namespace && id.author == prefix.author && bytes.HasPrefix(id.key, prefix.key)
}
