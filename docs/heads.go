package docs

import (
	"bytes"
	"slices"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/postcard"
)

type authorHead struct {
	Timestamp uint64
	Author    AuthorID
}

type syncHead struct {
	Timestamp uint64
	Author    AuthorID
	Hash      blobs.Hash
}

func (s *MemoryStore) authorHeads(namespace NamespaceID) []authorHead {
	s.mu.RLock()
	defer s.mu.RUnlock()

	latest := make(map[AuthorID]uint64)
	for _, entry := range s.entries {
		if entry.Entry.Namespace() != namespace {
			continue
		}
		author := entry.Entry.Author()
		ts := entry.Entry.Timestamp()
		if ts > latest[author] {
			latest[author] = ts
		}
	}
	heads := make([]authorHead, 0, len(latest))
	for author, ts := range latest {
		heads = append(heads, authorHead{Timestamp: ts, Author: author})
	}
	sortAuthorHeads(heads)
	return heads
}

func (s *MemoryStore) encodeAuthorHeads(namespace NamespaceID) []byte {
	b, err := postcard.Marshal(s.authorHeads(namespace))
	if err != nil {
		return nil
	}
	return b
}

func (s *MemoryStore) encodeAuthorHeadsLimited(namespace NamespaceID, limit int, fits func([]byte) bool) []byte {
	heads := s.authorHeads(namespace)
	for n := len(heads); n >= 0; n-- {
		b, err := postcard.Marshal(heads[:n])
		if err != nil {
			return nil
		}
		if len(b) <= limit && (fits == nil || fits(b)) {
			return b
		}
	}
	return nil
}

func (s *MemoryStore) encodeSyncHeads(namespace NamespaceID) []byte {
	b, err := postcard.Marshal(s.syncHeads(namespace))
	if err != nil {
		return nil
	}
	return b
}

func (s *MemoryStore) hasNewsForUs(namespace NamespaceID, encoded []byte) bool {
	var remote []authorHead
	if err := postcard.Unmarshal(encoded, &remote); err != nil {
		return true
	}
	local := s.authorHeads(namespace)
	byAuthor := make(map[AuthorID]uint64, len(local))
	for _, head := range local {
		byAuthor[head.Author] = head.Timestamp
	}
	for _, head := range remote {
		if head.Timestamp > byAuthor[head.Author] {
			return true
		}
	}
	return false
}

func sortAuthorHeads(heads []authorHead) {
	slices.SortFunc(heads, func(a, b authorHead) int {
		if a.Timestamp > b.Timestamp {
			return -1
		}
		if a.Timestamp < b.Timestamp {
			return 1
		}
		ab, bb := a.Author.Bytes(), b.Author.Bytes()
		return bytes.Compare(ab[:], bb[:])
	})
}

func (s *MemoryStore) syncHeads(namespace NamespaceID) []syncHead {
	s.mu.RLock()
	defer s.mu.RUnlock()

	latest := make(map[AuthorID]syncHead)
	for _, entry := range s.entries {
		if entry.Entry.Namespace() != namespace {
			continue
		}
		author := entry.Entry.Author()
		ts := entry.Entry.Timestamp()
		head := latest[author]
		switch {
		case ts > head.Timestamp:
			latest[author] = syncHead{
				Timestamp: ts,
				Author:    author,
				Hash:      blobs.Hash(entry.Fingerprint()),
			}
		case ts == head.Timestamp:
			hash := blobs.Hash(entry.Fingerprint())
			for i := range head.Hash {
				head.Hash[i] ^= hash[i]
			}
			latest[author] = head
		}
	}
	heads := make([]syncHead, 0, len(latest))
	for _, head := range latest {
		heads = append(heads, head)
	}
	sortSyncHeads(heads)
	return heads
}

func sortSyncHeads(heads []syncHead) {
	slices.SortFunc(heads, func(a, b syncHead) int {
		if a.Timestamp > b.Timestamp {
			return -1
		}
		if a.Timestamp < b.Timestamp {
			return 1
		}
		ab, bb := a.Author.Bytes(), b.Author.Bytes()
		if c := bytes.Compare(ab[:], bb[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.Hash[:], b.Hash[:])
	})
}
