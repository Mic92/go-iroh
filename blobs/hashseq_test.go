package blobs

import (
	"errors"
	"testing"
)

func TestHashSequenceRoundTrip(t *testing.T) {
	hashes := []Hash{
		NewHash([]byte("first")),
		NewHash([]byte("second")),
		NewHash([]byte("third")),
	}
	seq := NewHashSequence(hashes)
	got, err := ParseHashSequence(seq.Bytes())
	if err != nil {
		t.Fatalf("ParseHashSequence: %v", err)
	}
	if got.Len() != len(hashes) {
		t.Fatalf("Len = %d, want %d", got.Len(), len(hashes))
	}
	for i, want := range hashes {
		h, ok := got.At(i)
		if !ok || h != want {
			t.Fatalf("At(%d) = %s, %v, want %s, true", i, h, ok, want)
		}
	}

	hashes[0] = Hash{}
	if h, _ := seq.At(0); h == hashes[0] {
		t.Fatal("NewHashSequence retained caller slice")
	}
	out := seq.Hashes()
	out[0] = Hash{}
	if h, _ := seq.At(0); h == out[0] {
		t.Fatal("Hashes returned aliased slice")
	}
}

func TestParseHashSequenceErrors(t *testing.T) {
	_, err := ParseHashSequence([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("ParseHashSequence accepted short input")
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("ParseHashSequence error wraps unexpected cause: %v", err)
	}
}
