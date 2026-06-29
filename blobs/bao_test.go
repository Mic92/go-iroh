package blobs

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestSingleLeafRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "small", data: []byte("hello from iroh-blobs")},
		{name: "chunk", data: repeatByte(0xab, ChunkSize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, encoded, err := EncodeSingleLeaf(tt.data)
			if err != nil {
				t.Fatalf("EncodeSingleLeaf: %v", err)
			}
			if got := binary.LittleEndian.Uint64(encoded[:8]); got != uint64(len(tt.data)) {
				t.Fatalf("size prefix = %d, want %d", got, len(tt.data))
			}
			if string(encoded[8:]) != string(tt.data) {
				t.Fatalf("payload = %x, want %x", encoded[8:], tt.data)
			}
			if hash != NewHash(tt.data) {
				t.Fatalf("hash = %s, want %s", hash, NewHash(tt.data))
			}
			got, err := DecodeSingleLeaf(hash, encoded)
			if err != nil {
				t.Fatalf("DecodeSingleLeaf: %v", err)
			}
			if string(got) != string(tt.data) {
				t.Fatalf("DecodeSingleLeaf = %x, want %x", got, tt.data)
			}
			if len(got) > 0 {
				got[0] ^= 0xff
				if string(tt.data) == string(got) {
					t.Fatal("DecodeSingleLeaf returned aliased data")
				}
			}
		})
	}
}

func TestSingleLeafErrors(t *testing.T) {
	if _, _, err := EncodeSingleLeaf(repeatByte(0, ChunkSize+1)); !errors.Is(err, ErrSingleLeafTooLarge) {
		t.Fatalf("EncodeSingleLeaf too large error = %v", err)
	}
	hash := NewHash([]byte("ok"))
	if _, err := DecodeSingleLeaf(hash, []byte{1, 2, 3}); !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("DecodeSingleLeaf truncated error = %v", err)
	}
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, ChunkSize+1)
	if _, err := DecodeSingleLeaf(hash, encoded); !errors.Is(err, ErrSingleLeafTooLarge) {
		t.Fatalf("DecodeSingleLeaf too large error = %v", err)
	}
	_, encoded, err := EncodeSingleLeaf([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	encoded = encoded[:len(encoded)-1]
	if _, err := DecodeSingleLeaf(hash, encoded); !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("DecodeSingleLeaf size mismatch error = %v", err)
	}
	_, encoded, err = EncodeSingleLeaf([]byte("no"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSingleLeaf(hash, encoded); !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("DecodeSingleLeaf hash mismatch error = %v", err)
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
