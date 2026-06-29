package blobs

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestBlobRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		wantHash string
		wantLen  int
		prefix   string
	}{
		{
			name:     "empty",
			size:     0,
			wantHash: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
			wantLen:  8,
			prefix:   "0000000000000000",
		},
		{
			name:     "block",
			size:     BlockSize,
			wantHash: "068b01a50d692c1311866eed3f5f3f6a4b78cddcd6e87cb43da863bccc1b93aa",
			wantLen:  8 + BlockSize,
			prefix:   "00400000000000000726456483a2c1e0ff1e3d5c7b9ab9d8f7",
		},
		{
			name:     "two blocks",
			size:     BlockSize + 1,
			wantHash: "447b6bc5f6d14c607c412e30fa5b8c1d56b7348a5b91dc43e49ca128fc0cb7be",
			wantLen:  8 + 64 + BlockSize + 1,
			prefix:   "01400000000000003567e4d2d9739de1ed1ed4fd89d7497eaabf1a38fd3850cd864ed96b5b6e28d8958978d8553c584c1a2142c6b4b44fbf4c45565aced69ec9811185cf500046a10726456483a2c1e0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := vectorData(tt.size)
			hash, encoded, err := EncodeBlob(data)
			if err != nil {
				t.Fatalf("EncodeBlob: %v", err)
			}
			if got := hash.String(); got != tt.wantHash {
				t.Fatalf("hash = %s, want %s", got, tt.wantHash)
			}
			if len(encoded) != tt.wantLen {
				t.Fatalf("encoded len = %d, want %d", len(encoded), tt.wantLen)
			}
			if got := hex.EncodeToString(encoded[:hex.DecodedLen(len(tt.prefix))]); got != strings.ToLower(tt.prefix) {
				t.Fatalf("encoded prefix = %s, want %s", got, tt.prefix)
			}
			got, err := DecodeBlob(hash, encoded)
			if err != nil {
				t.Fatalf("DecodeBlob: %v", err)
			}
			if string(got) != string(data) {
				t.Fatalf("DecodeBlob data mismatch")
			}
		})
	}
}

func TestBlobDecodeErrors(t *testing.T) {
	data := vectorData(BlockSize + 1)
	hash, encoded, err := EncodeBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), encoded...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := DecodeBlob(hash, corrupt); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DecodeBlob corrupt error = %v", err)
	}
	trailing := append(append([]byte(nil), encoded...), 0)
	if _, err := DecodeBlob(hash, trailing); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DecodeBlob trailing error = %v", err)
	}
	wrong := NewHash([]byte("wrong"))
	if _, err := DecodeBlob(wrong, encoded); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DecodeBlob wrong hash error = %v", err)
	}
}

func TestBlobRangeRoundTrip(t *testing.T) {
	data := vectorData(3*BlockSize + 321)
	tests := []struct {
		name   string
		offset uint64
		length uint64
	}{
		{name: "prefix", offset: 0, length: ChunkSize},
		{name: "middle", offset: ChunkSize + 17, length: 2*ChunkSize + 3},
		{name: "suffix", offset: 2 * BlockSize, length: uint64(len(data)) - 2*BlockSize},
		{name: "empty", offset: ChunkSize, length: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, encoded, err := EncodeBlobRange(data, tt.offset, tt.length)
			if err != nil {
				t.Fatalf("EncodeBlobRange: %v", err)
			}
			if hash != NewHash(data) {
				t.Fatalf("hash = %s, want %s", hash, NewHash(data))
			}
			got, err := DecodeBlobRange(hash, encoded, tt.offset, tt.length)
			if err != nil {
				t.Fatalf("DecodeBlobRange: %v", err)
			}
			want := data[tt.offset:][:tt.length]
			if !strings.EqualFold(hex.EncodeToString(got), hex.EncodeToString(want)) {
				t.Fatalf("DecodeBlobRange mismatch")
			}
		})
	}
}

func TestBlobRangeDecodeErrors(t *testing.T) {
	data := vectorData(2*BlockSize + 1)
	hash, encoded, err := EncodeBlobRange(data, ChunkSize, ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), encoded...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := DecodeBlobRange(hash, corrupt, ChunkSize, ChunkSize); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DecodeBlobRange corrupt error = %v", err)
	}
	trailing := append(append([]byte(nil), encoded...), 0)
	if _, err := DecodeBlobRange(hash, trailing, ChunkSize, ChunkSize); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DecodeBlobRange trailing error = %v", err)
	}
}

func TestSingleLeafRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "small", data: []byte("hello from iroh-blobs")},
		{name: "chunk", data: repeatByte(0xab, ChunkSize)},
		{name: "multi chunk block", data: repeatByte(0xcd, 2*ChunkSize+17)},
		{name: "block", data: repeatByte(0xef, BlockSize)},
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
	if _, _, err := EncodeSingleLeaf(repeatByte(0, BlockSize+1)); !errors.Is(err, ErrSingleLeafTooLarge) {
		t.Fatalf("EncodeSingleLeaf too large error = %v", err)
	}
	hash := NewHash([]byte("ok"))
	if _, err := DecodeSingleLeaf(hash, []byte{1, 2, 3}); !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("DecodeSingleLeaf truncated error = %v", err)
	}
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, BlockSize+1)
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

func vectorData(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}
