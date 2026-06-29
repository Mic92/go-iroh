package blobs

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"lukechampine.com/blake3"
)

// HashSize is the size of a blob hash, in bytes.
const HashSize = 32

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// Hash is a BLAKE3 hash used by iroh-blobs.
type Hash [HashSize]byte

// EmptyHash is the BLAKE3 hash of the empty byte string.
var EmptyHash = Hash{
	175, 19, 73, 185, 245, 249, 161, 166, 160, 64, 77, 234, 54, 220, 201, 73,
	155, 203, 37, 201, 173, 193, 18, 183, 204, 154, 147, 202, 228, 31, 50, 98,
}

// NewHash returns the BLAKE3 hash of b.
func NewHash(b []byte) Hash {
	sum := blake3.Sum256(b)
	return Hash(sum)
}

// HashFromBytes returns the hash represented by b.
func HashFromBytes(b [HashSize]byte) Hash { return Hash(b) }

// ParseHash parses s as lowercase hex or RFC 4648 base32 without padding.
func ParseHash(s string) (Hash, error) {
	var out Hash
	var (
		b   []byte
		err error
	)
	if len(s) == hex.EncodedLen(HashSize) {
		b, err = hex.DecodeString(s)
	} else {
		b, err = base32NoPad.DecodeString(strings.ToUpper(s))
	}
	if err != nil {
		return Hash{}, err
	}
	if len(b) != HashSize {
		return Hash{}, fmt.Errorf("blob hash: invalid length %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// Bytes returns h as a byte array.
func (h Hash) Bytes() [HashSize]byte { return [HashSize]byte(h) }

// String returns h as lowercase hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// Short returns the first five bytes of h as lowercase hex.
func (h Hash) Short() string { return hex.EncodeToString(h[:5]) }

// MarshalText implements encoding.TextMarshaler.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(text []byte) error {
	parsed, err := ParseHash(string(text))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

// BlobFormat identifies the format of a blob root.
type BlobFormat uint64

const (
	// Raw is a single raw blob.
	Raw BlobFormat = iota
	// HashSeq is a sequence of BLAKE3 hashes.
	HashSeq
)

// IsRaw reports whether f is Raw.
func (f BlobFormat) IsRaw() bool { return f == Raw }

// IsHashSeq reports whether f is HashSeq.
func (f BlobFormat) IsHashSeq() bool { return f == HashSeq }

func (f BlobFormat) String() string {
	switch f {
	case Raw:
		return "Raw"
	case HashSeq:
		return "HashSeq"
	default:
		return fmt.Sprintf("BlobFormat(%d)", f)
	}
}

// HashAndFormat is a hash with its blob format.
type HashAndFormat struct {
	Hash   Hash
	Format BlobFormat
}

// RawHash returns h as a raw blob hash.
func RawHash(h Hash) HashAndFormat { return HashAndFormat{Hash: h, Format: Raw} }

// HashSeqHash returns h as a hash sequence root.
func HashSeqHash(h Hash) HashAndFormat { return HashAndFormat{Hash: h, Format: HashSeq} }

func verifyFormat(f uint64) (BlobFormat, error) {
	switch BlobFormat(f) {
	case Raw, HashSeq:
		return BlobFormat(f), nil
	default:
		return 0, errors.New("unknown blob format")
	}
}
