package base

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
)

// PublicKeyLength is the length of an Ed25519 public key, in bytes.
const PublicKeyLength = ed25519.PublicKeySize // 32

// SecretKeyLength is the length of an Ed25519 secret key seed, in bytes.
const SecretKeyLength = ed25519.SeedSize // 32

// SignatureLength is the length of an Ed25519 signature, in bytes.
const SignatureLength = ed25519.SignatureSize // 64

// zBase32 is the z-base-32 encoding used by pkarr (https://pkarr.org) for
// endpoint-id domain names. Its alphabet differs from RFC 4648 base32.
const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// Errors returned when parsing keys.
var (
	// ErrInvalidKeyData is returned when bytes do not represent a valid
	// Ed25519 curve point.
	ErrInvalidKeyData = errors.New("data is not a valid public key")
	// ErrInvalidKeyLength is returned when key bytes have the wrong length.
	ErrInvalidKeyLength = errors.New("invalid length")
	// ErrDecodeHex is returned when a string cannot be decoded as hex.
	ErrDecodeHex = errors.New("failed to decode hex string")
	// ErrDecodeBase32 is returned when a string cannot be decoded as base32.
	ErrDecodeBase32 = errors.New("failed to decode base32 string")
)

// PublicKey is an Ed25519 public key. It is stored as the compressed Edwards y
// coordinate and is verified to decompress to a valid curve point when created.
//
// The zero value is not usable; construct a PublicKey with [NewPublicKey],
// [ParsePublicKey], or [SecretKey.Public].
type PublicKey struct {
	bytes [PublicKeyLength]byte
}

// EndpointId is the identifier for an endpoint in the iroh network.
//
// It is identical to [PublicKey]. By convention use PublicKey when performing
// cryptographic operations and EndpointId when referencing an endpoint.
type EndpointId = PublicKey

// NewPublicKey constructs a PublicKey from a 32-byte array. It returns
// [ErrInvalidKeyData] if the bytes do not decompress to a valid Ed25519 curve
// point. It never fails for bytes returned from [PublicKey.Bytes].
func NewPublicKey(b [PublicKeyLength]byte) (PublicKey, error) {
	if _, err := new(edwards25519.Point).SetBytes(b[:]); err != nil {
		return PublicKey{}, ErrInvalidKeyData
	}
	return PublicKey{bytes: b}, nil
}

// PublicKeyFromSlice constructs a PublicKey from a byte slice. It returns
// [ErrInvalidKeyLength] if the slice is not 32 bytes and [ErrInvalidKeyData] if
// the bytes are not a valid curve point.
func PublicKeyFromSlice(b []byte) (PublicKey, error) {
	if len(b) != PublicKeyLength {
		return PublicKey{}, ErrInvalidKeyLength
	}
	var arr [PublicKeyLength]byte
	copy(arr[:], b)
	return NewPublicKey(arr)
}

// Bytes returns the public key as a 32-byte array.
func (k PublicKey) Bytes() [PublicKeyLength]byte { return k.bytes }

// AsSlice returns the public key as a byte slice. The slice aliases the key's
// storage and must not be mutated.
func (k *PublicKey) AsSlice() []byte { return k.bytes[:] }

// Verify reports whether sig is a valid signature of message by k. It returns
// nil on success and [ErrInvalidSignature] otherwise.
//
// Verification uses crypto/ed25519 (cofactored, RFC 8032). The Rust reference
// uses ed25519-dalek's verify_strict (cofactorless). The two agree for every
// signature an honest iroh peer produces; they differ only for adversarially
// malleable signatures, which iroh drops anyway. This divergence is benign for
// iroh's drop-on-failure model (relay handshake, TLS raw-key, and pkarr packet
// verification all reject on failure).
func (k PublicKey) Verify(message []byte, sig Signature) error {
	return k.verify(message, sig)
}

// IsZero reports whether k is the unusable zero value.
func (k PublicKey) IsZero() bool { return k == PublicKey{} }

// Equal reports whether k and other are the same key.
func (k PublicKey) Equal(other PublicKey) bool { return k.bytes == other.bytes }

// Compare returns -1, 0, or +1 comparing k and other by their raw bytes. It
// gives PublicKey a total order suitable for sorting and map-free ordered use.
func (k PublicKey) Compare(other PublicKey) int {
	return bytes.Compare(k.bytes[:], other.bytes[:])
}

// edwardsPoint returns the public key as a stdlib ed25519.PublicKey.
func (k PublicKey) edwardsPoint() ed25519.PublicKey {
	return ed25519.PublicKey(k.bytes[:])
}

// String returns the lowercase-hex encoding of the key. It is the canonical
// human-readable form and round-trips through [ParsePublicKey].
func (k PublicKey) String() string {
	return hex.EncodeToString(k.bytes[:])
}

// Short returns a short, friendly hex string of the first 5 bytes of the key,
// for logging. It is not a complete or parseable representation.
func (k PublicKey) Short() string {
	return hex.EncodeToString(k.bytes[:5])
}

// Z32 encodes the key in z-base-32, the encoding used by pkarr domain names.
func (k PublicKey) Z32() string {
	return encodeZBase32(k.bytes[:])
}

// PublicKeyFromZ32 parses a key from its z-base-32 encoding.
func PublicKeyFromZ32(s string) (PublicKey, error) {
	b, err := decodeZBase32(s)
	if err != nil {
		return PublicKey{}, ErrDecodeBase32
	}
	return PublicKeyFromSlice(b)
}

// ParsePublicKey parses a PublicKey from its hex or base32 string form. A string
// of exactly 64 characters is decoded as lowercase hex; otherwise it is decoded
// as RFC 4648 base32 (no padding, case-insensitive). [PublicKey.String] always
// produces the hex form.
func ParsePublicKey(s string) (PublicKey, error) {
	b, err := decodeBase32OrHex(s)
	if err != nil {
		return PublicKey{}, err
	}
	return NewPublicKey(b)
}

// MarshalText implements encoding.TextMarshaler, producing the hex form.
func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, parsing the hex or base32
// form.
func (k *PublicKey) UnmarshalText(text []byte) error {
	parsed, err := ParsePublicKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler, producing the 32 raw bytes.
func (k PublicKey) MarshalBinary() ([]byte, error) {
	b := k.bytes
	return b[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from 32 raw bytes.
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	parsed, err := PublicKeyFromSlice(data)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// SecretKey is an Ed25519 secret key. Its public part can always be recovered.
//
// Go has no destructors, so unlike the Rust original this type is not zeroized
// on drop; callers handling long-lived secrets should clear the bytes returned
// by [SecretKey.Bytes] themselves.
//
// The zero value is not usable; construct with [GenerateSecretKey],
// [NewSecretKey], or [ParseSecretKey].
type SecretKey struct {
	signing ed25519.PrivateKey // 64 bytes: seed||public
}

// GenerateSecretKey generates a new SecretKey using crypto/rand.
func GenerateSecretKey() (SecretKey, error) {
	var seed [SecretKeyLength]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return SecretKey{}, fmt.Errorf("generate secret key: %w", err)
	}
	return NewSecretKey(seed), nil
}

// NewSecretKey constructs a SecretKey from its 32-byte seed.
func NewSecretKey(seed [SecretKeyLength]byte) SecretKey {
	return SecretKey{signing: ed25519.NewKeyFromSeed(seed[:])}
}

// SecretKeyFromSlice constructs a SecretKey from a 32-byte seed slice. It
// returns [ErrInvalidKeyLength] if the slice is not 32 bytes.
func SecretKeyFromSlice(b []byte) (SecretKey, error) {
	if len(b) != SecretKeyLength {
		return SecretKey{}, ErrInvalidKeyLength
	}
	var seed [SecretKeyLength]byte
	copy(seed[:], b)
	return NewSecretKey(seed), nil
}

// ParseSecretKey parses a SecretKey from its hex or base32 string form, matching
// the rules of [ParsePublicKey].
func ParseSecretKey(s string) (SecretKey, error) {
	b, err := decodeBase32OrHex(s)
	if err != nil {
		return SecretKey{}, err
	}
	return NewSecretKey(b), nil
}

// Public returns the public key of this secret key.
func (k SecretKey) Public() PublicKey {
	var arr [PublicKeyLength]byte
	copy(arr[:], k.signing.Public().(ed25519.PublicKey))
	// Safe: a key derived from a valid seed is always a valid curve point.
	return PublicKey{bytes: arr}
}

// Sign signs msg and returns the signature.
func (k SecretKey) Sign(msg []byte) Signature {
	return k.sign(msg)
}

// Bytes returns the 32-byte seed of the secret key. The public part can be
// recovered from it.
func (k SecretKey) Bytes() [SecretKeyLength]byte {
	var seed [SecretKeyLength]byte
	copy(seed[:], k.signing.Seed())
	return seed
}

// IsZero reports whether k is the unusable zero value.
func (k SecretKey) IsZero() bool { return k.signing == nil }

// MarshalBinary implements encoding.BinaryMarshaler, producing the 32-byte seed.
func (k SecretKey) MarshalBinary() ([]byte, error) {
	seed := k.Bytes()
	return seed[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from a 32-byte seed.
func (k *SecretKey) UnmarshalBinary(data []byte) error {
	parsed, err := SecretKeyFromSlice(data)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// Signature is an Ed25519 signature.
type Signature struct {
	bytes [SignatureLength]byte
}

// NewSignature constructs a Signature from its 64 raw bytes.
func NewSignature(b [SignatureLength]byte) Signature {
	return Signature{bytes: b}
}

// SignatureFromSlice constructs a Signature from a byte slice. It returns
// [ErrInvalidSignatureParse] if the slice is not 64 bytes.
func SignatureFromSlice(b []byte) (Signature, error) {
	if len(b) != SignatureLength {
		return Signature{}, ErrInvalidSignatureParse
	}
	var arr [SignatureLength]byte
	copy(arr[:], b)
	return Signature{bytes: arr}, nil
}

// Bytes returns the signature as a 64-byte array.
func (s Signature) Bytes() [SignatureLength]byte { return s.bytes }

// String returns the lowercase-hex encoding of the signature.
func (s Signature) String() string { return hex.EncodeToString(s.bytes[:]) }

// Equal reports whether s and other are the same signature.
func (s Signature) Equal(other Signature) bool { return s.bytes == other.bytes }

// Signature parsing and verification errors.
var (
	// ErrInvalidSignatureParse is returned when bytes cannot be parsed as an
	// Ed25519 signature.
	ErrInvalidSignatureParse = errors.New("could not parse ed25519 signature")
	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
)

// decodeBase32OrHex decodes a 32-byte value from a key's string form: 64-char
// strings are lowercase hex, others are RFC 4648 base32 (no padding).
func decodeBase32OrHex(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) == PublicKeyLength*2 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return out, ErrDecodeHex
		}
		copy(out[:], b)
		return out, nil
	}
	b, err := decodeStdBase32NoPad(strings.ToUpper(s))
	if err != nil {
		return out, ErrDecodeBase32
	}
	if len(b) != PublicKeyLength {
		return out, ErrInvalidKeyLength
	}
	copy(out[:], b)
	return out, nil
}
