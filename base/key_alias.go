package base

import "github.com/tmc/go-iroh/key"

const (
	// PublicKeyLength is the length of an Ed25519 public key, in bytes.
	//
	// Deprecated: use [key.PublicKeyLength].
	PublicKeyLength = key.PublicKeyLength
	// SecretKeyLength is the length of an Ed25519 secret key seed, in bytes.
	//
	// Deprecated: use [key.SecretKeyLength].
	SecretKeyLength = key.SecretKeyLength
	// SignatureLength is the length of an Ed25519 signature, in bytes.
	//
	// Deprecated: use [key.SignatureLength].
	SignatureLength = key.SignatureLength
)

var (
	// ErrInvalidKeyData is returned when bytes do not represent a valid
	// Ed25519 curve point.
	//
	// Deprecated: use [key.ErrInvalidKeyData].
	ErrInvalidKeyData = key.ErrInvalidKeyData
	// ErrInvalidKeyLength is returned when key bytes have the wrong length.
	//
	// Deprecated: use [key.ErrInvalidKeyLength].
	ErrInvalidKeyLength = key.ErrInvalidKeyLength
	// ErrDecodeHex is returned when a string cannot be decoded as hex.
	//
	// Deprecated: use [key.ErrDecodeHex].
	ErrDecodeHex = key.ErrDecodeHex
	// ErrDecodeBase32 is returned when a string cannot be decoded as base32.
	//
	// Deprecated: use [key.ErrDecodeBase32].
	ErrDecodeBase32 = key.ErrDecodeBase32
	// ErrInvalidSignatureParse is returned when bytes cannot be parsed as an
	// Ed25519 signature.
	//
	// Deprecated: use [key.ErrInvalidSignatureParse].
	ErrInvalidSignatureParse = key.ErrInvalidSignatureParse
	// ErrInvalidSignature is returned when signature verification fails.
	//
	// Deprecated: use [key.ErrInvalidSignature].
	ErrInvalidSignature = key.ErrInvalidSignature
)

// PublicKey is an Ed25519 public key.
//
// Deprecated: use [key.PublicKey].
type PublicKey = key.PublicKey

// EndpointId is the identifier for an endpoint in the iroh network.
//
// Deprecated: use [key.EndpointId].
type EndpointId = key.EndpointId

// SecretKey is an Ed25519 secret key.
//
// Deprecated: use [key.SecretKey].
type SecretKey = key.SecretKey

// Signature is an Ed25519 signature.
//
// Deprecated: use [key.Signature].
type Signature = key.Signature

// NewPublicKey constructs a PublicKey from a 32-byte array.
//
// Deprecated: use [key.NewPublicKey].
func NewPublicKey(b [PublicKeyLength]byte) (PublicKey, error) { return key.NewPublicKey(b) }

// PublicKeyFromSlice constructs a PublicKey from a byte slice.
//
// Deprecated: use [key.PublicKeyFromSlice].
func PublicKeyFromSlice(b []byte) (PublicKey, error) { return key.PublicKeyFromSlice(b) }

// PublicKeyFromZ32 parses a key from its z-base-32 encoding.
//
// Deprecated: use [key.PublicKeyFromZ32].
func PublicKeyFromZ32(s string) (PublicKey, error) { return key.PublicKeyFromZ32(s) }

// ParsePublicKey parses a PublicKey from its hex or base32 string form.
//
// Deprecated: use [key.ParsePublicKey].
func ParsePublicKey(s string) (PublicKey, error) { return key.ParsePublicKey(s) }

// GenerateSecretKey generates a new SecretKey using crypto/rand.
//
// Deprecated: use [key.GenerateSecretKey].
func GenerateSecretKey() (SecretKey, error) { return key.GenerateSecretKey() }

// NewSecretKey constructs a SecretKey from its 32-byte seed.
//
// Deprecated: use [key.NewSecretKey].
func NewSecretKey(seed [SecretKeyLength]byte) SecretKey { return key.NewSecretKey(seed) }

// SecretKeyFromSlice constructs a SecretKey from a 32-byte seed slice.
//
// Deprecated: use [key.SecretKeyFromSlice].
func SecretKeyFromSlice(b []byte) (SecretKey, error) { return key.SecretKeyFromSlice(b) }

// ParseSecretKey parses a SecretKey from its hex or base32 string form.
//
// Deprecated: use [key.ParseSecretKey].
func ParseSecretKey(s string) (SecretKey, error) { return key.ParseSecretKey(s) }

// NewSignature constructs a Signature from its 64 raw bytes.
//
// Deprecated: use [key.NewSignature].
func NewSignature(b [SignatureLength]byte) Signature { return key.NewSignature(b) }

// SignatureFromSlice constructs a Signature from a byte slice.
//
// Deprecated: use [key.SignatureFromSlice].
func SignatureFromSlice(b []byte) (Signature, error) { return key.SignatureFromSlice(b) }
