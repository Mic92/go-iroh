package docs

import (
	"encoding/hex"
	"fmt"

	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/key"
)

// ALPN is the Rust iroh-docs sync protocol name.
const ALPN = "/iroh-sync/1"

// Author is a secret author key used to sign document entries.
type Author struct {
	key key.SecretKey
}

// NewAuthor returns an Author from a 32-byte secret seed.
func NewAuthor(seed [32]byte) Author {
	return Author{key: key.NewSecretKey(seed)}
}

// GenerateAuthor generates a random Author.
func GenerateAuthor() (Author, error) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		return Author{}, err
	}
	return Author{key: sk}, nil
}

// Bytes returns the 32-byte secret seed.
func (a Author) Bytes() [32]byte { return a.key.Bytes() }

// ID returns the public author identifier.
func (a Author) ID() AuthorID { return AuthorID{id: a.key.Public().EndpointID()} }

// Sign signs msg with the author key.
func (a Author) Sign(msg []byte) key.Signature { return a.key.Sign(msg) }

// String returns the lowercase hex secret seed.
func (a Author) String() string {
	b := a.Bytes()
	return hex.EncodeToString(b[:])
}

// EncodePostcard encodes a as Rust Author.
func (a Author) EncodePostcard(e *postcard.Encoder) error {
	b := a.Bytes()
	e.BytesValue(b[:])
	return nil
}

// DecodePostcard decodes a as Rust Author.
func (a *Author) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.BytesValue()
	if err != nil {
		return err
	}
	sk, err := key.SecretKeyFromSlice(b)
	if err != nil {
		return err
	}
	*a = Author{key: sk}
	return nil
}

// AuthorID identifies an Author.
type AuthorID struct {
	id key.EndpointID
}

// NewAuthorID constructs an AuthorID from raw public-key bytes.
func NewAuthorID(b [32]byte) (AuthorID, error) {
	id, err := key.NewEndpointID(b)
	if err != nil {
		return AuthorID{}, err
	}
	return AuthorID{id: id}, nil
}

// Bytes returns the 32-byte public key.
func (id AuthorID) Bytes() [32]byte { return id.id.Bytes() }

// EndpointID returns id as an iroh endpoint identifier.
func (id AuthorID) EndpointID() key.EndpointID { return id.id }

// Verify verifies sig over msg with id.
func (id AuthorID) Verify(msg []byte, sig key.Signature) error {
	return id.id.PublicKey().Verify(msg, sig)
}

// String returns the lowercase hex public key.
func (id AuthorID) String() string { return id.id.String() }

// EncodePostcard encodes id as Rust AuthorId.
func (id AuthorID) EncodePostcard(e *postcard.Encoder) error {
	b := id.Bytes()
	e.RawBytes(b[:])
	return nil
}

// DecodePostcard decodes id as Rust AuthorId.
func (id *AuthorID) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.RawBytes(32)
	if err != nil {
		return err
	}
	var raw [32]byte
	copy(raw[:], b)
	*id, err = NewAuthorID(raw)
	return err
}

// NamespaceSecret is a secret namespace key. Holders can write document
// entries in the namespace.
type NamespaceSecret struct {
	key key.SecretKey
}

// NewNamespaceSecret returns a NamespaceSecret from a 32-byte secret seed.
func NewNamespaceSecret(seed [32]byte) NamespaceSecret {
	return NamespaceSecret{key: key.NewSecretKey(seed)}
}

// GenerateNamespaceSecret generates a random NamespaceSecret.
func GenerateNamespaceSecret() (NamespaceSecret, error) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		return NamespaceSecret{}, err
	}
	return NamespaceSecret{key: sk}, nil
}

// Bytes returns the 32-byte secret seed.
func (s NamespaceSecret) Bytes() [32]byte { return s.key.Bytes() }

// ID returns the public namespace identifier.
func (s NamespaceSecret) ID() NamespaceID { return NamespaceID{id: s.key.Public().EndpointID()} }

// Sign signs msg with the namespace key.
func (s NamespaceSecret) Sign(msg []byte) key.Signature { return s.key.Sign(msg) }

// String returns the lowercase hex secret seed.
func (s NamespaceSecret) String() string {
	b := s.Bytes()
	return hex.EncodeToString(b[:])
}

// EncodePostcard encodes s as Rust NamespaceSecret.
func (s NamespaceSecret) EncodePostcard(e *postcard.Encoder) error {
	b := s.Bytes()
	e.BytesValue(b[:])
	return nil
}

// DecodePostcard decodes s as Rust NamespaceSecret.
func (s *NamespaceSecret) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.BytesValue()
	if err != nil {
		return err
	}
	sk, err := key.SecretKeyFromSlice(b)
	if err != nil {
		return err
	}
	*s = NamespaceSecret{key: sk}
	return nil
}

// NamespaceID identifies a document namespace.
type NamespaceID struct {
	id key.EndpointID
}

// NewNamespaceID constructs a NamespaceID from raw public-key bytes.
func NewNamespaceID(b [32]byte) (NamespaceID, error) {
	id, err := key.NewEndpointID(b)
	if err != nil {
		return NamespaceID{}, err
	}
	return NamespaceID{id: id}, nil
}

// MustNamespaceID constructs a NamespaceID or panics. It is intended for tests
// and package-level constants.
func MustNamespaceID(b [32]byte) NamespaceID {
	id, err := NewNamespaceID(b)
	if err != nil {
		panic(err)
	}
	return id
}

// Bytes returns the 32-byte public key.
func (id NamespaceID) Bytes() [32]byte { return id.id.Bytes() }

// EndpointID returns id as an iroh endpoint identifier.
func (id NamespaceID) EndpointID() key.EndpointID { return id.id }

// Verify verifies sig over msg with id.
func (id NamespaceID) Verify(msg []byte, sig key.Signature) error {
	return id.id.PublicKey().Verify(msg, sig)
}

// String returns the lowercase hex public key.
func (id NamespaceID) String() string { return id.id.String() }

// EncodePostcard encodes id as Rust NamespaceId.
func (id NamespaceID) EncodePostcard(e *postcard.Encoder) error {
	b := id.Bytes()
	e.RawBytes(b[:])
	return nil
}

// DecodePostcard decodes id as Rust NamespaceId.
func (id *NamespaceID) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.RawBytes(32)
	if err != nil {
		return err
	}
	var raw [32]byte
	copy(raw[:], b)
	*id, err = NewNamespaceID(raw)
	return err
}

// CapabilityKind identifies a document namespace capability.
type CapabilityKind uint8

const (
	// CapabilityWrite is a writable namespace capability.
	CapabilityWrite CapabilityKind = 1
	// CapabilityRead is a read-only namespace capability.
	CapabilityRead CapabilityKind = 2
)

// Capability is read or write access to a document namespace.
type Capability struct {
	kind   CapabilityKind
	secret NamespaceSecret
	id     NamespaceID
}

// NewWriteCapability returns a writable namespace capability.
func NewWriteCapability(secret NamespaceSecret) Capability {
	return Capability{kind: CapabilityWrite, secret: secret, id: secret.ID()}
}

// NewReadCapability returns a read-only namespace capability.
func NewReadCapability(id NamespaceID) Capability {
	return Capability{kind: CapabilityRead, id: id}
}

// Kind returns c's capability kind.
func (c Capability) Kind() CapabilityKind { return c.kind }

// NamespaceID returns the namespace id for c.
func (c Capability) NamespaceID() NamespaceID { return c.id }

// Secret returns the namespace secret and whether c is writable.
func (c Capability) Secret() (NamespaceSecret, bool) {
	if c.kind != CapabilityWrite {
		return NamespaceSecret{}, false
	}
	return c.secret, true
}

// Raw returns Rust's raw capability representation.
func (c Capability) Raw() (uint8, [32]byte) {
	switch c.kind {
	case CapabilityWrite:
		return uint8(CapabilityWrite), c.secret.Bytes()
	case CapabilityRead:
		return uint8(CapabilityRead), c.id.Bytes()
	default:
		return 0, [32]byte{}
	}
}

// CapabilityFromRaw constructs a Capability from Rust's raw representation.
func CapabilityFromRaw(kind uint8, b [32]byte) (Capability, error) {
	switch CapabilityKind(kind) {
	case CapabilityWrite:
		return NewWriteCapability(NewNamespaceSecret(b)), nil
	case CapabilityRead:
		id, err := NewNamespaceID(b)
		if err != nil {
			return Capability{}, err
		}
		return NewReadCapability(id), nil
	default:
		return Capability{}, fmt.Errorf("docs: unknown capability kind %d", kind)
	}
}
