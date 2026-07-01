package relayproto

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/key"
	"lukechampine.com/blake3"
)

// domainSepChallenge is the blake3 derive-key context for the challenge
// signature, matching iroh-relay/src/protos/handshake.rs.
const domainSepChallenge = "iroh-relay handshake v1 challenge signature"

// ClientAuthHeader is the HTTP header carrying TLS key-material relay auth.
const ClientAuthHeader = "x-iroh-relay-client-auth-v1"

const domainSepTLSExportLabel = "iroh-relay handshake v1"

// Handshake errors.
var (
	ErrServerDeniedAuth   = errors.New("relayproto: the relay denied authentication")
	ErrSignatureInvalid   = errors.New("relayproto: client signature invalid")
	ErrHandshakeDeserial  = errors.New("relayproto: handshake frame deserialization failed")
	ErrUnexpectedFrameTag = errors.New("relayproto: unexpected handshake frame type")
	ErrNoKeyingMaterial   = errors.New("relayproto: no TLS keying material")
	ErrKeyMaterialSuffix  = errors.New("relayproto: TLS keying material suffix mismatch")
)

// ServerChallenge is the challenge a relay sends a client to sign for endpoint
// authentication.
type ServerChallenge struct {
	// Challenge is 16 random bytes the client must sign.
	Challenge [16]byte
}

// messageToSign derives the actual 32-byte message signed for this challenge.
// The client signs a derived key rather than the challenge directly, for domain
// separation (see the Rust source for the rationale).
func (c ServerChallenge) messageToSign() [32]byte {
	var out [32]byte
	blake3.DeriveKey(out[:], domainSepChallenge, c.Challenge[:])
	return out
}

// AppendTo appends the framed wire encoding (frame type + postcard body) of c.
func (c ServerChallenge) AppendTo(dst []byte) []byte {
	dst = writeFrameType(dst, FrameServerChallenge)
	return append(dst, c.Challenge[:]...) // [u8;16]: 16 raw bytes, no length prefix
}

// ClientAuth is the client's authentication response: its public key and a
// signature of the challenge's message-to-sign.
type ClientAuth struct {
	PublicKey key.PublicKey
	Signature key.Signature
}

// KeyMaterialClientAuth is the client's 1-RTT relay authentication. It is sent
// in [ClientAuthHeader] as base64url-no-pad postcard bytes.
type KeyMaterialClientAuth struct {
	PublicKey         key.PublicKey
	Signature         key.Signature
	KeyMaterialSuffix [16]byte
}

// NewClientAuth builds a ClientAuth for challenge using secretKey.
func NewClientAuth(secretKey key.SecretKey, challenge ServerChallenge) ClientAuth {
	msg := challenge.messageToSign()
	return ClientAuth{
		PublicKey: secretKey.Public(),
		Signature: secretKey.Sign(msg[:]),
	}
}

// Verify checks this client auth against the challenge it answers.
func (a ClientAuth) Verify(challenge ServerChallenge) error {
	msg := challenge.messageToSign()
	if err := a.PublicKey.Verify(msg[:], a.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// NewKeyMaterialClientAuth builds a client auth header value from exported TLS
// keying material. It returns [ErrNoKeyingMaterial] if state cannot export it.
func NewKeyMaterialClientAuth(secretKey key.SecretKey, state *tls.ConnectionState) (KeyMaterialClientAuth, error) {
	if state == nil {
		return KeyMaterialClientAuth{}, ErrNoKeyingMaterial
	}
	publicKey := secretKey.Public()
	pk := publicKey.Bytes()
	keyMaterial, err := state.ExportKeyingMaterial(domainSepTLSExportLabel, pk[:], 32)
	if err != nil {
		return KeyMaterialClientAuth{}, fmt.Errorf("%w: %v", ErrNoKeyingMaterial, err)
	}
	auth := KeyMaterialClientAuth{
		PublicKey: publicKey,
		Signature: secretKey.Sign(keyMaterial[:16]),
	}
	copy(auth.KeyMaterialSuffix[:], keyMaterial[16:])
	return auth, nil
}

// KeyMaterialClientAuthFromHeader decodes a value from [ClientAuthHeader].
func KeyMaterialClientAuthFromHeader(value string) (KeyMaterialClientAuth, error) {
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return KeyMaterialClientAuth{}, fmt.Errorf("%w: %v", ErrHandshakeDeserial, err)
	}
	var auth KeyMaterialClientAuth
	if err := postcard.Unmarshal(b, &auth); err != nil {
		return KeyMaterialClientAuth{}, fmt.Errorf("%w: %v", ErrHandshakeDeserial, err)
	}
	return auth, nil
}

// HeaderValue encodes a for [ClientAuthHeader].
func (a KeyMaterialClientAuth) HeaderValue() (string, error) {
	b, err := postcard.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("relayproto: encode key-material auth: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Verify checks this key-material auth against the server's TLS state.
func (a KeyMaterialClientAuth) Verify(state *tls.ConnectionState) error {
	if state == nil {
		return ErrNoKeyingMaterial
	}
	pk := a.PublicKey.Bytes()
	keyMaterial, err := state.ExportKeyingMaterial(domainSepTLSExportLabel, pk[:], 32)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoKeyingMaterial, err)
	}
	if !bytes.Equal(keyMaterial[16:], a.KeyMaterialSuffix[:]) {
		return ErrKeyMaterialSuffix
	}
	if err := a.PublicKey.Verify(keyMaterial[:16], a.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

// EncodePostcard encodes a like Rust KeyMaterialClientAuth: raw public key,
// serde_bytes signature, then raw 16-byte suffix.
func (a KeyMaterialClientAuth) EncodePostcard(e *postcard.Encoder) error {
	pk := a.PublicKey.Bytes()
	e.RawBytes(pk[:])
	sig := a.Signature.Bytes()
	e.BytesValue(sig[:])
	e.RawBytes(a.KeyMaterialSuffix[:])
	return nil
}

// DecodePostcard decodes a Rust KeyMaterialClientAuth.
func (a *KeyMaterialClientAuth) DecodePostcard(d *postcard.Decoder) error {
	pkBytes, err := d.RawBytes(key.PublicKeySize)
	if err != nil {
		return err
	}
	pk, err := key.PublicKeyFromSlice(pkBytes)
	if err != nil {
		return err
	}
	sigBytes, err := d.BytesValue()
	if err != nil {
		return err
	}
	sig, err := key.SignatureFromSlice(sigBytes)
	if err != nil {
		return err
	}
	suffix, err := d.RawBytes(16)
	if err != nil {
		return err
	}
	a.PublicKey = pk
	a.Signature = sig
	copy(a.KeyMaterialSuffix[:], suffix)
	return nil
}

// AppendTo appends the framed wire encoding of a: frame type, the public key's
// 32 raw bytes, then the signature as a postcard serde_bytes value (varint
// length 64 followed by the 64 bytes).
func (a ClientAuth) AppendTo(dst []byte) []byte {
	dst = writeFrameType(dst, FrameClientAuth)
	pk := a.PublicKey.Bytes()
	dst = append(dst, pk[:]...) // PublicKey: 32 raw bytes (non-human-readable serde)
	sig := a.Signature.Bytes()
	dst = appendPostcardVarint(dst, uint64(len(sig))) // serde_bytes: postcard length prefix
	return append(dst, sig[:]...)
}

// ServerConfirmsAuth confirms a successful connection. Its postcard body is empty.
type ServerConfirmsAuth struct{}

// AppendTo appends the framed wire encoding of the (empty-bodied) confirmation.
func (ServerConfirmsAuth) AppendTo(dst []byte) []byte {
	return writeFrameType(dst, FrameServerConfirmsAuth)
}

// ServerDeniesAuth denies a connection with a reason.
type ServerDeniesAuth struct {
	Reason string
}

// AppendTo appends the framed wire encoding: frame type then the reason as a
// postcard string (varint byte-length prefix + UTF-8 bytes).
func (d ServerDeniesAuth) AppendTo(dst []byte) []byte {
	dst = writeFrameType(dst, FrameServerDeniesAuth)
	dst = appendPostcardVarint(dst, uint64(len(d.Reason)))
	return append(dst, d.Reason...)
}

// ParseHandshakeFrame parses one handshake frame from content (frame type +
// postcard body) into the concrete frame value, returning the value as one of
// *ServerChallenge, *ClientAuth, *ServerConfirmsAuth, or *ServerDeniesAuth.
func ParseHandshakeFrame(content []byte) (any, error) {
	ft, body, err := readFrameType(content)
	if err != nil {
		return nil, err
	}
	switch ft {
	case FrameServerChallenge:
		if len(body) != 16 {
			return nil, ErrHandshakeDeserial
		}
		var c ServerChallenge
		copy(c.Challenge[:], body)
		return &c, nil
	case FrameClientAuth:
		if len(body) < key.PublicKeySize {
			return nil, ErrHandshakeDeserial
		}
		pk, err := key.PublicKeyFromSlice(body[:key.PublicKeySize])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeDeserial, err)
		}
		body = body[key.PublicKeySize:]
		n, rest, err := readPostcardVarint(body)
		if err != nil || n != uint64(key.SignatureSize) || len(rest) != key.SignatureSize {
			return nil, ErrHandshakeDeserial
		}
		sig, err := key.SignatureFromSlice(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeDeserial, err)
		}
		return &ClientAuth{PublicKey: pk, Signature: sig}, nil
	case FrameServerConfirmsAuth:
		return &ServerConfirmsAuth{}, nil
	case FrameServerDeniesAuth:
		n, rest, err := readPostcardVarint(body)
		if err != nil || n != uint64(len(rest)) {
			return nil, ErrHandshakeDeserial
		}
		return &ServerDeniesAuth{Reason: string(rest)}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnexpectedFrameTag, ft)
	}
}
