package key

import (
	"crypto/ed25519"
	"encoding/base32"
)

// verify is the regeneratable core of [PublicKey.Verify]. It performs strict
// Ed25519 verification, matching ed25519-dalek's verify_strict.
func (k PublicKey) verify(message []byte, sig Signature) error {
	if !ed25519.Verify(k.bytes[:], message, sig.bytes[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// sign is the regeneratable core of [SecretKey.Sign].
func (k SecretKey) sign(msg []byte) Signature {
	sig, _ := SignatureFromEd25519(ed25519.Sign(k.signing, msg))
	return sig
}

// stdBase32NoPad is RFC 4648 base32 without padding, used for the alternative
// (non-hex) string form of a key. Decoding upper-cases the input first.
var stdBase32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func decodeStdBase32NoPad(s string) ([]byte, error) {
	return stdBase32NoPad.DecodeString(s)
}

// zBase32 is the z-base-32 encoding (pkarr / human-oriented base32) used for
// endpoint-id domain names. It uses a custom alphabet and no padding.
var zBase32 = base32.NewEncoding(zBase32Alphabet).WithPadding(base32.NoPadding)

func encodeZBase32(b []byte) string { return zBase32.EncodeToString(b) }

func decodeZBase32(s string) ([]byte, error) { return zBase32.DecodeString(s) }
