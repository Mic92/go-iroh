package pkarr

import (
	internalpkarr "github.com/tmc/go-iroh/internal/pkarr"
	"github.com/tmc/go-iroh/key"
)

type (
	SignedPacket = internalpkarr.SignedPacket
	Timestamp    = internalpkarr.Timestamp
)

var (
	ErrPacketTooLarge = internalpkarr.ErrPacketTooLarge
	ErrTooShort       = internalpkarr.ErrTooShort
	ErrTooLarge       = internalpkarr.ErrTooLarge
	ErrSignature      = internalpkarr.ErrSignature
	ErrDNS            = internalpkarr.ErrDNS
	ErrInvalidKey     = internalpkarr.ErrInvalidKey
)

// FromTxtStrings creates a signed packet containing TXT records.
func FromTxtStrings(sk key.SecretKey, name string, values []string, ttl uint32) (*SignedPacket, error) {
	return internalpkarr.FromTxtStrings(sk, name, values, ttl)
}

// FromBytes parses and verifies a signed packet from its wire representation.
func FromBytes(b []byte) (*SignedPacket, error) { return internalpkarr.FromBytes(b) }

// FromBytesUnchecked parses a signed packet without verifying its signature.
func FromBytesUnchecked(b []byte) (*SignedPacket, error) {
	return internalpkarr.FromBytesUnchecked(b)
}

// FromRelayPayload reconstructs a signed packet from a public key and relay payload.
func FromRelayPayload(pub key.PublicKey, payload []byte) (*SignedPacket, error) {
	return internalpkarr.FromRelayPayload(pub, payload)
}

// Now returns a strictly monotonic timestamp.
func Now() Timestamp { return internalpkarr.Now() }

// TimestampFromMicros returns a timestamp from microseconds since the UNIX epoch.
func TimestampFromMicros(micros uint64) Timestamp {
	return internalpkarr.TimestampFromMicros(micros)
}
