// Package pkarr implements the pkarr (https://pkarr.org) signed DNS packet
// format used by iroh for endpoint discovery.
//
// Wire format: <32-byte public key><64-byte signature><8-byte big-endian
// microsecond timestamp><DNS wire packet>. The signature covers the BEP-0044
// signable bytes derived from the timestamp and the encoded DNS packet. The DNS
// packet must be at most 1000 bytes; the total signed packet is at most 1104.
//
// It is a port of iroh-dns/src/pkarr.rs.
package pkarr

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/key"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// maxDNSPacketSize is the maximum size of the encoded DNS packet within a
	// signed packet.
	maxDNSPacketSize = 1000
	// headerSize is 32 (public key) + 64 (signature) + 8 (timestamp).
	headerSize = 104
	// MaxBytes is the maximum total size of a serialized signed packet.
	MaxBytes = headerSize + maxDNSPacketSize
)

// Errors returned by this package.
var (
	ErrPacketTooLarge = errors.New("pkarr: DNS packet too large")
	ErrTooShort       = errors.New("pkarr: signed packet too short")
	ErrTooLarge       = errors.New("pkarr: signed packet too large")
	ErrSignature      = errors.New("pkarr: invalid signature")
	ErrDNS            = errors.New("pkarr: DNS decoding error")
	ErrInvalidKey     = errors.New("pkarr: invalid public key")
)

// SignedPacket is a signed DNS packet in the pkarr format. It is immutable; all
// accessors derive their result from the stored wire bytes.
type SignedPacket struct {
	bytes []byte
}

// FromTxtStrings creates a signed packet containing one TXT record per value,
// all under the single DNS name relative to the signer's z-base-32 public key
// (the common case, e.g. name "_iroh"). ttl is the record TTL in seconds.
func FromTxtStrings(sk key.SecretKey, name string, values []string, ttl uint32) (*SignedPacket, error) {
	pub := sk.Public()
	origin := pub.EndpointID().Z32()
	normalized := normalizeName(origin, name)

	encoded, err := buildTxtPacket(normalized, values, ttl)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDNS, err)
	}
	if len(encoded) > maxDNSPacketSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrPacketTooLarge, len(encoded), maxDNSPacketSize)
	}

	ts := Now()
	sig := sk.Sign(signable(ts.Micros(), encoded))

	pubBytes := pub.Bytes()
	sigBytes := sig.Bytes()
	out := make([]byte, 0, headerSize+len(encoded))
	out = append(out, pubBytes[:]...)
	out = append(out, sigBytes[:]...)
	out = append(out, ts.beBytes()...)
	out = append(out, encoded...)
	return &SignedPacket{bytes: out}, nil
}

// FromBytes parses and verifies a signed packet from its wire representation.
func FromBytes(b []byte) (*SignedPacket, error) {
	if err := checkLen(b); err != nil {
		return nil, err
	}
	pub, err := key.PublicKeyFromSlice(b[:32])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	sig, err := key.SignatureFromSlice(b[32:96])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	var tsBytes [8]byte
	copy(tsBytes[:], b[96:104])
	ts := timestampFromBE(tsBytes)
	encoded := b[104:]

	if err := pub.Verify(signable(ts.Micros(), encoded), sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if _, err := parsePacket(encoded); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDNS, err)
	}
	return &SignedPacket{bytes: bytes.Clone(b)}, nil
}

// FromBytesUnchecked parses a signed packet without verifying its signature. It
// still validates the minimum length and that the DNS packet parses.
func FromBytesUnchecked(b []byte) (*SignedPacket, error) {
	if err := checkLen(b); err != nil {
		return nil, err
	}
	if _, err := parsePacket(b[104:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDNS, err)
	}
	return &SignedPacket{bytes: bytes.Clone(b)}, nil
}

// FromRelayPayload reconstructs a signed packet from a public key and a relay
// payload (signature + timestamp + DNS packet, i.e. everything after the key).
func FromRelayPayload(pub key.PublicKey, payload []byte) (*SignedPacket, error) {
	pubBytes := pub.Bytes()
	b := make([]byte, 0, 32+len(payload))
	b = append(b, pubBytes[:]...)
	b = append(b, payload...)
	return FromBytes(b)
}

// Bytes returns the full serialized wire bytes. The result must not be mutated.
func (p *SignedPacket) Bytes() []byte { return p.bytes }

// RelayPayload returns the relay payload: everything after the public key.
func (p *SignedPacket) RelayPayload() []byte { return bytes.Clone(p.bytes[32:]) }

// PublicKey returns the signer's public key.
func (p *SignedPacket) PublicKey() key.PublicKey {
	k, _ := key.PublicKeyFromSlice(p.bytes[:32])
	return k
}

// Signature returns the packet signature.
func (p *SignedPacket) Signature() key.Signature {
	s, _ := key.SignatureFromSlice(p.bytes[32:96])
	return s
}

// Timestamp returns the packet timestamp.
func (p *SignedPacket) Timestamp() Timestamp {
	var b [8]byte
	copy(b[:], p.bytes[96:104])
	return timestampFromBE(b)
}

// EncodedPacket returns the encoded DNS packet bytes.
func (p *SignedPacket) EncodedPacket() []byte { return p.bytes[104:] }

// MoreRecentThan reports whether p is more recent than other, breaking ties on
// equal timestamps by comparing the encoded DNS packets.
func (p *SignedPacket) MoreRecentThan(other *SignedPacket) bool {
	if p.Timestamp() == other.Timestamp() {
		return bytes.Compare(p.EncodedPacket(), other.EncodedPacket()) > 0
	}
	return p.Timestamp().Micros() > other.Timestamp().Micros()
}

// TxtRecords returns the TXT string values under the given DNS name (normalized
// relative to the signer's z-base-32 public key).
func (p *SignedPacket) TxtRecords(name string) []string {
	origin := p.PublicKey().EndpointID().Z32()
	normalized := normalizeName(origin, name)
	records, err := parsePacket(p.EncodedPacket())
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range records {
		rrName := strings.TrimSuffix(r.name, ".")
		if rrName == normalized {
			out = append(out, r.txt)
		} else if rel, ok := withoutZone(rrName, origin); ok && rel == strings.TrimSuffix(name, ".") {
			out = append(out, r.txt)
		}
	}
	return out
}

// AllTxtRecords returns all TXT records as (name-relative-to-origin, value) pairs.
func (p *SignedPacket) AllTxtRecords() [][2]string {
	origin := p.PublicKey().EndpointID().Z32()
	records, err := parsePacket(p.EncodedPacket())
	if err != nil {
		return nil
	}
	var out [][2]string
	for _, r := range records {
		rrName := strings.TrimSuffix(r.name, ".")
		rel, _ := withoutZone(rrName, origin)
		out = append(out, [2]string{rel, r.txt})
	}
	return out
}

func checkLen(b []byte) error {
	if len(b) < headerSize {
		return fmt.Errorf("%w: %d bytes (min %d)", ErrTooShort, len(b), headerSize)
	}
	if len(b) > MaxBytes {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrTooLarge, len(b), MaxBytes)
	}
	return nil
}

// signable constructs the BEP-0044 signable bytes: "3:seqi<ts>e1:v<len>:" + v.
func signable(timestamp uint64, v []byte) []byte {
	prefix := "3:seqi" + strconv.FormatUint(timestamp, 10) + "e1:v" + strconv.Itoa(len(v)) + ":"
	out := make([]byte, 0, len(prefix)+len(v))
	out = append(out, prefix...)
	out = append(out, v...)
	return out
}

// normalizeName normalizes a DNS name relative to the pkarr origin (the
// z-base-32 public key). A trailing dot is stripped first.
func normalizeName(origin, name string) string {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	last := ""
	if len(parts) > 0 {
		last = parts[len(parts)-1]
	}
	if last == origin {
		return name
	}
	if last == "@" || last == "" {
		return origin
	}
	return name + "." + origin
}

// withoutZone strips a trailing ".<origin>" (or exactly "<origin>") from name,
// returning the relative part and whether name was within the zone.
func withoutZone(name, origin string) (string, bool) {
	if name == origin {
		return "", true
	}
	if suffix := "." + origin; strings.HasSuffix(name, suffix) {
		return strings.TrimSuffix(name, suffix), true
	}
	return name, false
}

// Timestamp is a pkarr timestamp in microseconds since the UNIX epoch.
type Timestamp uint64

// lastTimestamp tracks the last value returned by Now for strict monotonicity.
var lastTimestamp atomic.Uint64

// Now returns a strictly monotonic timestamp: greater than any previous call,
// even if the system clock moves backward.
func Now() Timestamp {
	micros := uint64(time.Now().UnixMicro())
	for {
		last := lastTimestamp.Load()
		next := micros
		if next <= last {
			next = last + 1
		}
		if lastTimestamp.CompareAndSwap(last, next) {
			return Timestamp(next)
		}
	}
}

// TimestampFromMicros creates a timestamp from a raw microseconds value.
func TimestampFromMicros(micros uint64) Timestamp { return Timestamp(micros) }

// Micros returns the raw microseconds value.
func (t Timestamp) Micros() uint64 { return uint64(t) }

func (t Timestamp) beBytes() []byte {
	var b [8]byte
	v := uint64(t)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b[:]
}

func timestampFromBE(b [8]byte) Timestamp {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return Timestamp(v)
}

// SignedPacketBuildError and SignedPacketVerifyError sentinel checks are exposed
// via errors.Is against the package error values above.

var _ = dnsmessage.TypeTXT
