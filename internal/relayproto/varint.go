package relayproto

import "errors"

// errVarintEnd is returned when a buffer is too short to hold a varint.
var errVarintEnd = errors.New("relayproto: unexpected end decoding varint")

// QUIC variable-length integers per RFC 9000 §16: the two most-significant bits
// of the first byte select a 1/2/4/8-byte length (prefixes 0b00/01/10/11).

// varintLen returns the number of bytes needed to encode v as a QUIC varint.
func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	case v < 1<<62:
		return 8
	default:
		panic("relayproto: varint too large")
	}
}

// appendVarint appends v to dst as a QUIC varint.
func appendVarint(dst []byte, v uint64) []byte {
	switch varintLen(v) {
	case 1:
		return append(dst, byte(v))
	case 2:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case 4:
		return append(dst,
			byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default: // 8
		return append(dst,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readVarint reads a QUIC varint from the front of buf, returning the value and
// the remaining bytes.
func readVarint(buf []byte) (uint64, []byte, error) {
	if len(buf) == 0 {
		return 0, nil, errVarintEnd
	}
	prefix := buf[0] >> 6
	n := 1 << prefix // 1, 2, 4, or 8 bytes
	if len(buf) < n {
		return 0, nil, errVarintEnd
	}
	v := uint64(buf[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(buf[i])
	}
	return v, buf[n:], nil
}

// postcard uses LEB128 (unsigned little-endian base-128) varints for lengths and
// integers, which is a different encoding from the QUIC varints above. The relay
// datagram framing uses QUIC varints (for frame types); the handshake frame
// bodies are postcard, so their length prefixes use these.

// appendPostcardVarint appends v to dst as a postcard/LEB128 varint.
func appendPostcardVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// readPostcardVarint reads a postcard/LEB128 varint from the front of buf.
func readPostcardVarint(buf []byte) (uint64, []byte, error) {
	var v uint64
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, buf[i+1:], nil
		}
		if i >= 9 {
			break
		}
	}
	return 0, nil, errVarintEnd
}

// EcnCodepoint is the QUIC explicit-congestion-notification codepoint carried in
// a relayed datagram (RFC 9000 §13.4 / IP ECN field values).
type EcnCodepoint uint8

const (
	// EcnEct1 is ECT(1).
	EcnEct1 EcnCodepoint = 1
	// EcnEct0 is ECT(0).
	EcnEct0 EcnCodepoint = 2
	// EcnCe is CE (congestion experienced).
	EcnCe EcnCodepoint = 3
)

// ecnFromBits returns the EcnCodepoint for the low two bits of b, or (0, false)
// for Not-ECT.
func ecnFromBits(b uint8) (EcnCodepoint, bool) {
	switch b & 0b11 {
	case 1:
		return EcnEct1, true
	case 2:
		return EcnEct0, true
	case 3:
		return EcnCe, true
	default:
		return 0, false
	}
}
