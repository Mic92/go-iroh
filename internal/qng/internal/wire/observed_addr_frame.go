package wire

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// errInvalidObservedAddr is returned when an OBSERVED_ADDRESS frame body does
// not match its frame type's address family (a v4 frame must carry 4 address
// bytes, a v6 frame 16), matching the fixed-size reads in frame.rs
// ObservedAddr::read (n0ext/reference/frame.rs:2147-2156).
var errInvalidObservedAddr = errors.New("wire: malformed observed-address frame")

// This file holds the codec for the QUIC Address Discovery OBSERVED_ADDRESS
// frame (draft-seemann-quic-address-discovery), as used by iroh's noq QUIC
// fork. The wire layout mirrors internal/qng/n0ext/reference/frame.rs
// ObservedAddr (lines 2107-2178) byte-for-byte:
//
//	frame_type | seq_no (QUIC varint) | ip (4 bytes v4 / 16 bytes v6, raw) | port (u16 big-endian)
//
// The frame type selects the address family: ObservedIpv4Addr (0x9f81a6) or
// ObservedIpv6Addr (0x9f81a7) (frame.rs:100-103). Both type ids are multi-byte
// QUIC varints, so they are written with quicvarint.Append. OBSERVED_ADDRESS is
// a 1-RTT-only frame (frame.rs Frame::is_1rtt; see frame_type.go).

// An ObservedAddrFrame reports the source address a peer observed for the
// connection, so the recipient can learn its own reflexive (publicly observed)
// address. See frame.rs:2107-2178.
type ObservedAddrFrame struct {
	// SeqNo is a per-connection monotonically increasing sequence number
	// (frame.rs:2108-2109). The recipient keeps the report with the highest
	// SeqNo (paths.rs update_observed_addr_report).
	SeqNo uint64
	// Addr is the observed IP address. Its family (4 vs 16 bytes on the wire)
	// is determined by the frame type, matching get_type (frame.rs:2126-2132).
	Addr netip.Addr
	// Port is the observed UDP port.
	Port uint16
}

// frameType returns the OBSERVED_ADDRESS frame type for f's address family,
// mirroring ObservedAddr::get_type (frame.rs:2126-2132): a v6 address uses
// ObservedIpv6Addr, anything else ObservedIpv4Addr.
func (f *ObservedAddrFrame) frameType() FrameType {
	if f.Addr.Is6() {
		return FrameTypeObservedIPv6Addr
	}
	return FrameTypeObservedIPv4Addr
}

// parseObservedAddrFrame reads the OBSERVED_ADDRESS frame body (everything after
// the frame type). isIPv6 selects the address family, just as the Rust decoder
// dispatches on the frame type (frame.rs:1665-1668, ObservedAddr::read
// frame.rs:2147-2156): seq_no varint, then 4 or 16 raw address bytes, then a
// big-endian u16 port.
func parseObservedAddrFrame(b []byte, isIPv6 bool, _ protocol.Version) (*ObservedAddrFrame, int, error) {
	startLen := len(b)
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	var addr netip.Addr
	if isIPv6 {
		if len(b) < 16 {
			return nil, 0, errInvalidObservedAddr
		}
		addr = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
	} else {
		if len(b) < 4 {
			return nil, 0, errInvalidObservedAddr
		}
		addr = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
	}

	if len(b) < 2 {
		return nil, 0, errInvalidObservedAddr
	}
	port := binary.BigEndian.Uint16(b[:2])
	b = b[2:]

	return &ObservedAddrFrame{SeqNo: seq, Addr: addr, Port: port}, startLen - len(b), nil
}

// Append encodes f, mirroring the Encodable impl (frame.rs:2164-2178): frame
// type, seq_no varint, raw address bytes (4 for v4, 16 for v6), then the port as
// a big-endian u16.
func (f *ObservedAddrFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.frameType()))
	b = quicvarint.Append(b, f.SeqNo)
	if f.Addr.Is6() {
		v6 := f.Addr.As16()
		b = append(b, v6[:]...)
	} else {
		v4 := f.Addr.As4()
		b = append(b, v4[:]...)
	}
	return binary.BigEndian.AppendUint16(b, f.Port), nil
}

// Length returns the encoded size of f, matching ObservedAddr::size
// (frame.rs:2134-2141): type size + seq_no varint size + ip bytes (16 for v6, 4
// otherwise) + 2 port bytes.
func (f *ObservedAddrFrame) Length(_ protocol.Version) protocol.ByteCount {
	ipBytes := 4
	if f.Addr.Is6() {
		ipBytes = 16
	}
	return protocol.ByteCount(quicvarint.Len(uint64(f.frameType())) +
		quicvarint.Len(f.SeqNo) + ipBytes + 2)
}
