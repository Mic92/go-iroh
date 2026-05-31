package wire

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// errInvalidQNTAddress is returned when a QNT address-bearing frame body does
// not have enough bytes for the address family selected by its frame type.
var errInvalidQNTAddress = errors.New("wire: malformed qnt address frame")

// This file holds inert codecs for iroh's n0 NAT traversal frames from noq.
// The layouts mirror internal/qng/n0ext/reference/frame.rs:
//
//	AddAddress  | seq_no (varint) | ip (4 or 16 bytes) | port (u16)
//	ReachOut    | round  (varint) | ip (4 or 16 bytes) | port (u16)
//	RemoveAddr  | seq_no (varint)
//
// These frame types are not admitted by FrameParser yet.

// AddAddressFrame advertises an address for n0 NAT traversal.
// See reference/frame.rs:2285-2368.
type AddAddressFrame struct {
	SeqNo uint64
	Addr  netip.Addr
	Port  uint16
}

func (f *AddAddressFrame) frameType() FrameType {
	if f.Addr.Is6() {
		return FrameTypeAddIPv6Address
	}
	return FrameTypeAddIPv4Address
}

func parseAddAddressFrame(b []byte, isIPv6 bool, _ protocol.Version) (*AddAddressFrame, int, error) {
	seq, addr, port, n, err := parseQNTAddressBody(b, isIPv6)
	if err != nil {
		return nil, 0, err
	}
	return &AddAddressFrame{SeqNo: seq, Addr: addr, Port: port}, n, nil
}

func (f *AddAddressFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.frameType()))
	b = quicvarint.Append(b, f.SeqNo)
	return appendQNTAddress(b, f.Addr, f.Port), nil
}

func (f *AddAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	return qntAddressFrameLength(f.frameType(), f.SeqNo, f.Addr)
}

// ReachOutFrame asks the peer to send a NAT traversal probe to the encoded
// address. See reference/frame.rs:2375-2441.
type ReachOutFrame struct {
	Round uint64
	Addr  netip.Addr
	Port  uint16
}

func (f *ReachOutFrame) frameType() FrameType {
	if f.Addr.Is6() {
		return FrameTypeReachOutAtIPv6
	}
	return FrameTypeReachOutAtIPv4
}

func parseReachOutFrame(b []byte, isIPv6 bool, _ protocol.Version) (*ReachOutFrame, int, error) {
	round, addr, port, n, err := parseQNTAddressBody(b, isIPv6)
	if err != nil {
		return nil, 0, err
	}
	return &ReachOutFrame{Round: round, Addr: addr, Port: port}, n, nil
}

func (f *ReachOutFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(f.frameType()))
	b = quicvarint.Append(b, f.Round)
	return appendQNTAddress(b, f.Addr, f.Port), nil
}

func (f *ReachOutFrame) Length(_ protocol.Version) protocol.ByteCount {
	return qntAddressFrameLength(f.frameType(), f.Round, f.Addr)
}

func parseQNTAddressBody(b []byte, isIPv6 bool) (uint64, netip.Addr, uint16, int, error) {
	startLen := len(b)
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, netip.Addr{}, 0, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	var addr netip.Addr
	if isIPv6 {
		if len(b) < 16 {
			return 0, netip.Addr{}, 0, 0, errInvalidQNTAddress
		}
		addr = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
	} else {
		if len(b) < 4 {
			return 0, netip.Addr{}, 0, 0, errInvalidQNTAddress
		}
		addr = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
	}

	if len(b) < 2 {
		return 0, netip.Addr{}, 0, 0, errInvalidQNTAddress
	}
	port := binary.BigEndian.Uint16(b[:2])
	b = b[2:]
	return seq, addr, port, startLen - len(b), nil
}

func appendQNTAddress(b []byte, addr netip.Addr, port uint16) []byte {
	if addr.Is6() {
		v6 := addr.As16()
		b = append(b, v6[:]...)
	} else {
		v4 := addr.As4()
		b = append(b, v4[:]...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

func qntAddressFrameLength(typ FrameType, n uint64, addr netip.Addr) protocol.ByteCount {
	ipBytes := 4
	if addr.Is6() {
		ipBytes = 16
	}
	return protocol.ByteCount(quicvarint.Len(uint64(typ)) + quicvarint.Len(n) + ipBytes + 2)
}

// RemoveAddressFrame stops advertising an address sequence number.
// See reference/frame.rs:2448-2491.
type RemoveAddressFrame struct {
	SeqNo uint64
}

func parseRemoveAddressFrame(b []byte, _ protocol.Version) (*RemoveAddressFrame, int, error) {
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	return &RemoveAddressFrame{SeqNo: seq}, l, nil
}

func (f *RemoveAddressFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeRemoveAddress))
	b = quicvarint.Append(b, f.SeqNo)
	return b, nil
}

func (f *RemoveAddressFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeRemoveAddress)) + quicvarint.Len(f.SeqNo))
}
