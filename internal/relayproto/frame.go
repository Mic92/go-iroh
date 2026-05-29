// Package relayproto implements the iroh relay wire protocol: the framing,
// datagram, and handshake messages exchanged between a relay client and server.
//
// It is a port of iroh-relay/src/protos. Frames are carried in binary WebSocket
// messages; each frame begins with a QUIC-varint frame type followed by a
// type-specific payload. The encodings here are byte-for-byte compatible with
// the Rust reference (verified by golden snapshot tests).
package relayproto

import (
	"errors"
	"fmt"
)

// MaxPacketSize is the maximum size of a packet sent over the relay, counting
// only the visible data bytes, not the on-wire framing overhead.
const MaxPacketSize = 64 * 1024

// PerClientSendQueueDepth is the number of packets buffered for sending per
// client by a relay server.
const PerClientSendQueueDepth = 512

// FrameType identifies a relay protocol frame. It is encoded on the wire as a
// QUIC varint.
type FrameType uint32

// Frame types, matching iroh-relay/src/protos/common.rs.
const (
	FrameServerChallenge          FrameType = 0
	FrameClientAuth               FrameType = 1
	FrameServerConfirmsAuth       FrameType = 2
	FrameServerDeniesAuth         FrameType = 3
	FrameClientToRelayDatagram    FrameType = 4
	FrameClientToRelayDatagramBat FrameType = 5
	FrameRelayToClientDatagram    FrameType = 6
	FrameRelayToClientDatagramBat FrameType = 7
	FrameEndpointGone             FrameType = 8
	FramePing                     FrameType = 9
	FramePong                     FrameType = 10
	FrameHealth                   FrameType = 11
	FrameRestarting               FrameType = 12
	FrameStatus                   FrameType = 13
)

func (f FrameType) String() string {
	switch f {
	case FrameServerChallenge:
		return "ServerChallenge"
	case FrameClientAuth:
		return "ClientAuth"
	case FrameServerConfirmsAuth:
		return "ServerConfirmsAuth"
	case FrameServerDeniesAuth:
		return "ServerDeniesAuth"
	case FrameClientToRelayDatagram:
		return "ClientToRelayDatagram"
	case FrameClientToRelayDatagramBat:
		return "ClientToRelayDatagramBatch"
	case FrameRelayToClientDatagram:
		return "RelayToClientDatagram"
	case FrameRelayToClientDatagramBat:
		return "RelayToClientDatagramBatch"
	case FrameEndpointGone:
		return "EndpointGone"
	case FramePing:
		return "Ping"
	case FramePong:
		return "Pong"
	case FrameHealth:
		return "Health"
	case FrameRestarting:
		return "Restarting"
	case FrameStatus:
		return "Status"
	default:
		return fmt.Sprintf("FrameType(%d)", uint32(f))
	}
}

// knownFrameType reports whether t is a defined frame type.
func knownFrameType(t uint32) bool {
	return t <= uint32(FrameStatus)
}

// Protocol errors.
var (
	ErrInvalidFrame             = errors.New("relayproto: invalid frame encoding")
	ErrFrameTooLarge            = errors.New("relayproto: frame too large")
	ErrUnknownFrameType         = errors.New("relayproto: unknown frame type")
	ErrFrameTypeUnexpectedEnd   = errors.New("relayproto: not enough bytes to parse frame type")
	ErrFrameNotAllowedInVersion = errors.New("relayproto: frame not allowed in this protocol version")
)

// writeFrameType appends f to dst as a QUIC varint.
func writeFrameType(dst []byte, f FrameType) []byte {
	return appendVarint(dst, uint64(f))
}

// frameTypeEncodedLen returns the number of bytes writeFrameType writes for f.
func frameTypeEncodedLen(f FrameType) int {
	return varintLen(uint64(f))
}

// readFrameType reads a QUIC-varint frame type from the front of buf and returns
// it with the remaining bytes.
func readFrameType(buf []byte) (FrameType, []byte, error) {
	v, rest, err := readVarint(buf)
	if err != nil {
		return 0, nil, ErrFrameTypeUnexpectedEnd
	}
	if v > 0xffff_ffff || !knownFrameType(uint32(v)) {
		return 0, nil, fmt.Errorf("%w: %d", ErrUnknownFrameType, v)
	}
	return FrameType(v), rest, nil
}
