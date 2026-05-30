package ackhandler

import (
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket, isPathProbePacket bool)
	// ReceivedAck processes an ACK frame.
	// It does not store a copy of the frame.
	ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
	// ReceivedAckForPath processes a multipath ACK (PATH_ACK) for the
	// application-data packet number space identified by pid. An unknown pid
	// is a protocol violation; it never falls back to PathIDZero.
	ReceivedAckForPath(f *wire.AckFrame, pid protocol.PathID, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
	// AddPath provisions a genuinely-new application-data path (pid !=
	// PathIDZero) with its own RTT estimator and its own congestion controller
	// (never the connection-level objects PathIDZero aliases). It does not
	// schedule any send over the path. pid == PathIDZero or an already-present
	// pid is an error. It is only called once multipath is negotiated.
	AddPath(pid protocol.PathID) error
	ReceivedPacket(protocol.EncryptionLevel, monotime.Time)
	ReceivedBytes(_ protocol.ByteCount, rcvTime monotime.Time)
	DropPackets(_ protocol.EncryptionLevel, rcvTime monotime.Time)
	ResetForRetry(rcvTime monotime.Time)

	// The SendMode determines if and what kind of packets can be sent.
	SendMode(now monotime.Time) SendMode
	// TimeUntilSend is the time when the next packet should be sent.
	// It is used for pacing packets.
	TimeUntilSend() monotime.Time
	SetMaxDatagramSize(count protocol.ByteCount)

	// only to be called once the handshake is complete
	QueueProbePacket(protocol.EncryptionLevel) bool /* was a packet queued */

	ECNMode(isShortHeaderPacket bool) protocol.ECN // isShortHeaderPacket should only be true for non-coalesced 1-RTT packets
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber

	GetLossDetectionTimeout() monotime.Time
	OnLossDetectionTimeout(now monotime.Time) error

	MigratedPath(now monotime.Time, initialMaxPacketSize protocol.ByteCount)
}
