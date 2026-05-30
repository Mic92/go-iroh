package ackhandler

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/qlog"
)

// These tests pin the behavior of the flat-field sentPacketHandler so that the
// Stage 4a refactor (introducing a single-entry appDataPaths map keyed by
// protocol.PathIDZero) can be shown to be a behavioral no-op. They construct the
// real handler via NewSentPacketHandler with the real cubic congestion
// controller and a real RTTStats, then assert observable recovery state through
// the concrete *sentPacketHandler.
//
// Stage 4a moved the packet-number bookkeeping into the single PathIDZero map
// entry; Stage 4b additionally moved the appData bytes-in-flight, PTO count,
// congestion controller, RTT estimator and ECN tracker there. The field reads
// below therefore go through getAppDataPath(protocol.PathIDZero) for the
// app-data recovery state (bytesInFlight, ptoCount); the asserted values are
// identical to the pre-refactor flat-field handler.

const oracleInitialMaxDatagramSize = protocol.ByteCount(1252)

// newOracleSentHandler builds a sentPacketHandler with the handshake already
// confirmed and the peer's address validated, so the appData (1-RTT) space
// behaves as it does in steady state. A fixed RTT is seeded so loss-detection
// and PTO timers are deterministic.
func newOracleSentHandler(t *testing.T) (*sentPacketHandler, *utils.RTTStats) {
	t.Helper()
	rttStats := utils.NewRTTStats()
	// Seed a deterministic RTT so getScaledPTO / time-threshold loss detection
	// produce stable, non-zero timer values.
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	h := NewSentPacketHandler(
		0,
		oracleInitialMaxDatagramSize,
		rttStats,
		connStats,
		true, // clientAddressValidated
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil, // no qlogger
		utils.DefaultLogger,
	).(*sentPacketHandler)
	// Put the handler into the post-handshake steady state for the appData space.
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	h.peerAddressValidated = true
	h.initialPackets = nil
	h.handshakePackets = nil
	return h, rttStats
}

// ackElicitingFrame returns a Frame that makes a packet ack-eliciting without
// any acked/lost callbacks.
func ackElicitingFrame() Frame {
	return Frame{Frame: &wire.PingFrame{}}
}

// sendAppDataPacket allocates the next 1-RTT packet number through the handler
// (so the packet-number generator and the sent-packet history stay in lockstep,
// exactly as the connection drives them) and sends a single ack-eliciting 1-RTT
// packet. It returns the allocated packet number.
func sendAppDataPacket(h *sentPacketHandler, sendTime monotime.Time, size protocol.ByteCount) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.Encryption1RTT)
	h.SentPacket(
		sendTime,
		pn,
		protocol.InvalidPacketNumber,
		nil,
		[]Frame{ackElicitingFrame()},
		protocol.Encryption1RTT,
		protocol.ECNNon,
		size,
		false,
		false,
	)
	return pn
}

// ackFrameForPN returns an ACK frame acknowledging a single packet number.
func ackFrameForPN(pn protocol.PacketNumber) *wire.AckFrame {
	return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}}
}

// outstandingPNs returns the still-outstanding packet numbers in the appData
// history, in ascending order.
func outstandingPNs(h *sentPacketHandler) []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for pn, p := range h.getAppDataPath(protocol.PathIDZero).space.history.Packets() {
		if p.Outstanding() {
			pns = append(pns, pn)
		}
	}
	return pns
}

func TestSentPacketHandlerAckBookkeeping(t *testing.T) {
	const packetSize = protocol.ByteCount(1000)

	// The appData packet-number generator skips numbers at random, so the test
	// captures the actually-allocated PNs and indexes into them rather than
	// hardcoding values. ackIdx/wantOutstandingIdx are indices into the slice
	// of sent PNs.
	tests := []struct {
		name string
		// number of 1-RTT packets to send
		numSent int
		// indices (into the sent-PN slice) acked by a contiguous range
		// [sent[ackLoIdx] .. sent[ackHiIdx]]
		ackLoIdx, ackHiIdx int
		wantBytesInFlight  protocol.ByteCount
		wantAcked1RTT      bool
		// indices of PNs expected to remain outstanding after the ack
		wantOutstandingIdx []int
	}{
		{
			name:               "ack all packets",
			numSent:            5,
			ackLoIdx:           0,
			ackHiIdx:           4,
			wantBytesInFlight:  0,
			wantAcked1RTT:      true,
			wantOutstandingIdx: nil,
		},
		{
			name:               "ack a prefix",
			numSent:            5,
			ackLoIdx:           0,
			ackHiIdx:           2,
			wantBytesInFlight:  2 * packetSize, // sent[3], sent[4] still outstanding
			wantAcked1RTT:      true,
			wantOutstandingIdx: []int{3, 4},
		},
		{
			name:               "ack single middle packet",
			numSent:            3,
			ackLoIdx:           1,
			ackHiIdx:           1,
			wantBytesInFlight:  2 * packetSize, // sent[0], sent[2] still outstanding
			wantAcked1RTT:      true,
			wantOutstandingIdx: []int{0, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newOracleSentHandler(t)
			now := monotime.Now()
			sent := make([]protocol.PacketNumber, tt.numSent)
			for i := range sent {
				sent[i] = sendAppDataPacket(h, now, packetSize)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).bytesInFlight; got != protocol.ByteCount(tt.numSent)*packetSize {
				t.Fatalf("bytesInFlight before ack = %d, want %d", got, protocol.ByteCount(tt.numSent)*packetSize)
			}

			wantLargestAcked := sent[tt.ackHiIdx]
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: sent[tt.ackLoIdx], Largest: sent[tt.ackHiIdx]}}}
			acked1RTT, err := h.ReceivedAck(ack, protocol.Encryption1RTT, now)
			if err != nil {
				t.Fatalf("ReceivedAck: %v", err)
			}
			if acked1RTT != tt.wantAcked1RTT {
				t.Errorf("acked1RTT = %v, want %v", acked1RTT, tt.wantAcked1RTT)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).bytesInFlight; got != tt.wantBytesInFlight {
				t.Errorf("bytesInFlight = %d, want %d", got, tt.wantBytesInFlight)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).space.largestAcked; got != wantLargestAcked {
				t.Errorf("largestAcked = %d, want %d", got, wantLargestAcked)
			}

			var want []protocol.PacketNumber
			for _, idx := range tt.wantOutstandingIdx {
				want = append(want, sent[idx])
			}
			if got := outstandingPNs(h); !equalPNs(got, want) {
				t.Errorf("outstanding = %v, want %v", got, want)
			}
		})
	}
}

// TestSentPacketHandlerPTOCountReset pins that ptoCount is reset on an ACK that
// acknowledges packets once the peer has completed address validation.
func TestSentPacketHandlerPTOCountReset(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	sendAppDataPacket(h, now, 1000)

	// Force a PTO to bump ptoCount.
	if err := h.OnLossDetectionTimeout(now.Add(time.Second)); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}
	if h.getAppDataPath(protocol.PathIDZero).ptoCount == 0 {
		t.Fatalf("expected ptoCount > 0 after PTO, got 0")
	}

	// A packet sent in PTO mode, then acked, must reset ptoCount.
	pn := sendAppDataPacket(h, now.Add(time.Second), 1000)
	if _, err := h.ReceivedAck(ackFrameForPN(pn), protocol.Encryption1RTT, now.Add(2*time.Second)); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	if got := h.getAppDataPath(protocol.PathIDZero).ptoCount; got != 0 {
		t.Errorf("ptoCount after ack = %d, want 0", got)
	}
}

// TestSentPacketHandlerLossTimerArmed pins that sending an ack-eliciting 1-RTT
// packet arms a PTO loss-detection timer in the 1-RTT space and that delivering
// an ACK that leaves nothing outstanding cancels it.
func TestSentPacketHandlerLossTimerArmed(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	if !h.GetLossDetectionTimeout().IsZero() {
		t.Fatalf("loss timer should be unset before any packet is sent")
	}

	pn := sendAppDataPacket(h, now, 1000)
	armed := h.GetLossDetectionTimeout()
	if armed.IsZero() {
		t.Fatalf("loss timer should be armed after sending an ack-eliciting packet")
	}
	// With a single outstanding packet, the armed alarm is a PTO timer.
	if h.alarm.TimerType != qlog.TimerTypePTO {
		t.Errorf("alarm type = %v, want %v", h.alarm.TimerType, qlog.TimerTypePTO)
	}
	if h.alarm.EncryptionLevel != protocol.Encryption1RTT {
		t.Errorf("alarm enc level = %v, want %v", h.alarm.EncryptionLevel, protocol.Encryption1RTT)
	}

	// Ack the only outstanding packet: timer must be canceled.
	if _, err := h.ReceivedAck(ackFrameForPN(pn), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	if !h.GetLossDetectionTimeout().IsZero() {
		t.Errorf("loss timer should be canceled once nothing is outstanding, got %v", h.GetLossDetectionTimeout())
	}
}

// TestSentPacketHandlerReorderingLoss pins reordering-threshold loss detection:
// after acking a much higher packet number, lower outstanding ack-eliciting
// packets beyond the reordering threshold are declared lost (removed from
// bytes-in-flight and history).
func TestSentPacketHandlerReorderingLoss(t *testing.T) {
	const packetSize = protocol.ByteCount(1000)
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	// Send 5 packets, capturing the actually-allocated packet numbers (the
	// appData generator skips numbers at random).
	sent := make([]protocol.PacketNumber, 5)
	for i := range sent {
		sent[i] = sendAppDataPacket(h, now, packetSize)
	}
	largest := sent[len(sent)-1]

	// Derive, from the implementation's own packet-distance measure, which of the
	// earlier packets are >= packetThreshold behind the largest acked. Those must
	// be declared lost by reordering; the rest must remain outstanding. This makes
	// the assertion robust to random packet-number skips while still pinning the
	// reordering-threshold behavior.
	appData := h.getAppDataPath(protocol.PathIDZero).space
	var wantOutstanding []protocol.PacketNumber
	for _, pn := range sent[:len(sent)-1] {
		if appData.history.Difference(largest, pn) < packetThreshold {
			wantOutstanding = append(wantOutstanding, pn)
		}
	}

	// Ack only the largest packet.
	if _, err := h.ReceivedAck(ackFrameForPN(largest), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}

	if got := outstandingPNs(h); !equalPNs(got, wantOutstanding) {
		t.Errorf("outstanding after reordering loss = %v, want %v", got, wantOutstanding)
	}
	if got, want := h.getAppDataPath(protocol.PathIDZero).bytesInFlight, protocol.ByteCount(len(wantOutstanding))*packetSize; got != want {
		t.Errorf("bytesInFlight = %d, want %d", got, want)
	}
	if appData.largestAcked != largest {
		t.Errorf("largestAcked = %d, want %d", appData.largestAcked, largest)
	}
	// A loss-detection timer should be armed for the still-pending packets.
	if len(wantOutstanding) > 0 && appData.lossTime.IsZero() {
		t.Errorf("expected an appData lossTime to be set for the pending packets")
	}
}

// TestSentPacketHandlerAckUnsentPacket pins the ProtocolViolation guard for an
// ACK acknowledging a packet number we never sent.
func TestSentPacketHandlerAckUnsentPacket(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	pn := sendAppDataPacket(h, now, 1000)

	// Ack a packet number well above the largest we sent.
	_, err := h.ReceivedAck(ackFrameForPN(pn+100), protocol.Encryption1RTT, now)
	if err == nil {
		t.Fatalf("expected error for ACK of unsent packet")
	}
	transportErr, ok := err.(*qerr.TransportError)
	if !ok {
		t.Fatalf("error type = %T, want *qerr.TransportError", err)
	}
	if transportErr.ErrorCode != qerr.ProtocolViolation {
		t.Errorf("error code = %v, want ProtocolViolation", transportErr.ErrorCode)
	}
}

// TestSentPacketHandlerLossTimeAndSpaceSinglePath pins getLossTimeAndSpace /
// getPTOTimeAndSpace for the single (appData) path, which is the exact output
// the post-refactor fan-out over the single-entry path map must reproduce.
func TestSentPacketHandlerLossTimeAndSpaceSinglePath(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	// No outstanding packets: both helpers return zero/empty.
	if lt, _ := h.getLossTimeAndSpace(); !lt.IsZero() {
		t.Errorf("getLossTimeAndSpace with nothing sent = %v, want zero", lt)
	}
	if pt, _ := h.getPTOTimeAndSpace(now); !pt.IsZero() {
		t.Errorf("getPTOTimeAndSpace with nothing sent = %v, want zero", pt)
	}

	// Send a packet: PTO time/space should reference the 1-RTT space.
	sendAppDataPacket(h, now, 1000)
	ptoTime, ptoEncLevel := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		t.Fatalf("expected non-zero PTO time after sending an ack-eliciting packet")
	}
	if ptoEncLevel != protocol.Encryption1RTT {
		t.Errorf("PTO enc level = %v, want %v", ptoEncLevel, protocol.Encryption1RTT)
	}
	// The PTO time is anchored to the last ack-eliciting send time plus the
	// scaled PTO. This pins the exact arithmetic so the per-path version must
	// match.
	wantPTO := now.Add(h.getScaledPTO(true))
	if !ptoTime.Equal(wantPTO) {
		t.Errorf("PTO time = %v, want %v", ptoTime, wantPTO)
	}

	// detectLostPackets sets appData lossTime when there is a still-pending
	// packet below the largest acked; getLossTimeAndSpace must surface it as
	// the 1-RTT space. Send two more and ack only the last so the earlier
	// packets stay within the reordering threshold (arming a time-based loss
	// timer rather than being declared lost outright).
	sendAppDataPacket(h, now, 1000)
	last := sendAppDataPacket(h, now, 1000)
	if _, err := h.ReceivedAck(ackFrameForPN(last), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	lossTime, lossEncLevel := h.getLossTimeAndSpace()
	if lossTime.IsZero() {
		t.Fatalf("expected a non-zero loss time after partial ack")
	}
	if lossEncLevel != protocol.Encryption1RTT {
		t.Errorf("loss enc level = %v, want %v", lossEncLevel, protocol.Encryption1RTT)
	}
	appDataLossTime := h.getAppDataPath(protocol.PathIDZero).space.lossTime
	if !lossTime.Equal(appDataLossTime) {
		t.Errorf("getLossTimeAndSpace = %v, want appData lossTime %v", lossTime, appDataLossTime)
	}
}

func equalPNs(a, b []protocol.PacketNumber) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
