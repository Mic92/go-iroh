package quic

import (
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTPackerPullsQueuedAddAddressFrame(t *testing.T) {
	f := newFramer(noopConnectionFlowController{})
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	f.QueueControlFrame(&wire.AddAddressFrame{
		SeqNo: 7,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})

	p := &packetPacker{
		framer:              f,
		acks:                noAckFrameSource{},
		retransmissionQueue: newRetransmissionQueue(),
	}
	pl := p.composeNextPacket(1200, false, true, monotime.Now(), protocol.Version1)
	if len(pl.frames) != 1 {
		t.Fatalf("packed %d control frames, want 1", len(pl.frames))
	}
	got, ok := pl.frames[0].Frame.(*wire.AddAddressFrame)
	if !ok {
		t.Fatalf("packed frame = %T, want *wire.AddAddressFrame", pl.frames[0].Frame)
	}
	if got.SeqNo != 7 || netip.AddrPortFrom(got.Addr, got.Port) != addr {
		t.Fatalf("ADD_ADDRESS = seq %d %s:%d, want seq 7 %v", got.SeqNo, got.Addr, got.Port, addr)
	}
	if pl.frames[0].Handler == nil {
		t.Fatal("ADD_ADDRESS frame has no retransmission handler")
	}
	if f.HasData() {
		t.Fatal("framer still has data after packer pulled ADD_ADDRESS")
	}
}

type noAckFrameSource struct{}

func (noAckFrameSource) GetAckFrame(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame {
	return nil
}

func (noAckFrameSource) GetAckFrameForPath(protocol.PathID, monotime.Time, bool) *wire.AckFrame {
	return nil
}

type noopConnectionFlowController struct{}

func (noopConnectionFlowController) SendWindowSize() protocol.ByteCount               { return 0 }
func (noopConnectionFlowController) UpdateSendWindow(protocol.ByteCount) bool         { return false }
func (noopConnectionFlowController) AddBytesSent(protocol.ByteCount)                  {}
func (noopConnectionFlowController) GetWindowUpdate(monotime.Time) protocol.ByteCount { return 0 }
func (noopConnectionFlowController) AddBytesRead(protocol.ByteCount) bool             { return false }
func (noopConnectionFlowController) Reset() error                                     { return nil }
func (noopConnectionFlowController) IsNewlyBlocked() (bool, protocol.ByteCount)       { return false, 0 }
