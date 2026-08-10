package quic

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type sendStreamTestSender struct {
	streamData int
}

func (s *sendStreamTestSender) onHasConnectionData() {}
func (s *sendStreamTestSender) onHasStreamData(protocol.StreamID, *SendStream) {
	s.streamData++
}

func TestSendStreamCoalescesActiveNotifications(t *testing.T) {
	sender := new(sendStreamTestSender)
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	for range 2 {
		if _, err := str.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := sender.streamData, 1; got != want {
		t.Fatalf("notifications before pop: got %d, want %d", got, want)
	}
	if frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1); frame.Frame == nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t), want frame and no more", frame.Frame, more)
	}
	if _, err := str.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if got, want := sender.streamData, 2; got != want {
		t.Fatalf("notifications after pop: got %d, want %d", got, want)
	}
}
func (s *sendStreamTestSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (s *sendStreamTestSender) onStreamCompleted(protocol.StreamID) {}

func TestSendStreamConnectionWindowUpdateRequeuesPendingData(t *testing.T) {
	sender := &sendStreamTestSender{}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)

	str.mutex.Lock()
	str.dataForWriting = []byte("x")
	str.mutex.Unlock()

	str.onConnectionSendWindowUpdated()
	if sender.streamData != 1 {
		t.Fatalf("stream data notifications = %d, want 1", sender.streamData)
	}
}

func TestSendStreamConnectionWindowUpdateNoPendingData(t *testing.T) {
	sender := &sendStreamTestSender{}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)

	str.onConnectionSendWindowUpdated()
	if sender.streamData != 0 {
		t.Fatalf("stream data notifications = %d, want 0", sender.streamData)
	}
}
