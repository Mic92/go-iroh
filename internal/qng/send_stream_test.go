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
