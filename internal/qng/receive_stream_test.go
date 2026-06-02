package quic

import (
	"io"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

type receiveStreamTestSender struct{}

func (receiveStreamTestSender) onHasConnectionData()                           {}
func (receiveStreamTestSender) onHasStreamData(protocol.StreamID, *SendStream) {}
func (receiveStreamTestSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (receiveStreamTestSender) onStreamCompleted(protocol.StreamID) {}

type receiveStreamTestFlow struct{}

func (receiveStreamTestFlow) SendWindowSize() protocol.ByteCount               { return protocol.MaxByteCount }
func (receiveStreamTestFlow) UpdateSendWindow(protocol.ByteCount) bool         { return false }
func (receiveStreamTestFlow) AddBytesSent(protocol.ByteCount)                  {}
func (receiveStreamTestFlow) GetWindowUpdate(monotime.Time) protocol.ByteCount { return 0 }
func (receiveStreamTestFlow) AddBytesRead(protocol.ByteCount) (bool, bool)     { return false, false }
func (receiveStreamTestFlow) UpdateHighestReceived(protocol.ByteCount, bool, monotime.Time) error {
	return nil
}
func (receiveStreamTestFlow) Abandon()             {}
func (receiveStreamTestFlow) IsNewlyBlocked() bool { return false }

func newReceiveStreamForTest() *ReceiveStream {
	return newReceiveStream(0, receiveStreamTestSender{}, receiveStreamTestFlow{})
}

func TestReceiveStreamInOrderFrameRead(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	n, err := s.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %d, %q; want 1, a", n, buf[:n])
	}
}

func TestReceiveStreamBlockedReadDirectHandoff(t *testing.T) {
	s := newReceiveStreamForTest()

	type result struct {
		n   int
		err error
		buf [1]byte
	}
	done := make(chan result, 1)
	go func() {
		var buf [1]byte
		n, err := s.Read(buf[:])
		done <- result{n: n, err: err, buf: buf}
	}()

	var waiting bool
	for i := 0; i < 100; i++ {
		s.mutex.Lock()
		waiting = s.pendingRead != nil
		s.mutex.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		t.Fatal("Read did not block")
	}

	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.n != 1 || got.buf[0] != 'a' {
			t.Fatalf("Read = %d, %q; want 1, a", got.n, got.buf[:got.n])
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not complete")
	}
	if s.frameQueue.HasMoreData() {
		t.Fatal("direct handoff left data queued")
	}
}

func TestReceiveStreamDuplicateAfterInOrderRead(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := s.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	dup := &wire.StreamFrame{StreamID: 0, Data: []byte("b")}
	if err := s.handleStreamFrame(dup, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if s.frameQueue.HasMoreData() {
		t.Fatal("duplicate data queued after in-order read")
	}
}

func TestReceiveStreamOutOfOrderFallback(t *testing.T) {
	s := newReceiveStreamForTest()
	later := &wire.StreamFrame{StreamID: 0, Offset: 1, Data: []byte("b")}
	if err := s.handleStreamFrame(later, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	first := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(first, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [2]byte
	n, err := s.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || string(buf[:]) != "ab" {
		t.Fatalf("Read = %d, %q; want 2, ab", n, buf[:])
	}
}

func TestReceiveStreamFinAfterInOrderFrame(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a"), Fin: true}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [2]byte
	n, err := s.Read(buf[:])
	if err != io.EOF {
		t.Fatalf("Read err = %v, want EOF", err)
	}
	if n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %d, %q; want 1, a", n, buf[:n])
	}
}
