package quic

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type sendStreamTestSender struct {
	streamData int
}

type sendStreamNotificationSender struct {
	streamData chan struct{}
}

func (s *sendStreamTestSender) onHasConnectionData() {}
func (s *sendStreamTestSender) onHasStreamData(protocol.StreamID, *SendStream) {
	s.streamData++
}
func (s *sendStreamNotificationSender) onHasConnectionData() {}
func (s *sendStreamNotificationSender) onHasStreamData(protocol.StreamID, *SendStream) {
	s.streamData <- struct{}{}
}
func (s *sendStreamNotificationSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (s *sendStreamNotificationSender) onStreamCompleted(protocol.StreamID) {}

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

func TestSendStreamEpisodeQualifiesBurst(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Hour, time.Hour)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	for range 4 {
		if _, err := str.Write(make([]byte, 300)); err != nil {
			t.Fatal(err)
		}
	}
	<-sender.streamData
	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t), want one frame", frame.Frame, more)
	}
	frame.Frame.PutBack()
	if _, err := str.Write(make([]byte, 300)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
		t.Fatal("fresh burst evidence activated below threshold")
	default:
	}
	if _, err := str.Write(make([]byte, 900)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
	default:
		t.Fatal("fresh burst evidence did not activate at threshold")
	}
}

func TestSendStreamEpisodeBelowThresholdDoesNotQualify(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Hour, time.Hour)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	if _, err := str.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	<-sender.streamData
	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t), want one frame", frame.Frame, more)
	}
	frame.Frame.PutBack()
	if _, err := str.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
	default:
		t.Fatal("unqualified episode did not activate immediately")
	}
}

func TestSendStreamEpisodeEvidenceExpires(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Nanosecond, time.Hour)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	qualifySendStreamEpisode(t, str, sender)
	if _, err := str.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
	default:
		t.Fatal("expired burst evidence did not activate immediately")
	}
}

func TestSendStreamEpisodeTailTimeout(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Hour, time.Millisecond)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	qualifySendStreamEpisode(t, str, sender)
	if _, err := str.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
		t.Fatal("burst tail activated before timeout")
	default:
	}
	select {
	case <-sender.streamData:
	case <-time.After(time.Second):
		t.Fatal("burst tail did not activate after timeout")
	}
}

func TestSendStreamEpisodeCloseFlushesTail(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Hour, time.Hour)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	qualifySendStreamEpisode(t, str, sender)
	if _, err := str.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sender.streamData:
	default:
		t.Fatal("Close did not activate burst tail")
	}
}

func TestSendStreamEpisodeCancelStopsTailTimer(t *testing.T) {
	setSendStreamEpisodeTestParameters(t, time.Hour, time.Hour)
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 2)}
	str := newSendStream(context.Background(), 0, sender, receiveStreamTestFlow{}, false)
	qualifySendStreamEpisode(t, str, sender)
	if _, err := str.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)
	str.mutex.Lock()
	timer := str.activationTimer
	str.mutex.Unlock()
	if timer != nil {
		t.Fatal("CancelWrite left burst tail timer armed")
	}
	select {
	case <-sender.streamData:
		t.Fatal("CancelWrite activated discarded burst tail")
	default:
	}
}

func setSendStreamEpisodeTestParameters(t *testing.T, freshness, delay time.Duration) {
	t.Helper()
	oldFreshness, oldDelay := sendStreamBurstFreshness, sendStreamTailDelay
	sendStreamBurstFreshness, sendStreamTailDelay = freshness, delay
	t.Cleanup(func() {
		sendStreamBurstFreshness, sendStreamTailDelay = oldFreshness, oldDelay
	})
}

func qualifySendStreamEpisode(t *testing.T, str *SendStream, sender *sendStreamNotificationSender) {
	t.Helper()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	<-sender.streamData
	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t), want one frame", frame.Frame, more)
	}
	frame.Frame.PutBack()
}

func TestSendStreamWriteBufferPreservesOrder(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, false)
	want := bytes.Repeat([]byte("0123456789abcdef"), sendStreamWriteBufferSize/16)
	for p := want; len(p) > 0; {
		n := min(37, len(p))
		if got, err := str.Write(p[:n]); err != nil || got != n {
			t.Fatalf("Write = %d, %v; want %d, nil", got, err, n)
		}
		p = p[n:]
	}

	var got []byte
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("popped data differs: got %d bytes, want %d", len(got), len(want))
	}
}

func TestSendStreamWriteBufferBackpressure(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, false)
	if n, err := str.Write(make([]byte, sendStreamWriteBufferSize)); err != nil || n != sendStreamWriteBufferSize {
		t.Fatalf("initial Write = %d, %v", n, err)
	}

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := str.Write([]byte("x"))
		done <- result{n: n, err: err}
	}()
	waitForBlockedSendStreamWrite(t, str)
	select {
	case r := <-done:
		t.Fatalf("Write returned without buffer space: %d, %v", r.n, r.err)
	default:
	}

	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	frame.Frame.PutBack()
	select {
	case r := <-done:
		if r.n != 1 || r.err != nil {
			t.Fatalf("unblocked Write = %d, %v; want 1, nil", r.n, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock after buffer space became available")
	}
}

func TestSendStreamWriteBufferDeadline(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, false)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := str.Write(make([]byte, 2*sendStreamWriteBufferSize))
		done <- result{n: n, err: err}
	}()
	waitForBlockedSendStreamWrite(t, str)
	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	wantN := len(frame.Frame.Data)
	frame.Frame.PutBack()
	if err := str.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.n != wantN || !errors.Is(r.err, errDeadline) {
			t.Fatalf("Write = %d, %v; want %d, deadline error", r.n, r.err, wantN)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock after deadline")
	}
}

func TestSendStreamWriteBufferShutdown(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, false)
	if _, err := str.Write(make([]byte, sendStreamWriteBufferSize)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := str.Write([]byte("x"))
		done <- err
	}()
	waitForBlockedSendStreamWrite(t, str)
	want := errors.New("shutdown")
	str.closeForShutdown(want)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("Write error = %v; want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock on shutdown")
	}
}

func TestSendStreamWriteBufferFin(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, false)
	if _, err := str.Write(make([]byte, sendStreamWriteBufferSize)); err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame == nil {
			t.Fatal("popStreamFrame returned no frame")
		}
		if frame.Frame.Fin != !more {
			t.Fatalf("frame %d: Fin = %t, more = %t; FIN must appear only on last frame", i, frame.Frame.Fin, more)
		}
		frame.Frame.PutBack()
		if !more {
			break
		}
	}
}

func TestSendStreamWriteBufferReliableCancel(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, true)
	if _, err := str.Write([]byte("reliable")); err != nil {
		t.Fatal(err)
	}
	str.SetReliableBoundary()
	if _, err := str.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)

	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil || string(frame.Frame.Data) != "reliable" || more {
		t.Fatalf("popStreamFrame = (%v, more %t); want reliable data only", frame.Frame, more)
	}
	frame.Frame.PutBack()
}

func TestSendStreamWriteBufferUnreliableCancel(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), receiveStreamTestFlow{}, true)
	if _, err := str.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)
	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame != nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t); want no data", frame.Frame, more)
	}
}

func waitForBlockedSendStreamWrite(t *testing.T, str *SendStream) {
	t.Helper()
	for range 10_000 {
		str.mutex.Lock()
		blocked := str.dataForWriting != nil
		str.mutex.Unlock()
		if blocked {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("Write did not block")
}
