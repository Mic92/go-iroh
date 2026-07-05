package iroh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRDMAStreamConnReadWrite(t *testing.T) {
	a, b := newMemRDMAStreamTransportPair(1024)
	ac, err := newRDMAStreamConn(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()

	want := []byte("hello over rdma")
	done := make(chan error, 1)
	go func() {
		_, err := ac.Write(want)
		done <- err
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(bc, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read = %q, want %q", got, want)
	}
}

func TestRDMAStreamConnRejectsOversizedWrite(t *testing.T) {
	a, _ := newMemRDMAStreamTransportPair(8)
	c, err := newRDMAStreamConn(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("12345")); err == nil {
		t.Fatal("Write succeeded with oversized frame")
	}
}

func TestRDMAStreamConnMaxPayload(t *testing.T) {
	a, _ := newMemRDMAStreamTransportPair(32)
	c, err := newRDMAStreamConnWithMaxPayload(t.Context(), a, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.max != 7 {
		t.Fatalf("max payload = %d, want 7", c.max)
	}
	if _, err := c.Write(make([]byte, 8)); err == nil {
		t.Fatal("Write succeeded above negotiated max payload")
	}
}

func TestRDMAStreamConnRejectsNegativeMaxPayload(t *testing.T) {
	a, _ := newMemRDMAStreamTransportPair(32)
	if _, err := newRDMAStreamConnWithMaxPayload(t.Context(), a, -1); err == nil {
		t.Fatal("newRDMAStreamConnWithMaxPayload succeeded with negative max payload")
	}
}

func TestRDMAStreamConnCapsMaxPayloadAtBuffer(t *testing.T) {
	a, _ := newMemRDMAStreamTransportPair(32)
	c, err := newRDMAStreamConnWithMaxPayload(t.Context(), a, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	want := 32 - rdmaStreamFrameHeaderSize
	if c.max != want {
		t.Fatalf("max payload = %d, want %d", c.max, want)
	}
}

func TestRDMAStreamConnPartialRead(t *testing.T) {
	a, b := newMemRDMAStreamTransportPair(1024)
	ac, err := newRDMAStreamConn(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()

	want := []byte("hello over rdma")
	done := make(chan error, 1)
	go func() {
		_, err := ac.Write(want)
		done <- err
	}()
	var got bytes.Buffer
	buf := make([]byte, 3)
	for got.Len() < len(want) {
		n, err := bc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("read = %q, want %q", got.Bytes(), want)
	}
}

func TestRDMAStreamConnPollBatchesCompletions(t *testing.T) {
	a, b := newMemRDMAStreamTransportPair(1024)
	ac, err := newRDMAStreamConn(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()

	done := make(chan error, 1)
	go func() {
		_, err := ac.Write([]byte("batch completions"))
		done <- err
	}()
	got := make([]byte, len("batch completions"))
	if _, err := io.ReadFull(bc, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := a.maxPoll; n < 2 {
		t.Fatalf("max poll size = %d, want at least 2", n)
	}
}

func TestRDMAStreamConnPollKeepsPendingCompletion(t *testing.T) {
	tp := &scriptedRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
		batches: [][]rdmaStreamWorkRequest{
			{
				{ID: 2, Bytes: 4},
				{ID: 1, Bytes: 4},
			},
		},
	}
	c, err := newRDMAStreamConn(t.Context(), tp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first, err := c.pollWorkID(c.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != 1 {
		t.Fatalf("first id = %d, want 1", first.ID)
	}
	second, err := c.pollWorkID(c.ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != 2 {
		t.Fatalf("second id = %d, want 2", second.ID)
	}
	if tp.polls != 1 {
		t.Fatalf("polls = %d, want 1", tp.polls)
	}
}

func TestRDMAStreamConnReadDeadline(t *testing.T) {
	tp := &scriptedRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
	}
	c, err := newRDMAStreamConn(t.Context(), tp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want deadline exceeded", err)
	}
}

func TestRDMAStreamConnReadDeadlineWakesPoll(t *testing.T) {
	tp := &blockingRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
	}
	c, err := newRDMAStreamConn(t.Context(), tp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	<-tp.polled
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read error = %v, want deadline exceeded", err)
	}
}

func TestRDMAStreamConnWriteDeadline(t *testing.T) {
	tp := &scriptedRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
	}
	c, err := newRDMAStreamConn(t.Context(), tp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write error = %v, want deadline exceeded", err)
	}
}

func TestRDMAStreamConnWriteDeadlineWakesPoll(t *testing.T) {
	tp := &blockingRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
	}
	c, err := newRDMAStreamConn(t.Context(), tp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	done := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("x"))
		done <- err
	}()
	<-tp.polled
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write error = %v, want deadline exceeded", err)
	}
}

func TestRDMAStreamFramePayload(t *testing.T) {
	buf := make([]byte, 16)
	buf[3] = 3
	copy(buf[4:], "abc")
	got, err := rdmaStreamFramePayload(buf, 7)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("payload = %q, want abc", got)
	}
	if _, err := rdmaStreamFramePayload(buf, 3); err == nil {
		t.Fatal("rdmaStreamFramePayload succeeded with short frame")
	}
	buf[3] = 8
	if _, err := rdmaStreamFramePayload(buf, 7); err == nil {
		t.Fatal("rdmaStreamFramePayload succeeded with short payload")
	}
}

type scriptedRDMAStreamTransport struct {
	send    []byte
	recv    []byte
	batches [][]rdmaStreamWorkRequest
	polls   int
}

func (t *scriptedRDMAStreamTransport) sendBuf() []byte { return t.send }
func (t *scriptedRDMAStreamTransport) recvBuf() []byte { return t.recv }
func (t *scriptedRDMAStreamTransport) postSend(offset, length int, id uint64) error {
	return nil
}
func (t *scriptedRDMAStreamTransport) postRecv(offset, length int, id uint64) error {
	return nil
}
func (t *scriptedRDMAStreamTransport) poll(ctx context.Context, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(t.batches) == 0 {
		return nil, context.Canceled
	}
	t.polls++
	batch := t.batches[0]
	t.batches = t.batches[1:]
	n := copy(out, batch)
	return out[:n], nil
}
func (t *scriptedRDMAStreamTransport) close() error { return nil }

type blockingRDMAStreamTransport struct {
	send       []byte
	recv       []byte
	once       sync.Once
	polled     chan struct{}
	closeOnce  sync.Once
	closed     chan struct{}
	initClosed sync.Once
}

func (t *blockingRDMAStreamTransport) sendBuf() []byte {
	t.init()
	return t.send
}
func (t *blockingRDMAStreamTransport) recvBuf() []byte {
	t.init()
	return t.recv
}
func (t *blockingRDMAStreamTransport) postSend(offset, length int, id uint64) error {
	return nil
}
func (t *blockingRDMAStreamTransport) postRecv(offset, length int, id uint64) error {
	return nil
}
func (t *blockingRDMAStreamTransport) poll(ctx context.Context, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	t.init()
	t.once.Do(func() { close(t.polled) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, context.Canceled
	}
}
func (t *blockingRDMAStreamTransport) close() error {
	t.init()
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}
func (t *blockingRDMAStreamTransport) init() {
	t.initClosed.Do(func() {
		t.polled = make(chan struct{})
		t.closed = make(chan struct{})
	})
}

func BenchmarkRDMAStreamConnMemoryPartialRead(b *testing.B) {
	a, btr := newMemRDMAStreamTransportPair(128 * 1024)
	ac, err := newRDMAStreamConn(b.Context(), a)
	if err != nil {
		b.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(b.Context(), btr)
	if err != nil {
		b.Fatal(err)
	}
	defer bc.Close()

	buf := make([]byte, 64*1024)
	got := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ac.Write(buf); err != nil {
			b.Fatalf("write rdma stream: %v", err)
		}
		for nread := 0; nread < len(buf); {
			n, err := bc.Read(got)
			if err != nil {
				b.Fatalf("read rdma stream: %v", err)
			}
			nread += n
		}
	}
	b.StopTimer()
	ac.Close()
	bc.Close()
}

func BenchmarkRDMAStreamConnMemoryThroughput(b *testing.B) {
	a, btr := newMemRDMAStreamTransportPair(128 * 1024)
	ac, err := newRDMAStreamConn(b.Context(), a)
	if err != nil {
		b.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(b.Context(), btr)
	if err != nil {
		b.Fatal(err)
	}
	defer bc.Close()

	buf := make([]byte, 64*1024)
	got := make([]byte, len(buf))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ac.Write(buf); err != nil {
			b.Fatalf("write rdma stream: %v", err)
		}
		if _, err := io.ReadFull(bc, got); err != nil {
			b.Fatalf("read rdma stream: %v", err)
		}
	}
	b.StopTimer()
	ac.Close()
	bc.Close()
}

func BenchmarkRDMAStreamConnMemoryThroughput1MiB(b *testing.B) {
	a, btr := newMemRDMAStreamTransportPair(2 * 1024 * 1024)
	ac, err := newRDMAStreamConn(b.Context(), a)
	if err != nil {
		b.Fatal(err)
	}
	defer ac.Close()
	bc, err := newRDMAStreamConn(b.Context(), btr)
	if err != nil {
		b.Fatal(err)
	}
	defer bc.Close()

	buf := make([]byte, 1024*1024)
	got := make([]byte, len(buf))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ac.Write(buf); err != nil {
			b.Fatalf("write rdma stream: %v", err)
		}
		if _, err := io.ReadFull(bc, got); err != nil {
			b.Fatalf("read rdma stream: %v", err)
		}
	}
	b.StopTimer()
	ac.Close()
	bc.Close()
}

func BenchmarkRDMAStreamConnPendingCompletion(b *testing.B) {
	tp := &scriptedRDMAStreamTransport{
		send: make([]byte, 16),
		recv: make([]byte, 16),
	}
	c, err := newRDMAStreamConn(b.Context(), tp)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := uint64(i) + 1
		c.pending[0] = rdmaStreamWorkRequest{ID: id, Bytes: 4}
		c.pendingLen = 1
		if _, err := c.pollWorkID(c.ctx, id); err != nil {
			b.Fatalf("poll pending rdma completion: %v", err)
		}
	}
}

type memRDMAStreamTransport struct {
	mu          sync.Mutex
	send        []byte
	recv        []byte
	recvPosted  rdmaStreamPostWork
	hasRecv     bool
	completions []rdmaStreamWorkRequest
	peer        *memRDMAStreamTransport
	closed      bool
	maxPoll     int
}

func newMemRDMAStreamTransportPair(size int) (*memRDMAStreamTransport, *memRDMAStreamTransport) {
	a := &memRDMAStreamTransport{send: make([]byte, size), recv: make([]byte, size)}
	b := &memRDMAStreamTransport{send: make([]byte, size), recv: make([]byte, size)}
	a.peer = b
	b.peer = a
	return a, b
}

func (t *memRDMAStreamTransport) sendBuf() []byte { return t.send }
func (t *memRDMAStreamTransport) recvBuf() []byte { return t.recv }

func (t *memRDMAStreamTransport) postRecv(offset, length int, id uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recvPosted = rdmaStreamPostWork{Offset: offset, Length: length, ID: id}
	t.hasRecv = true
	return nil
}

func (t *memRDMAStreamTransport) postSend(offset, length int, id uint64) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return context.Canceled
	}
	t.completions = append(t.completions, rdmaStreamWorkRequest{ID: id, Bytes: length})
	peer := t.peer
	send := t.send[offset : offset+length]
	t.mu.Unlock()

	peer.mu.Lock()
	defer peer.mu.Unlock()
	if !peer.hasRecv {
		return context.Canceled
	}
	work := peer.recvPosted
	peer.hasRecv = false
	copy(peer.recv[work.Offset:], send)
	peer.completions = append(peer.completions, rdmaStreamWorkRequest{ID: work.ID, Bytes: len(send)})
	return nil
}

func (t *memRDMAStreamTransport) poll(ctx context.Context, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	for {
		t.mu.Lock()
		if len(out) > t.maxPoll {
			t.maxPoll = len(out)
		}
		if len(t.completions) > 0 {
			n := len(out)
			if n > len(t.completions) {
				n = len(t.completions)
			}
			out = out[:n]
			copy(out, t.completions[:n])
			copy(t.completions, t.completions[n:])
			t.completions = t.completions[:len(t.completions)-n]
			t.mu.Unlock()
			return out, nil
		}
		closed := t.closed
		t.mu.Unlock()
		if closed {
			return nil, context.Canceled
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
}

func (t *memRDMAStreamTransport) close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	return nil
}
