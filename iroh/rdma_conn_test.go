package iroh

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
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

type memRDMAStreamTransport struct {
	mu          sync.Mutex
	send        []byte
	recv        []byte
	recvPosted  *rdmaStreamPostWork
	completions []rdmaStreamWorkRequest
	peer        *memRDMAStreamTransport
	closed      bool
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
	t.recvPosted = &rdmaStreamPostWork{Offset: offset, Length: length, ID: id}
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
	if peer.recvPosted == nil {
		return context.Canceled
	}
	work := *peer.recvPosted
	peer.recvPosted = nil
	copy(peer.recv[work.Offset:], send)
	peer.completions = append(peer.completions, rdmaStreamWorkRequest{ID: work.ID, Bytes: len(send)})
	return nil
}

func (t *memRDMAStreamTransport) poll(ctx context.Context, n int) ([]rdmaStreamWorkRequest, error) {
	for {
		t.mu.Lock()
		if len(t.completions) > 0 {
			if n > len(t.completions) {
				n = len(t.completions)
			}
			out := append([]rdmaStreamWorkRequest(nil), t.completions[:n]...)
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
