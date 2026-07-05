//go:build darwin && arm64

package iroh

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDarwinRDMAStreamBackendControlHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	factory := newFakeRDMAStreamResourceFactory(1024)
	oldFactory := newRDMAStreamResource
	newRDMAStreamResource = factory.new
	defer func() { newRDMAStreamResource = oldFactory }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	backend := darwinRDMAStreamBackend{}
	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- backend.ListenStreams(ctx, 77, ln, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()

	remote := NewStreamLinkAddr(77, TransportLinkRDMA, "rdma_en3", rdmaStreamDialAddr(RDMALink{Device: "rdma_en3"}, ln.Addr().String()))
	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "rdma-test/0",
		StableID:    1,
		TransportID: 77,
		Purpose:     "handshake-test",
		Nonce:       "nonce",
		Expiry:      time.Now().Add(time.Minute),
	}
	client, err := backend.DialStream(ctx, 77, remote, StreamOptions{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var server io.ReadWriteCloser
	select {
	case a := <-accepted:
		server = a.Conn
		if a.Token.TransportID != tok.TransportID || a.Token.Purpose != tok.Purpose {
			t.Fatalf("accepted token = %+v, want %+v", a.Token, tok)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	msg := []byte("backend handshake")
	done := make(chan error, 1)
	go func() {
		_, err := client.Write(msg)
		done <- err
	}()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("read = %q, want %q", got, msg)
	}

	clientRT, serverRT := factory.resources()
	if !clientRT.connected || !serverRT.connected {
		t.Fatalf("connected = client %v server %v, want both true", clientRT.connected, serverRT.connected)
	}
	for i, size := range factory.requestedBufSizes() {
		if size != rdmaStreamBufferSize {
			t.Fatalf("resource %d buffer size = %d, want %d", i, size, rdmaStreamBufferSize)
		}
	}
	if clientRT.remote.QPN != serverRT.local.QPN || serverRT.remote.QPN != clientRT.local.QPN {
		t.Fatalf("destinations not exchanged: client remote=%+v server local=%+v server remote=%+v client local=%+v", clientRT.remote, serverRT.local, serverRT.remote, clientRT.local)
	}

	cancel()
	_ = ln.Close()
}

type fakeRDMAStreamResourceFactory struct {
	mu      sync.Mutex
	nextQPN uint32
	pending *fakeRDMAStreamResource
	created []*fakeRDMAStreamResource
	bufSize int
	sizes   []int
}

func newFakeRDMAStreamResourceFactory(bufSize int) *fakeRDMAStreamResourceFactory {
	return &fakeRDMAStreamResourceFactory{nextQPN: 100, bufSize: bufSize}
}

func (f *fakeRDMAStreamResourceFactory) new(ctx context.Context, device string, bufSize int) (rdmaStreamResource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sizes = append(f.sizes, bufSize)
	r := &fakeRDMAStreamResource{
		device: device,
		local: rdmaStreamDestination{
			LID:       1,
			QPN:       f.nextQPN,
			PSN:       rdmaStreamDefaultPSN,
			GIDIndex:  1,
			ActiveMTU: 5,
		},
		send: make([]byte, f.bufSize),
		recv: make([]byte, f.bufSize),
	}
	r.local.GID[15] = byte(f.nextQPN)
	f.nextQPN++
	if f.pending == nil {
		f.pending = r
	} else {
		r.peer = f.pending
		f.pending.peer = r
		f.pending = nil
	}
	f.created = append(f.created, r)
	return r, nil
}

func (f *fakeRDMAStreamResourceFactory) resources() (*fakeRDMAStreamResource, *fakeRDMAStreamResource) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created[0], f.created[1]
}

func (f *fakeRDMAStreamResourceFactory) requestedBufSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.sizes...)
}

type fakeRDMAStreamResource struct {
	mu          sync.Mutex
	device      string
	local       rdmaStreamDestination
	remote      rdmaStreamDestination
	connected   bool
	send        []byte
	recv        []byte
	recvPosted  rdmaStreamPostWork
	hasRecv     bool
	completions []rdmaStreamWorkRequest
	peer        *fakeRDMAStreamResource
	closed      bool
}

func (r *fakeRDMAStreamResource) localDestination() (rdmaStreamDestination, error) {
	return r.local, nil
}

func (r *fakeRDMAStreamResource) connect(ctx context.Context, local, remote rdmaStreamDestination) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.remote = remote
	r.connected = true
	r.mu.Unlock()
	return nil
}

func (r *fakeRDMAStreamResource) sendBuf() []byte { return r.send }
func (r *fakeRDMAStreamResource) recvBuf() []byte { return r.recv }

func (r *fakeRDMAStreamResource) postRecv(offset, length int, id uint64) error {
	r.mu.Lock()
	r.recvPosted = rdmaStreamPostWork{Offset: offset, Length: length, ID: id}
	r.hasRecv = true
	r.mu.Unlock()
	return nil
}

func (r *fakeRDMAStreamResource) postSend(offset, length int, id uint64) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return context.Canceled
	}
	r.completions = append(r.completions, rdmaStreamWorkRequest{ID: id, Bytes: length})
	peer := r.peer
	send := r.send[offset : offset+length]
	r.mu.Unlock()

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

func (r *fakeRDMAStreamResource) poll(ctx context.Context, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	for {
		r.mu.Lock()
		if len(r.completions) > 0 {
			n := len(out)
			if n > len(r.completions) {
				n = len(r.completions)
			}
			out = out[:n]
			copy(out, r.completions[:n])
			copy(r.completions, r.completions[n:])
			r.completions = r.completions[:len(r.completions)-n]
			r.mu.Unlock()
			return out, nil
		}
		closed := r.closed
		r.mu.Unlock()
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

func (r *fakeRDMAStreamResource) close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}
