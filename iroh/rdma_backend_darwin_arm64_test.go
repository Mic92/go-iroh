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
		if size != defaultRDMAStreamBufferSize {
			t.Fatalf("resource %d buffer size = %d, want %d", i, size, defaultRDMAStreamBufferSize)
		}
	}
	if clientRT.remote.QPN != serverRT.local.QPN || serverRT.remote.QPN != clientRT.local.QPN {
		t.Fatalf("destinations not exchanged: client remote=%+v server local=%+v server remote=%+v client local=%+v", clientRT.remote, serverRT.local, serverRT.remote, clientRT.local)
	}
	if clientConn, ok := client.(*rdmaStreamConn); !ok || clientConn.max != len(clientRT.send)-rdmaStreamFrameHeaderSize {
		t.Fatalf("client max payload = %v, want %d", clientConnMax(client), len(clientRT.send)-rdmaStreamFrameHeaderSize)
	}
	if serverConn, ok := server.(*rdmaStreamConn); !ok || serverConn.max != len(serverRT.send)-rdmaStreamFrameHeaderSize {
		t.Fatalf("server max payload = %v, want %d", clientConnMax(server), len(serverRT.send)-rdmaStreamFrameHeaderSize)
	}
	if got := clientRT.postSendCount(); got != 2 {
		t.Fatalf("client post sends = %d, want 2", got)
	}
	if got := serverRT.postSendCount(); got != 1 {
		t.Fatalf("server post sends = %d, want 1", got)
	}

	cancel()
	_ = ln.Close()
}

func TestDarwinRDMAStreamBackendNegotiatesFramePayload(t *testing.T) {
	t.Setenv("GO_IROH_RDMA_BUFFER_SIZE", "4096")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	factory := newFakeRDMAStreamResourceFactory(2048)
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
	var server net.Conn
	select {
	case a := <-accepted:
		server = a.Conn
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer server.Close()

	want := 2048 - rdmaStreamFrameHeaderSize
	if got := clientConnMax(client); got != want {
		t.Fatalf("client max payload = %d, want %d", got, want)
	}
	if got := clientConnMax(server); got != want {
		t.Fatalf("server max payload = %d, want %d", got, want)
	}
	clientRT, serverRT := factory.resources()
	if got := clientRT.postSendCount(); got != 1 {
		t.Fatalf("client post sends = %d, want 1", got)
	}
	if got := serverRT.postSendCount(); got != 1 {
		t.Fatalf("server post sends = %d, want 1", got)
	}
}

func TestDarwinRDMAStreamBackendDialFailureDoesNotOpenResource(t *testing.T) {
	factory := newFakeRDMAStreamResourceFactory(1024)
	oldFactory := newRDMAStreamResource
	newRDMAStreamResource = factory.new
	defer func() { newRDMAStreamResource = oldFactory }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	backend := darwinRDMAStreamBackend{}
	remote := NewStreamLinkAddr(77, TransportLinkRDMA, "rdma_en3", rdmaStreamDialAddr(RDMALink{Device: "rdma_en3"}, addr))
	if _, err := backend.DialStream(t.Context(), 77, remote, StreamOptions{}); err == nil {
		t.Fatal("DialStream succeeded")
	}
	if got := factory.resourceCount(); got != 0 {
		t.Fatalf("resources = %d, want 0", got)
	}
}

func TestAcceptRDMAStreamControlHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	err := acceptRDMAStreamControl(ctx, 77, server, func(StreamAccept) error {
		t.Fatal("accept called")
		return nil
	})
	if err == nil {
		t.Fatal("acceptRDMAStreamControl succeeded")
	}
}

func clientConnMax(c any) int {
	rc, ok := c.(*rdmaStreamConn)
	if !ok {
		return -1
	}
	return rc.max
}

func TestRDMAStreamBufferSize(t *testing.T) {
	t.Setenv("GO_IROH_RDMA_BUFFER_SIZE", "")
	if got := rdmaStreamBufferSize(); got != defaultRDMAStreamBufferSize {
		t.Fatalf("default buffer size = %d, want %d", got, defaultRDMAStreamBufferSize)
	}
	t.Setenv("GO_IROH_RDMA_BUFFER_SIZE", "2097152")
	if got := rdmaStreamBufferSize(); got != 2097152 {
		t.Fatalf("configured buffer size = %d, want 2097152", got)
	}
	t.Setenv("GO_IROH_RDMA_BUFFER_SIZE", "4")
	if got := rdmaStreamBufferSize(); got != defaultRDMAStreamBufferSize {
		t.Fatalf("tiny buffer size = %d, want default %d", got, defaultRDMAStreamBufferSize)
	}
	t.Setenv("GO_IROH_RDMA_BUFFER_SIZE", "bad")
	if got := rdmaStreamBufferSize(); got != defaultRDMAStreamBufferSize {
		t.Fatalf("bad buffer size = %d, want default %d", got, defaultRDMAStreamBufferSize)
	}
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

func (f *fakeRDMAStreamResourceFactory) resourceCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.created)
}

type fakeRDMAStreamResource struct {
	mu          sync.Mutex
	device      string
	local       rdmaStreamDestination
	remote      rdmaStreamDestination
	connected   bool
	send        []byte
	recv        []byte
	recvPosted  []rdmaStreamPostWork
	completions []rdmaStreamWorkRequest
	peer        *fakeRDMAStreamResource
	closed      bool
	postSends   int
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
	r.recvPosted = append(r.recvPosted, rdmaStreamPostWork{Offset: offset, Length: length, ID: id})
	r.mu.Unlock()
	return nil
}

func (r *fakeRDMAStreamResource) postRecvs(works *[rdmaStreamMaxRecvSlots]rdmaStreamPostWork, n int) error {
	r.mu.Lock()
	r.recvPosted = append(r.recvPosted, works[:n]...)
	r.mu.Unlock()
	return nil
}

func (r *fakeRDMAStreamResource) postSend(offset, length int, id uint64) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return context.Canceled
	}
	r.postSends++
	r.completions = append(r.completions, rdmaStreamWorkRequest{ID: id, Bytes: length})
	peer := r.peer
	send := r.send[offset : offset+length]
	r.mu.Unlock()

	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.recvPosted) == 0 {
		return context.Canceled
	}
	work := peer.recvPosted[0]
	copy(peer.recvPosted, peer.recvPosted[1:])
	peer.recvPosted = peer.recvPosted[:len(peer.recvPosted)-1]
	copy(peer.recv[work.Offset:], send)
	peer.completions = append(peer.completions, rdmaStreamWorkRequest{ID: work.ID, Bytes: len(send)})
	return nil
}

func (r *fakeRDMAStreamResource) postSendCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.postSends
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
