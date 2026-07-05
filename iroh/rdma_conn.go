package iroh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type rdmaStreamPostWork struct {
	Offset int
	Length int
	ID     uint64
}

type rdmaStreamWorkRequest struct {
	ID     uint64
	Opcode int
	Bytes  int
	Status int
}

type rdmaStreamConnTransport interface {
	sendBuf() []byte
	recvBuf() []byte
	postSend(offset, length int, id uint64) error
	postRecv(offset, length int, id uint64) error
	poll(context.Context, []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error)
	close() error
}

type rdmaStreamConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	t      rdmaStreamConnTransport
	send   []byte
	recv   []byte
	max    int

	readMu sync.Mutex
	read   []byte
	recvID uint64

	writeMu sync.Mutex
	sendID  uint64

	pollMu     sync.Mutex
	pending    [8]rdmaStreamWorkRequest
	pendingLen int
	pollBuf    [8]rdmaStreamWorkRequest

	readDL  atomic.Pointer[rdmaStreamDeadlineState]
	writeDL atomic.Pointer[rdmaStreamDeadlineState]

	closeOnce sync.Once
	closeErr  error
}

func newRDMAStreamConn(ctx context.Context, t rdmaStreamConnTransport) (*rdmaStreamConn, error) {
	return newRDMAStreamConnWithMaxPayload(ctx, t, 0)
}

func newRDMAStreamConnWithMaxPayload(ctx context.Context, t rdmaStreamConnTransport, maxPayload int) (*rdmaStreamConn, error) {
	if t == nil {
		return nil, errors.New("rdma: nil stream transport")
	}
	if maxPayload < 0 {
		return nil, fmt.Errorf("rdma: frame payload %d must be non-negative", maxPayload)
	}
	send := t.sendBuf()
	recv := t.recvBuf()
	if len(send) < rdmaStreamFrameHeaderSize+1 {
		return nil, fmt.Errorf("rdma: send buffer too small: %d", len(send))
	}
	if len(recv) < rdmaStreamFrameHeaderSize+1 {
		return nil, fmt.Errorf("rdma: receive buffer too small: %d", len(recv))
	}
	max := len(send) - rdmaStreamFrameHeaderSize
	if recvMax := len(recv) - rdmaStreamFrameHeaderSize; recvMax < max {
		max = recvMax
	}
	if maxPayload > 0 && maxPayload < max {
		max = maxPayload
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &rdmaStreamConn{
		ctx:    ctx,
		cancel: cancel,
		t:      t,
		send:   send,
		recv:   recv,
		max:    max,
		recvID: rdmaStreamRecvWorkID,
		sendID: rdmaStreamSendWorkID,
	}
	c.readDL.Store(newRDMAStreamDeadlineState(ctx, time.Time{}))
	c.writeDL.Store(newRDMAStreamDeadlineState(ctx, time.Time{}))
	if err := c.postRecvLocked(); err != nil {
		c.readDL.Load().cancel()
		c.writeDL.Load().cancel()
		cancel()
		_ = t.close()
		return nil, err
	}
	return c, nil
}

func (c *rdmaStreamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	if len(c.read) > 0 {
		n, err := c.readBufferedLocked(p)
		c.readMu.Unlock()
		return n, err
	}
	for len(c.read) == 0 {
		ctx, dl := c.readPollContext()
		work, err := c.pollWorkID(ctx, c.recvID)
		if err != nil {
			err = c.readPollError(dl, err)
			if errors.Is(err, errRDMAStreamDeadlineChanged) {
				continue
			}
			c.readMu.Unlock()
			return 0, err
		}
		frame, err := rdmaStreamFramePayload(c.recv, work.Bytes)
		if err != nil {
			c.readMu.Unlock()
			return 0, err
		}
		if len(p) >= len(frame) {
			n := copy(p, frame)
			c.recvID++
			if err := c.postRecvLocked(); err != nil {
				c.readMu.Unlock()
				return 0, err
			}
			c.readMu.Unlock()
			return n, nil
		}
		c.read = frame
	}
	n, err := c.readBufferedLocked(p)
	c.readMu.Unlock()
	return n, err
}

func (c *rdmaStreamConn) readBufferedLocked(p []byte) (int, error) {
	n := copy(p, c.read)
	c.read = c.read[n:]
	if len(c.read) == 0 {
		c.recvID++
		if err := c.postRecvLocked(); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *rdmaStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	buf := c.send
	if len(p) > c.max {
		c.writeMu.Unlock()
		return 0, fmt.Errorf("rdma: write size %d exceeds frame payload %d", len(p), c.max)
	}
	binary.BigEndian.PutUint32(buf[:rdmaStreamFrameHeaderSize], uint32(len(p)))
	copy(buf[rdmaStreamFrameHeaderSize:], p)
	id := c.sendID
	c.sendID++
	if err := c.t.postSend(0, rdmaStreamFrameHeaderSize+len(p), id); err != nil {
		c.writeMu.Unlock()
		return 0, err
	}
	for {
		ctx, dl := c.writePollContext()
		_, err := c.pollWorkID(ctx, id)
		if err == nil {
			break
		}
		err = c.writePollError(dl, err)
		if errors.Is(err, errRDMAStreamDeadlineChanged) {
			continue
		}
		c.writeMu.Unlock()
		return 0, err
	}
	c.writeMu.Unlock()
	return len(p), nil
}

func (c *rdmaStreamConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.closeErr = c.t.close()
	})
	return c.closeErr
}

func (c *rdmaStreamConn) LocalAddr() net.Addr  { return rdmaStreamNetAddr("rdma") }
func (c *rdmaStreamConn) RemoteAddr() net.Addr { return rdmaStreamNetAddr("rdma") }

func (c *rdmaStreamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *rdmaStreamConn) SetReadDeadline(t time.Time) error {
	next := newRDMAStreamDeadlineState(c.ctx, t)
	prev := c.readDL.Swap(next)
	if prev != nil {
		prev.cancel()
	}
	return nil
}

func (c *rdmaStreamConn) SetWriteDeadline(t time.Time) error {
	next := newRDMAStreamDeadlineState(c.ctx, t)
	prev := c.writeDL.Swap(next)
	if prev != nil {
		prev.cancel()
	}
	return nil
}

func (c *rdmaStreamConn) postRecvLocked() error {
	return c.t.postRecv(0, len(c.recv), c.recvID)
}

func (c *rdmaStreamConn) pollWorkID(ctx context.Context, id uint64) (rdmaStreamWorkRequest, error) {
	c.pollMu.Lock()
	for {
		for i := 0; i < c.pendingLen; i++ {
			work := c.pending[i]
			if work.ID == id {
				c.pendingLen--
				c.pending[i] = c.pending[c.pendingLen]
				c.pollMu.Unlock()
				return work, nil
			}
		}
		works, err := c.t.poll(ctx, c.pollBuf[:])
		if err != nil {
			c.pollMu.Unlock()
			return rdmaStreamWorkRequest{}, err
		}
		for _, work := range works {
			if work.ID == id {
				c.pollMu.Unlock()
				return work, nil
			}
			if c.pendingLen == len(c.pending) {
				c.pollMu.Unlock()
				return rdmaStreamWorkRequest{}, errors.New("rdma: too many pending completions")
			}
			c.pending[c.pendingLen] = work
			c.pendingLen++
		}
	}
}

func (c *rdmaStreamConn) readPollContext() (context.Context, *rdmaStreamDeadlineState) {
	state := c.readDL.Load()
	return state.ctx, state
}

func (c *rdmaStreamConn) writePollContext() (context.Context, *rdmaStreamDeadlineState) {
	state := c.writeDL.Load()
	return state.ctx, state
}

func (c *rdmaStreamConn) readPollError(state *rdmaStreamDeadlineState, err error) error {
	return c.deadlineError(c.readDL.Load(), state, err)
}

func (c *rdmaStreamConn) writePollError(state *rdmaStreamDeadlineState, err error) error {
	return c.deadlineError(c.writeDL.Load(), state, err)
}

func (c *rdmaStreamConn) deadlineError(current, poll *rdmaStreamDeadlineState, err error) error {
	if current != poll {
		return errRDMAStreamDeadlineChanged
	}
	if errors.Is(err, context.DeadlineExceeded) || !poll.deadline.IsZero() && !time.Now().Before(poll.deadline) {
		return os.ErrDeadlineExceeded
	}
	if errors.Is(err, context.Canceled) && c.ctx.Err() != nil {
		return net.ErrClosed
	}
	return err
}

func newRDMAStreamDeadlineState(parent context.Context, t time.Time) *rdmaStreamDeadlineState {
	ctx, cancel := rdmaStreamDeadlineContext(parent, t)
	return &rdmaStreamDeadlineState{ctx: ctx, cancel: cancel, deadline: t}
}

var errRDMAStreamDeadlineChanged = errors.New("rdma: deadline changed")

type rdmaStreamDeadlineState struct {
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
}

func rdmaStreamDeadlineContext(ctx context.Context, t time.Time) (context.Context, context.CancelFunc) {
	if t.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, t)
}

func rdmaStreamFramePayload(buf []byte, n int) ([]byte, error) {
	if n < rdmaStreamFrameHeaderSize {
		return nil, io.ErrShortBuffer
	}
	if n > len(buf) {
		return nil, fmt.Errorf("rdma: completion byte count %d exceeds receive buffer %d", n, len(buf))
	}
	payload := int(binary.BigEndian.Uint32(buf[:rdmaStreamFrameHeaderSize]))
	if payload > n-rdmaStreamFrameHeaderSize {
		return nil, fmt.Errorf("rdma: frame payload %d exceeds completion payload %d", payload, n-rdmaStreamFrameHeaderSize)
	}
	return buf[rdmaStreamFrameHeaderSize : rdmaStreamFrameHeaderSize+payload], nil
}

type rdmaStreamNetAddr string

func (a rdmaStreamNetAddr) Network() string { return "rdma" }
func (a rdmaStreamNetAddr) String() string  { return string(a) }

const (
	rdmaStreamFrameHeaderSize = 4
	rdmaStreamSendWorkID      = 1
	rdmaStreamRecvWorkID      = 1 << 32
)
