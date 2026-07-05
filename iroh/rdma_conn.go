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

	readMu sync.Mutex
	read   []byte
	recvID uint64

	writeMu sync.Mutex
	sendID  uint64

	pollMu     sync.Mutex
	pending    [8]rdmaStreamWorkRequest
	pendingLen int
	pollBuf    [8]rdmaStreamWorkRequest

	deadlineMu      sync.Mutex
	readDeadline    time.Time
	writeDeadline   time.Time
	readDeadlineID  uint64
	writeDeadlineID uint64
	readCtx         context.Context
	readCancel      context.CancelFunc
	writeCtx        context.Context
	writeCancel     context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

func newRDMAStreamConn(ctx context.Context, t rdmaStreamConnTransport) (*rdmaStreamConn, error) {
	if t == nil {
		return nil, errors.New("rdma: nil stream transport")
	}
	send := t.sendBuf()
	recv := t.recvBuf()
	if len(send) < rdmaStreamFrameHeaderSize+1 {
		return nil, fmt.Errorf("rdma: send buffer too small: %d", len(send))
	}
	if len(recv) < rdmaStreamFrameHeaderSize+1 {
		return nil, fmt.Errorf("rdma: receive buffer too small: %d", len(recv))
	}
	ctx, cancel := context.WithCancel(ctx)
	readCtx, readCancel := context.WithCancel(ctx)
	writeCtx, writeCancel := context.WithCancel(ctx)
	c := &rdmaStreamConn{
		ctx:         ctx,
		cancel:      cancel,
		t:           t,
		send:        send,
		recv:        recv,
		recvID:      rdmaStreamRecvWorkID,
		sendID:      rdmaStreamSendWorkID,
		readCtx:     readCtx,
		readCancel:  readCancel,
		writeCtx:    writeCtx,
		writeCancel: writeCancel,
	}
	if err := c.postRecvLocked(); err != nil {
		readCancel()
		writeCancel()
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
	defer c.readMu.Unlock()
	if len(c.read) > 0 {
		return c.readBufferedLocked(p)
	}
	for len(c.read) == 0 {
		ctx, deadlineID := c.readPollContext()
		work, err := c.pollWorkID(ctx, c.recvID)
		if err != nil {
			err = c.readPollError(deadlineID, err)
			if errors.Is(err, errRDMAStreamDeadlineChanged) {
				continue
			}
			return 0, err
		}
		frame, err := rdmaStreamFramePayload(c.recv, work.Bytes)
		if err != nil {
			return 0, err
		}
		if len(p) >= len(frame) {
			n := copy(p, frame)
			c.recvID++
			if err := c.postRecvLocked(); err != nil {
				return 0, err
			}
			return n, nil
		}
		c.read = frame
	}
	return c.readBufferedLocked(p)
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
	defer c.writeMu.Unlock()
	buf := c.send
	if len(p) > len(buf)-rdmaStreamFrameHeaderSize {
		return 0, fmt.Errorf("rdma: write size %d exceeds frame payload %d", len(p), len(buf)-rdmaStreamFrameHeaderSize)
	}
	binary.BigEndian.PutUint32(buf[:rdmaStreamFrameHeaderSize], uint32(len(p)))
	copy(buf[rdmaStreamFrameHeaderSize:], p)
	id := c.sendID
	c.sendID++
	if err := c.t.postSend(0, rdmaStreamFrameHeaderSize+len(p), id); err != nil {
		return 0, err
	}
	for {
		ctx, deadlineID := c.writePollContext()
		_, err := c.pollWorkID(ctx, id)
		if err == nil {
			break
		}
		err = c.writePollError(deadlineID, err)
		if errors.Is(err, errRDMAStreamDeadlineChanged) {
			continue
		}
		return 0, err
	}
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
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	c.readDeadlineID++
	c.readCancel()
	c.readCtx, c.readCancel = rdmaStreamDeadlineContext(c.ctx, t)
	return nil
}

func (c *rdmaStreamConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	c.writeDeadlineID++
	c.writeCancel()
	c.writeCtx, c.writeCancel = rdmaStreamDeadlineContext(c.ctx, t)
	return nil
}

func (c *rdmaStreamConn) postRecvLocked() error {
	return c.t.postRecv(0, len(c.recv), c.recvID)
}

func (c *rdmaStreamConn) pollWorkID(ctx context.Context, id uint64) (rdmaStreamWorkRequest, error) {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	for {
		for i := 0; i < c.pendingLen; i++ {
			work := c.pending[i]
			if work.ID == id {
				c.pendingLen--
				c.pending[i] = c.pending[c.pendingLen]
				return work, nil
			}
		}
		works, err := c.t.poll(ctx, c.pollBuf[:])
		if err != nil {
			return rdmaStreamWorkRequest{}, err
		}
		for _, work := range works {
			if work.ID == id {
				return work, nil
			}
			if c.pendingLen == len(c.pending) {
				return rdmaStreamWorkRequest{}, errors.New("rdma: too many pending completions")
			}
			c.pending[c.pendingLen] = work
			c.pendingLen++
		}
	}
}

func (c *rdmaStreamConn) readPollContext() (context.Context, uint64) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readCtx, c.readDeadlineID
}

func (c *rdmaStreamConn) writePollContext() (context.Context, uint64) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeCtx, c.writeDeadlineID
}

func (c *rdmaStreamConn) readPollError(deadlineID uint64, err error) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.deadlineErrorLocked(c.readDeadlineID, deadlineID, c.readDeadline, err)
}

func (c *rdmaStreamConn) writePollError(deadlineID uint64, err error) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.deadlineErrorLocked(c.writeDeadlineID, deadlineID, c.writeDeadline, err)
}

func (c *rdmaStreamConn) deadlineErrorLocked(currentID, pollID uint64, deadline time.Time, err error) error {
	if currentID != pollID {
		return errRDMAStreamDeadlineChanged
	}
	if errors.Is(err, context.DeadlineExceeded) || !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	if errors.Is(err, context.Canceled) && c.ctx.Err() != nil {
		return net.ErrClosed
	}
	return err
}

func rdmaStreamDeadlineContext(ctx context.Context, t time.Time) (context.Context, context.CancelFunc) {
	if t.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, t)
}

var errRDMAStreamDeadlineChanged = errors.New("rdma: deadline changed")

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
