package iroh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

	pollMu  sync.Mutex
	pending []rdmaStreamWorkRequest
	pollBuf [8]rdmaStreamWorkRequest

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
	c := &rdmaStreamConn{
		ctx:    ctx,
		cancel: cancel,
		t:      t,
		send:   send,
		recv:   recv,
		recvID: rdmaStreamRecvWorkID,
		sendID: rdmaStreamSendWorkID,
	}
	if err := c.postRecvLocked(); err != nil {
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
		work, err := c.pollWorkID(c.recvID)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return 0, net.ErrClosed
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
	if _, err := c.pollWorkID(id); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0, net.ErrClosed
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
	if !t.IsZero() {
		return errors.New("rdma: deadlines are unsupported")
	}
	return nil
}

func (c *rdmaStreamConn) SetReadDeadline(t time.Time) error {
	if !t.IsZero() {
		return errors.New("rdma: read deadlines are unsupported")
	}
	return nil
}

func (c *rdmaStreamConn) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		return errors.New("rdma: write deadlines are unsupported")
	}
	return nil
}

func (c *rdmaStreamConn) postRecvLocked() error {
	return c.t.postRecv(0, len(c.recv), c.recvID)
}

func (c *rdmaStreamConn) pollWorkID(id uint64) (rdmaStreamWorkRequest, error) {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	for {
		for i, work := range c.pending {
			if work.ID == id {
				copy(c.pending[i:], c.pending[i+1:])
				c.pending = c.pending[:len(c.pending)-1]
				return work, nil
			}
		}
		works, err := c.t.poll(c.ctx, c.pollBuf[:])
		if err != nil {
			return rdmaStreamWorkRequest{}, err
		}
		for _, work := range works {
			if work.ID == id {
				return work, nil
			}
			c.pending = append(c.pending, work)
		}
	}
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
