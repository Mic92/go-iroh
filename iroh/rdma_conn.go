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

	readMu   sync.Mutex
	read     []byte
	readSlot int
	recvID   uint64
	nslots   int
	slots    [rdmaStreamMaxRecvSlots]rdmaStreamRecvSlot

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
	recvSlots := rdmaStreamRecvSlotCount(len(recv))
	max := rdmaStreamSlotPayload(len(send), rdmaStreamSendSlots)
	if recvMax := rdmaStreamSlotPayload(len(recv), recvSlots); recvMax < max {
		max = recvMax
	}
	if maxPayload > 0 && maxPayload < max {
		max = maxPayload
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &rdmaStreamConn{
		ctx:      ctx,
		cancel:   cancel,
		t:        t,
		send:     send,
		recv:     recv,
		readSlot: -1,
		max:      max,
		recvID:   rdmaStreamRecvWorkID,
		sendID:   rdmaStreamSendWorkID,
		nslots:   recvSlots,
	}
	c.readDL.Store(newRDMAStreamDeadlineState(ctx, time.Time{}))
	c.writeDL.Store(newRDMAStreamDeadlineState(ctx, time.Time{}))
	for i := 0; i < c.nslots; i++ {
		if err := c.postRecvSlotLocked(i); err != nil {
			c.readDL.Load().cancel()
			c.writeDL.Load().cancel()
			cancel()
			_ = t.close()
			return nil, err
		}
	}
	if c.nslots == 0 {
		c.readDL.Load().cancel()
		c.writeDL.Load().cancel()
		cancel()
		_ = t.close()
		return nil, errors.New("rdma: no receive slots")
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
		slot, work, err := c.pollRecv(ctx)
		if err != nil {
			err = c.readPollError(dl, err)
			if errors.Is(err, errRDMAStreamDeadlineChanged) {
				continue
			}
			c.readMu.Unlock()
			return 0, err
		}
		frame, err := rdmaStreamFramePayloadAt(c.recv, c.slots[slot].offset, work.Bytes)
		if err != nil {
			c.readMu.Unlock()
			return 0, err
		}
		if len(p) >= len(frame) {
			n := copy(p, frame)
			if err := c.postRecvSlotLocked(slot); err != nil {
				c.readMu.Unlock()
				return 0, err
			}
			c.readMu.Unlock()
			return n, nil
		}
		c.read = frame
		c.readSlot = slot
	}
	n, err := c.readBufferedLocked(p)
	c.readMu.Unlock()
	return n, err
}

func (c *rdmaStreamConn) readBufferedLocked(p []byte) (int, error) {
	n := copy(p, c.read)
	c.read = c.read[n:]
	if len(c.read) == 0 {
		slot := c.readSlot
		c.readSlot = -1
		if err := c.postRecvSlotLocked(slot); err != nil {
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
	if c.max <= 0 {
		return 0, fmt.Errorf("rdma: invalid frame payload %d", c.max)
	}
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > c.max {
			n = c.max
		}
		if err := c.writeFrameLocked(p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *rdmaStreamConn) writeFrameLocked(p []byte) error {
	if len(p) > c.max {
		return fmt.Errorf("rdma: write size %d exceeds frame payload %d", len(p), c.max)
	}
	buf := c.send
	if rdmaStreamFrameHeaderSize+len(p) > len(buf) {
		return fmt.Errorf("rdma: write size %d exceeds send buffer %d", len(p), len(buf))
	}
	binary.BigEndian.PutUint32(buf[:rdmaStreamFrameHeaderSize], uint32(len(p)))
	copy(buf[rdmaStreamFrameHeaderSize:], p)
	id := c.sendID
	c.sendID++
	if err := c.t.postSend(0, rdmaStreamFrameHeaderSize+len(p), id); err != nil {
		return err
	}
	for {
		ctx, dl := c.writePollContext()
		_, err := c.pollWorkID(ctx, id)
		if err == nil {
			return nil
		}
		err = c.writePollError(dl, err)
		if errors.Is(err, errRDMAStreamDeadlineChanged) {
			continue
		}
		return err
	}
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

func (c *rdmaStreamConn) postRecvSlotLocked(slot int) error {
	if slot < 0 || slot >= c.nslots {
		return fmt.Errorf("rdma: receive slot %d outside slot count %d", slot, c.nslots)
	}
	size := rdmaStreamSlotSize(len(c.recv), c.nslots)
	offset := slot * size
	id := c.recvID
	c.recvID++
	c.slots[slot] = rdmaStreamRecvSlot{id: id, offset: offset}
	return c.t.postRecv(offset, size, id)
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
		var found rdmaStreamWorkRequest
		ok := false
		for _, work := range works {
			if work.ID == id {
				found = work
				ok = true
				continue
			}
			if c.pendingLen == len(c.pending) {
				c.pollMu.Unlock()
				return rdmaStreamWorkRequest{}, errors.New("rdma: too many pending completions")
			}
			c.pending[c.pendingLen] = work
			c.pendingLen++
		}
		if ok {
			c.pollMu.Unlock()
			return found, nil
		}
	}
}

func (c *rdmaStreamConn) pollRecv(ctx context.Context) (int, rdmaStreamWorkRequest, error) {
	if c.nslots == 1 {
		work, err := c.pollWorkID(ctx, c.slots[0].id)
		if err != nil {
			return 0, rdmaStreamWorkRequest{}, err
		}
		return 0, work, nil
	}
	c.pollMu.Lock()
	for {
		for i := 0; i < c.pendingLen; i++ {
			work := c.pending[i]
			if slot := c.recvSlotByID(work.ID); slot >= 0 {
				c.pendingLen--
				c.pending[i] = c.pending[c.pendingLen]
				c.pollMu.Unlock()
				return slot, work, nil
			}
		}
		works, err := c.t.poll(ctx, c.pollBuf[:])
		if err != nil {
			c.pollMu.Unlock()
			return 0, rdmaStreamWorkRequest{}, err
		}
		foundSlot := -1
		var found rdmaStreamWorkRequest
		for _, work := range works {
			if slot := c.recvSlotByID(work.ID); slot >= 0 {
				if foundSlot < 0 {
					foundSlot = slot
					found = work
					continue
				}
			}
			if c.pendingLen == len(c.pending) {
				c.pollMu.Unlock()
				return 0, rdmaStreamWorkRequest{}, errors.New("rdma: too many pending completions")
			}
			c.pending[c.pendingLen] = work
			c.pendingLen++
		}
		if foundSlot >= 0 {
			c.pollMu.Unlock()
			return foundSlot, found, nil
		}
	}
}

func (c *rdmaStreamConn) recvSlotByID(id uint64) int {
	for i := 0; i < c.nslots; i++ {
		if c.slots[i].id == id {
			return i
		}
	}
	return -1
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
	return rdmaStreamFramePayloadAt(buf, 0, n)
}

func rdmaStreamFramePayloadAt(buf []byte, offset, n int) ([]byte, error) {
	if offset < 0 || offset > len(buf) {
		return nil, fmt.Errorf("rdma: frame offset %d outside receive buffer %d", offset, len(buf))
	}
	buf = buf[offset:]
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
	rdmaStreamSendSlots       = 1
	rdmaStreamMaxRecvSlots    = 2
	rdmaStreamMinSlotPayload  = 1024 * 1024
)

type rdmaStreamRecvSlot struct {
	id     uint64
	offset int
}

func rdmaStreamRecvSlotCount(n int) int {
	if rdmaStreamSlotPayload(n, rdmaStreamMaxRecvSlots) >= rdmaStreamMinSlotPayload {
		return rdmaStreamMaxRecvSlots
	}
	return 1
}

func rdmaStreamSlotSize(n, slots int) int {
	if slots <= 0 {
		return 0
	}
	return n / slots
}

func rdmaStreamSlotPayload(n, slots int) int {
	size := rdmaStreamSlotSize(n, slots)
	if size < rdmaStreamFrameHeaderSize {
		return 0
	}
	return size - rdmaStreamFrameHeaderSize
}
