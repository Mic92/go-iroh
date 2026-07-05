//go:build darwin && arm64

package iroh

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	applerdma "github.com/tmc/apple/rdma"
	xrdma "github.com/tmc/apple/x/rdma"
)

type rdmaStreamDevice struct {
	name   string
	handle applerdma.RDMAContext
	once   sync.Once
}

type rdmaStreamProtectionDomain struct {
	dev    *rdmaStreamDevice
	handle applerdma.RDMAPD
	once   sync.Once
}

type rdmaStreamCompletionQueue struct {
	dev    *rdmaStreamDevice
	handle applerdma.RDMACQ
	poller applerdma.IbvCQPoller
	once   sync.Once
}

type rdmaStreamQueuePair struct {
	pd     *rdmaStreamProtectionDomain
	cq     *rdmaStreamCompletionQueue
	handle applerdma.RDMAQP
	poster applerdma.IbvQPPoster
	once   sync.Once
}

type rdmaStreamMemoryRegion struct {
	pd     *rdmaStreamProtectionDomain
	handle applerdma.RDMAMR
	buf    []byte
	lkey   uint32
	mapped bool
	once   sync.Once
}

type rdmaStreamResourceTransport struct {
	dev    *rdmaStreamDevice
	pd     *rdmaStreamProtectionDomain
	cq     *rdmaStreamCompletionQueue
	qp     *rdmaStreamQueuePair
	sendMR *rdmaStreamMemoryRegion
	recvMR *rdmaStreamMemoryRegion
}

func newRDMAStreamResourceTransport(ctx context.Context, device string, bufSize int) (*rdmaStreamResourceTransport, error) {
	if _, err := checkRDMAStreamDeviceActive(ctx, device); err != nil {
		return nil, err
	}
	dev, err := openRDMAStreamDevice(device)
	if err != nil {
		return nil, err
	}
	t := &rdmaStreamResourceTransport{dev: dev}
	if err := t.open(bufSize); err != nil {
		_ = t.close()
		return nil, err
	}
	return t, nil
}

func (t *rdmaStreamResourceTransport) open(bufSize int) error {
	pd, err := newRDMAStreamProtectionDomain(t.dev)
	if err != nil {
		return err
	}
	t.pd = pd
	cq, err := newRDMAStreamCompletionQueue(t.dev, 128)
	if err != nil {
		return err
	}
	t.cq = cq
	qp, err := newRDMAStreamQueuePair(pd, cq)
	if err != nil {
		return err
	}
	t.qp = qp
	if err := initRDMAStreamQueuePair(qp); err != nil {
		return err
	}
	sendMR, err := newRDMAStreamMemoryRegion(pd, bufSize)
	if err != nil {
		return err
	}
	t.sendMR = sendMR
	recvMR, err := newRDMAStreamMemoryRegion(pd, bufSize)
	if err != nil {
		return err
	}
	t.recvMR = recvMR
	return nil
}

func (t *rdmaStreamResourceTransport) sendBuf() []byte { return t.sendMR.buf }
func (t *rdmaStreamResourceTransport) recvBuf() []byte { return t.recvMR.buf }

func (t *rdmaStreamResourceTransport) postSend(offset, length int, id uint64) error {
	return postRDMAStreamSend(t.qp, t.sendMR, offset, length, id)
}

func (t *rdmaStreamResourceTransport) postRecv(offset, length int, id uint64) error {
	return postRDMAStreamRecv(t.qp, t.recvMR, offset, length, id)
}

func (t *rdmaStreamResourceTransport) poll(ctx context.Context, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	return pollRDMAStreamCompletions(ctx, t.cq, out)
}

func (t *rdmaStreamResourceTransport) localDestination() (rdmaStreamDestination, error) {
	return localRDMAStreamDestination(t.qp)
}

func (t *rdmaStreamResourceTransport) connect(ctx context.Context, local, remote rdmaStreamDestination) error {
	if err := readyToReceiveRDMAStream(ctx, t.qp, local, remote); err != nil {
		return err
	}
	return readyToSendRDMAStream(ctx, t.qp, local.PSN)
}

func (t *rdmaStreamResourceTransport) close() error {
	var err error
	if t.qp != nil && t.cq != nil {
		err = errorsJoin(err, drainRDMAStreamQueuePair(t.qp, t.cq))
	}
	err = errorsJoin(err, t.sendMR.Close())
	err = errorsJoin(err, t.recvMR.Close())
	err = errorsJoin(err, t.qp.Close())
	err = errorsJoin(err, t.cq.Close())
	err = errorsJoin(err, t.pd.Close())
	err = errorsJoin(err, t.dev.Close())
	return err
}

func openRDMAStreamDevice(name string) (*rdmaStreamDevice, error) {
	devices, err := applerdma.Devices()
	if err != nil {
		return nil, fmt.Errorf("rdma: list devices: %w", err)
	}
	for _, dev := range devices {
		if name != "" && dev.Name != name {
			continue
		}
		ctx, err := applerdma.IbvOpenDevice(dev.Handle)
		if err != nil {
			return nil, fmt.Errorf("rdma: open device %q: %w", dev.Name, err)
		}
		if ctx == 0 {
			return nil, fmt.Errorf("rdma: open device %q: nil provider handle", dev.Name)
		}
		return &rdmaStreamDevice{name: dev.Name, handle: ctx}, nil
	}
	if name == "" {
		return nil, errorsRDMA("open device: no devices")
	}
	return nil, fmt.Errorf("rdma: open device %q: not found", name)
}

func (d *rdmaStreamDevice) Close() error {
	if d == nil || d.handle == 0 {
		return nil
	}
	var err error
	d.once.Do(func() {
		rc, e := applerdma.IbvCloseDevice(d.handle)
		if e != nil {
			err = fmt.Errorf("rdma: close device %q: %w", d.name, e)
			return
		}
		if rc != 0 {
			err = fmt.Errorf("rdma: close device %q: errno %d", d.name, rc)
			return
		}
		d.handle = 0
	})
	return err
}

func newRDMAStreamProtectionDomain(dev *rdmaStreamDevice) (*rdmaStreamProtectionDomain, error) {
	if dev == nil || dev.handle == 0 {
		return nil, errorsRDMA("alloc protection domain: nil device")
	}
	pd, err := applerdma.IbvAllocPd(dev.handle)
	if err != nil {
		return nil, fmt.Errorf("rdma: alloc protection domain: %w", err)
	}
	if pd == 0 {
		return nil, errorsRDMA("alloc protection domain: nil provider handle")
	}
	return &rdmaStreamProtectionDomain{dev: dev, handle: pd}, nil
}

func (p *rdmaStreamProtectionDomain) Close() error {
	if p == nil || p.handle == 0 {
		return nil
	}
	var err error
	p.once.Do(func() {
		rc, e := applerdma.IbvDeallocPd(p.handle)
		if e != nil {
			err = fmt.Errorf("rdma: dealloc protection domain: %w", e)
			return
		}
		if rc != 0 {
			err = fmt.Errorf("rdma: dealloc protection domain: errno %d", rc)
			return
		}
		p.handle = 0
	})
	return err
}

func newRDMAStreamCompletionQueue(dev *rdmaStreamDevice, capacity int) (*rdmaStreamCompletionQueue, error) {
	if dev == nil || dev.handle == 0 {
		return nil, errorsRDMA("create completion queue: nil device")
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("rdma: create completion queue: capacity %d must be positive", capacity)
	}
	cq, err := applerdma.IbvCreateCq(dev.handle, capacity, 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("rdma: create completion queue: %w", err)
	}
	if cq == 0 {
		return nil, errorsRDMA("create completion queue: nil provider handle")
	}
	poller, err := applerdma.NewIbvCQPoller(cq)
	if err != nil {
		_, _ = applerdma.IbvDestroyCq(cq)
		return nil, fmt.Errorf("rdma: create completion queue poller: %w", err)
	}
	return &rdmaStreamCompletionQueue{dev: dev, handle: cq, poller: poller}, nil
}

func (c *rdmaStreamCompletionQueue) Close() error {
	if c == nil || c.handle == 0 {
		return nil
	}
	var err error
	c.once.Do(func() {
		rc, e := applerdma.IbvDestroyCq(c.handle)
		if e != nil {
			err = fmt.Errorf("rdma: destroy completion queue: %w", e)
			return
		}
		if rc != 0 {
			err = fmt.Errorf("rdma: destroy completion queue: errno %d", rc)
			return
		}
		c.handle = 0
	})
	return err
}

func newRDMAStreamQueuePair(pd *rdmaStreamProtectionDomain, cq *rdmaStreamCompletionQueue) (*rdmaStreamQueuePair, error) {
	if pd == nil || pd.handle == 0 {
		return nil, errorsRDMA("create queue pair: nil protection domain")
	}
	if cq == nil || cq.handle == 0 {
		return nil, errorsRDMA("create queue pair: nil completion queue")
	}
	attr := applerdma.IbvQPInitAttr{
		SendCQ: cq.handle,
		RecvCQ: cq.handle,
		Cap: applerdma.IbvQPCap{
			MaxSendWR:  64,
			MaxRecvWR:  64,
			MaxSendSGE: 1,
			MaxRecvSGE: 1,
		},
		QPType:   applerdma.IBV_QPT_UC,
		SQSigAll: 1,
	}
	qp, err := applerdma.IbvCreateQpAttr(pd.handle, &attr)
	if err != nil {
		return nil, fmt.Errorf("rdma: create queue pair: %w", err)
	}
	if qp == 0 {
		return nil, errorsRDMA("create queue pair: nil provider handle")
	}
	poster, err := applerdma.NewIbvQPPoster(qp)
	if err != nil {
		_, _ = applerdma.IbvDestroyQp(qp)
		return nil, fmt.Errorf("rdma: create queue pair poster: %w", err)
	}
	return &rdmaStreamQueuePair{pd: pd, cq: cq, handle: qp, poster: poster}, nil
}

func (q *rdmaStreamQueuePair) Close() error {
	if q == nil || q.handle == 0 {
		return nil
	}
	var err error
	q.once.Do(func() {
		rc, e := applerdma.IbvDestroyQp(q.handle)
		if e != nil {
			err = fmt.Errorf("rdma: destroy queue pair: %w", e)
			return
		}
		if rc != 0 {
			err = fmt.Errorf("rdma: destroy queue pair: errno %d", rc)
			return
		}
		q.handle = 0
	})
	return err
}

func (q *rdmaStreamQueuePair) number() uint32 {
	if q == nil || q.handle == 0 {
		return 0
	}
	return applerdma.Ibv_qp_num(q.handle)
}

func localRDMAStreamDestination(qp *rdmaStreamQueuePair) (rdmaStreamDestination, error) {
	port, gid, gidIndex, err := localRDMAStreamPortGID(qp)
	if err != nil {
		return rdmaStreamDestination{}, err
	}
	return rdmaStreamDestination{
		LID:       port.LID,
		QPN:       qp.number(),
		PSN:       rdmaStreamDefaultPSN,
		GIDIndex:  uint8(gidIndex),
		GID:       [16]byte(gid),
		ActiveMTU: port.ActiveMTU,
	}, nil
}

func initRDMAStreamQueuePair(qp *rdmaStreamQueuePair) error {
	if qp == nil || qp.handle == 0 {
		return errorsRDMA("change queue pair to INIT: nil queue pair")
	}
	attr := applerdma.IbvQPAttr{
		QPState:       applerdma.IBV_QPS_INIT,
		PortNum:       1,
		PKeyIndex:     0,
		QPAccessFlags: applerdma.IBV_ACCESS_LOCAL_WRITE | applerdma.IBV_ACCESS_REMOTE_READ | applerdma.IBV_ACCESS_REMOTE_WRITE,
	}
	mask := applerdma.IBV_QP_STATE | applerdma.IBV_QP_PKEY_INDEX | applerdma.IBV_QP_PORT | applerdma.IBV_QP_ACCESS_FLAGS
	return modifyRDMAStreamQueuePair(qp, &attr, mask, "INIT")
}

func readyToReceiveRDMAStream(ctx context.Context, qp *rdmaStreamQueuePair, local, remote rdmaStreamDestination) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rdma: change queue pair to RTR: %w", err)
	}
	if qp == nil || qp.handle == 0 {
		return errorsRDMA("change queue pair to RTR: nil queue pair")
	}
	attr, mask, err := xrdma.RTRAttr(xrdma.LocalQP{
		PortNum:   1,
		GIDIndex:  int(local.GIDIndex),
		ActiveMTU: local.ActiveMTU,
	}, xrdma.RemoteQP{
		LID:       remote.LID,
		QPN:       remote.QPN,
		PSN:       remote.PSN,
		GIDIndex:  int(remote.GIDIndex),
		GID:       applerdma.IbvGID(remote.GID),
		UseGlobal: remote.GID != ([16]byte{}),
		ActiveMTU: remote.ActiveMTU,
	}, xrdma.RTRPolicy{
		ZeroDLIDWhenGlobal: true,
		HopLimit:           1,
	})
	if err != nil {
		return fmt.Errorf("rdma: build rtr attrs: %w", err)
	}
	return modifyRDMAStreamQueuePair(qp, &attr, mask, "RTR")
}

func readyToSendRDMAStream(ctx context.Context, qp *rdmaStreamQueuePair, psn uint32) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("rdma: change queue pair to RTS: %w", err)
	}
	if qp == nil || qp.handle == 0 {
		return errorsRDMA("change queue pair to RTS: nil queue pair")
	}
	attr := applerdma.IbvQPAttr{
		QPState: applerdma.IBV_QPS_RTS,
		SQPSN:   psn,
	}
	mask := applerdma.IBV_QP_STATE | applerdma.IBV_QP_SQ_PSN
	return modifyRDMAStreamQueuePair(qp, &attr, mask, "RTS")
}

func modifyRDMAStreamQueuePair(qp *rdmaStreamQueuePair, attr *applerdma.IbvQPAttr, mask int, state string) error {
	rc, err := applerdma.IbvModifyQpAttr(qp.handle, attr, mask)
	if err != nil || rc != 0 {
		return fmt.Errorf("rdma: change queue pair to %s: %w", state, applerdma.NewModifyQPError(qp.handle, attr, mask, rc, err))
	}
	return nil
}

func localRDMAStreamPortGID(qp *rdmaStreamQueuePair) (applerdma.IbvPortAttr, applerdma.IbvGID, int, error) {
	if qp == nil || qp.handle == 0 || qp.pd == nil || qp.pd.dev == nil {
		return applerdma.IbvPortAttr{}, applerdma.IbvGID{}, 0, errorsRDMA("local destination: nil queue pair")
	}
	port, gids, selected, err := queryRDMAStreamPortGIDs(qp.pd.dev.handle, 0)
	if err != nil {
		return applerdma.IbvPortAttr{}, applerdma.IbvGID{}, 0, err
	}
	for _, entry := range gids {
		if entry.index == selected {
			return port, entry.gid, selected, nil
		}
	}
	return port, applerdma.IbvGID{}, selected, errorsRDMA("local destination: no trusted route gid")
}

type rdmaStreamPortGID struct {
	index int
	gid   applerdma.IbvGID
}

func queryRDMAStreamPortGIDs(ctx applerdma.RDMAContext, maxGIDs int) (applerdma.IbvPortAttr, []rdmaStreamPortGID, int, error) {
	var port applerdma.IbvPortAttr
	if rc, err := applerdma.IbvQueryPortAttr(ctx, 1, &port); err != nil {
		return applerdma.IbvPortAttr{}, nil, 0, fmt.Errorf("rdma: query port: %w", err)
	} else if rc != 0 {
		return applerdma.IbvPortAttr{}, nil, 0, fmt.Errorf("rdma: query port: errno %d", rc)
	}
	n := int(port.GIDTblLen)
	if maxGIDs > 0 && maxGIDs < n {
		n = maxGIDs
	}
	var gids []rdmaStreamPortGID
	for i := 0; i < n; i++ {
		var gid applerdma.IbvGID
		rc, err := applerdma.IbvQueryGidInto(ctx, 1, i, &gid)
		if err != nil || rc != 0 {
			continue
		}
		gids = append(gids, rdmaStreamPortGID{index: i, gid: gid})
	}
	selected := selectRDMAStreamPortGID(gids)
	return port, gids, selected, nil
}

func selectRDMAStreamPortGID(gids []rdmaStreamPortGID) int {
	for _, entry := range gids {
		if isZeroRDMAStreamGID(entry.gid) || entry.index == 0 {
			continue
		}
		if isIPv4MappedRDMAStreamGID(entry.gid) {
			return entry.index
		}
	}
	for _, entry := range gids {
		if entry.index == 1 && !isZeroRDMAStreamGID(entry.gid) {
			return entry.index
		}
	}
	for _, entry := range gids {
		if !isZeroRDMAStreamGID(entry.gid) {
			return entry.index
		}
	}
	return -1
}

func isZeroRDMAStreamGID(gid applerdma.IbvGID) bool {
	for _, b := range gid {
		if b != 0 {
			return false
		}
	}
	return true
}

func isIPv4MappedRDMAStreamGID(gid applerdma.IbvGID) bool {
	for i := 0; i < 10; i++ {
		if gid[i] != 0 {
			return false
		}
	}
	return gid[10] == 0xff && gid[11] == 0xff
}

func newRDMAStreamMemoryRegion(pd *rdmaStreamProtectionDomain, size int) (*rdmaStreamMemoryRegion, error) {
	if pd == nil || pd.handle == 0 {
		return nil, errorsRDMA("alloc memory region: nil protection domain")
	}
	if size <= 0 {
		return nil, fmt.Errorf("rdma: alloc memory region: size %d must be positive", size)
	}
	buf, err := syscall.Mmap(-1, 0, roundRDMAStreamPage(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("rdma: mmap memory region: %w", err)
	}
	mr, err := registerRDMAStreamMemory(pd, buf)
	if err != nil {
		_ = syscall.Munmap(buf)
		return nil, err
	}
	mr.mapped = true
	return mr, nil
}

func registerRDMAStreamMemory(pd *rdmaStreamProtectionDomain, buf []byte) (*rdmaStreamMemoryRegion, error) {
	if len(buf) == 0 {
		return nil, errorsRDMA("register memory: empty buffer")
	}
	mr, err := applerdma.IbvRegMr(pd.handle, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(len(buf)), applerdma.IBV_ACCESS_LOCAL_WRITE|applerdma.IBV_ACCESS_REMOTE_WRITE|applerdma.IBV_ACCESS_REMOTE_READ)
	if err != nil {
		return nil, fmt.Errorf("rdma: register memory: %w", err)
	}
	if mr == 0 {
		return nil, errorsRDMA("register memory: nil provider handle")
	}
	return &rdmaStreamMemoryRegion{
		pd:     pd,
		handle: mr,
		buf:    buf,
		lkey:   applerdma.Ibv_mr_lkey(mr),
	}, nil
}

func (m *rdmaStreamMemoryRegion) Close() error {
	if m == nil || m.handle == 0 {
		return nil
	}
	var err error
	m.once.Do(func() {
		rc, e := applerdma.IbvDeregMr(m.handle)
		if e != nil {
			err = fmt.Errorf("rdma: dereg memory: %w", e)
			return
		}
		if rc != 0 {
			err = fmt.Errorf("rdma: dereg memory: errno %d", rc)
			return
		}
		if m.mapped {
			if e := syscall.Munmap(m.buf); e != nil {
				err = fmt.Errorf("rdma: unmap memory: %w", e)
				return
			}
		}
		m.handle = 0
		m.buf = nil
	})
	return err
}

func postRDMAStreamSend(qp *rdmaStreamQueuePair, mr *rdmaStreamMemoryRegion, offset, length int, id uint64) error {
	return postRDMAStreamMany(qp, mr, []rdmaStreamPostWork{{Offset: offset, Length: length, ID: id}}, true)
}

func postRDMAStreamRecv(qp *rdmaStreamQueuePair, mr *rdmaStreamMemoryRegion, offset, length int, id uint64) error {
	return postRDMAStreamMany(qp, mr, []rdmaStreamPostWork{{Offset: offset, Length: length, ID: id}}, false)
}

func postRDMAStreamMany(qp *rdmaStreamQueuePair, mr *rdmaStreamMemoryRegion, works []rdmaStreamPostWork, send bool) error {
	op := "post recvs"
	if send {
		op = "post sends"
	}
	if qp == nil || qp.handle == 0 {
		return fmt.Errorf("rdma: %s: nil queue pair", op)
	}
	if mr == nil || mr.handle == 0 {
		return fmt.Errorf("rdma: %s: nil memory region", op)
	}
	if len(works) == 0 {
		return nil
	}
	var sgeBuf [8]applerdma.IbvSGE
	sges := sgeBuf[:]
	if len(works) > len(sges) {
		sges = make([]applerdma.IbvSGE, len(works))
	}
	if send {
		var wrBuf [8]applerdma.IbvSendWR
		wrs := wrBuf[:]
		if len(works) > len(wrs) {
			wrs = make([]applerdma.IbvSendWR, len(works))
		}
		n, err := buildRDMAStreamSendWorkRequests("rdma: "+op, mr, works, wrs, sges)
		if err != nil || n == 0 {
			return err
		}
		var bad *applerdma.IbvSendWR
		if rc := qp.poster.PostSend(&wrs[0], &bad); rc != 0 {
			return fmt.Errorf("rdma: %s: errno %d", op, rc)
		}
		return nil
	}
	var wrBuf [8]applerdma.IbvRecvWR
	wrs := wrBuf[:]
	if len(works) > len(wrs) {
		wrs = make([]applerdma.IbvRecvWR, len(works))
	}
	n, err := buildRDMAStreamRecvWorkRequests("rdma: "+op, mr, works, wrs, sges)
	if err != nil || n == 0 {
		return err
	}
	var bad *applerdma.IbvRecvWR
	if rc := qp.poster.PostRecv(&wrs[0], &bad); rc != 0 {
		return fmt.Errorf("rdma: %s: errno %d", op, rc)
	}
	return nil
}

func buildRDMAStreamSendWorkRequests(op string, mr *rdmaStreamMemoryRegion, works []rdmaStreamPostWork, wrs []applerdma.IbvSendWR, sges []applerdma.IbvSGE) (int, error) {
	n := 0
	for i, work := range works {
		if err := validateRDMAStreamPostWork(op, mr, i, work); err != nil {
			return 0, err
		}
		if work.Length == 0 {
			continue
		}
		sges[n] = applerdma.IbvSGE{
			Addr:   uint64(uintptr(unsafe.Pointer(&mr.buf[work.Offset]))),
			Length: uint32(work.Length),
			LKey:   mr.lkey,
		}
		wrs[n] = applerdma.IbvSendWR{
			WRID:      work.ID,
			SGList:    &sges[n],
			NumSGE:    1,
			Opcode:    applerdma.IBV_WR_SEND,
			SendFlags: applerdma.IBV_SEND_SIGNALED,
		}
		if n > 0 {
			wrs[n-1].Next = &wrs[n]
		}
		n++
	}
	return n, nil
}

func buildRDMAStreamRecvWorkRequests(op string, mr *rdmaStreamMemoryRegion, works []rdmaStreamPostWork, wrs []applerdma.IbvRecvWR, sges []applerdma.IbvSGE) (int, error) {
	n := 0
	for i, work := range works {
		if err := validateRDMAStreamPostWork(op, mr, i, work); err != nil {
			return 0, err
		}
		if work.Length == 0 {
			continue
		}
		sges[n] = applerdma.IbvSGE{
			Addr:   uint64(uintptr(unsafe.Pointer(&mr.buf[work.Offset]))),
			Length: uint32(work.Length),
			LKey:   mr.lkey,
		}
		wrs[n] = applerdma.IbvRecvWR{
			WRID:   work.ID,
			SGList: &sges[n],
			NumSGE: 1,
		}
		if n > 0 {
			wrs[n-1].Next = &wrs[n]
		}
		n++
	}
	return n, nil
}

func validateRDMAStreamPostWork(op string, mr *rdmaStreamMemoryRegion, index int, work rdmaStreamPostWork) error {
	if work.Offset < 0 || work.Length < 0 || work.Offset > len(mr.buf) || work.Length > len(mr.buf)-work.Offset {
		return fmt.Errorf("%s: work %d range [%d,%s) outside buffer length %d", op, index, work.Offset, rdmaStreamPostEnd(work), len(mr.buf))
	}
	return nil
}

func pollRDMAStreamCompletions(ctx context.Context, cq *rdmaStreamCompletionQueue, out []rdmaStreamWorkRequest) ([]rdmaStreamWorkRequest, error) {
	if cq == nil || cq.handle == 0 {
		return nil, errorsRDMA("poll completions: nil completion queue")
	}
	if len(out) == 0 {
		return out, nil
	}
	want := len(out)
	var wc [8]applerdma.IbvWC
	works := out[:0]
	spins := 0
	for len(works) < want {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := cq.poller.Poll(len(wc), &wc[0])
		if n < 0 {
			return nil, fmt.Errorf("rdma: poll completions: errno %d", n)
		}
		if n > len(wc) {
			return nil, fmt.Errorf("rdma: poll completions: returned %d completions, max %d", n, len(wc))
		}
		if n == 0 {
			spins++
			if spins >= 16384 {
				time.Sleep(10 * time.Microsecond)
			}
			continue
		}
		next, err := appendRDMAStreamWorkRequests(works, wc[:], n)
		if err != nil {
			return nil, err
		}
		works = next
	}
	return works, nil
}

func rdmaStreamWorkRequests(wc []applerdma.IbvWC, n int) ([]rdmaStreamWorkRequest, error) {
	return appendRDMAStreamWorkRequests(make([]rdmaStreamWorkRequest, 0, n), wc, n)
}

func appendRDMAStreamWorkRequests(out []rdmaStreamWorkRequest, wc []applerdma.IbvWC, n int) ([]rdmaStreamWorkRequest, error) {
	if n < 0 || n > len(wc) {
		return nil, fmt.Errorf("rdma: completion count %d outside buffer length %d", n, len(wc))
	}
	for i := 0; i < n; i++ {
		if wc[i].Status != applerdma.IBV_WC_SUCCESS {
			return nil, fmt.Errorf("rdma: completion id %d opcode %d status %d", wc[i].WRID, wc[i].Opcode, wc[i].Status)
		}
		out = append(out, rdmaStreamWorkRequest{
			ID:     wc[i].WRID,
			Opcode: int(wc[i].Opcode),
			Bytes:  int(wc[i].ByteLen),
			Status: int(wc[i].Status),
		})
	}
	return out, nil
}

func drainRDMAStreamQueuePair(qp *rdmaStreamQueuePair, cq *rdmaStreamCompletionQueue) error {
	if qp == nil || qp.handle == 0 {
		return nil
	}
	if err := applerdma.IbvModifyQpToErr(qp.handle); err != nil {
		return fmt.Errorf("rdma: flush queue pair to error: %w", err)
	}
	if cq == nil || cq.handle == 0 {
		return nil
	}
	var wc [8]applerdma.IbvWC
	const maxPolls = 4096
	for polls := 0; polls < maxPolls; polls++ {
		if n := cq.poller.Poll(len(wc), &wc[0]); n <= 0 {
			return nil
		}
	}
	return fmt.Errorf("rdma: drain queue pair: completions still outstanding after %d polls", maxPolls)
}

func rdmaStreamPostEnd(work rdmaStreamPostWork) string {
	max := int(^uint(0) >> 1)
	if work.Offset < 0 || work.Length < 0 || work.Length > max-work.Offset {
		return "overflow"
	}
	return fmt.Sprint(work.Offset + work.Length)
}

func roundRDMAStreamPage(n int) int {
	const page = 16 * 1024
	if n%page == 0 {
		return n
	}
	return n + page - n%page
}

func errorsRDMA(msg string) error {
	return fmt.Errorf("rdma: %s", msg)
}

func errorsJoin(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

const rdmaStreamDefaultPSN = 7
