package socket

import (
	"context"

	"github.com/tmc/go-iroh/netaddr"
)

// CustomDatagram is one datagram received by a [CustomTransport].
type CustomDatagram struct {
	Remote   netaddr.CustomAddr
	Local    netaddr.CustomAddr
	HasLocal bool
	Data     []byte
}

// CustomTransport is a pluggable transport backend for custom addresses. It is
// intentionally small: the transport owns its wire format and reports datagrams
// as iroh custom addresses for the magic socket to map into qng paths.
type CustomTransport interface {
	// Serve runs the transport until ctx is done. Each received datagram should
	// be passed to recv. recv reports false when the magic socket is shutting
	// down or its receive queue is full.
	Serve(ctx context.Context, recv func(CustomDatagram) bool)

	// Send sends p to remote. local is nil when qng did not select a specific
	// local custom address for the path.
	Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool
}

type customTransport struct {
	transport CustomTransport
	recvCh    chan<- recvBatch
}

func newCustomTransport(t CustomTransport, recvCh chan<- recvBatch) *customTransport {
	return &customTransport{transport: t, recvCh: recvCh}
}

func (t *customTransport) Serve(ctx context.Context) {
	t.transport.Serve(ctx, func(d CustomDatagram) bool {
		data := make([]byte, len(d.Data))
		copy(data, d.Data)
		select {
		case t.recvCh <- recvBatch{
			data: data,
			info: RecvInfo{Remote: CustomAddr(d.Remote), Local: d.Local, HasLocal: d.HasLocal},
		}:
			return true
		case <-ctx.Done():
			return false
		default:
			return false
		}
	})
}

func (t *customTransport) Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool {
	data := make([]byte, len(p))
	copy(data, p)
	return t.transport.Send(remote, local, data)
}
