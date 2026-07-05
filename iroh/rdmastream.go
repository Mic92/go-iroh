package iroh

import (
	"context"
	"errors"
	"net"

	"github.com/tmc/go-iroh/netaddr"
)

// ErrRDMAUnsupported reports that no RDMA data path is available.
var ErrRDMAUnsupported = errors.New("rdma: unsupported on this platform")

// RDMAStreamTransport is an RDMA-backed stream transport.
//
// It advertises the RDMA link class so negotiation can prefer RDMA when both
// peers support it. The data path is available only when a platform backend can
// open and connect a local RDMA device.
type RDMAStreamTransport struct {
	id uint64
}

// NewRDMAStreamTransport returns an RDMA stream transport.
func NewRDMAStreamTransport(id uint64) (*RDMAStreamTransport, error) {
	if id == 0 {
		return nil, errors.New("iroh: zero rdma stream transport id")
	}
	return &RDMAStreamTransport{id: id}, nil
}

func (t *RDMAStreamTransport) ID() uint64 { return t.id }

func (t *RDMAStreamTransport) LinkClass() TransportLinkClass { return TransportLinkRDMA }

func (t *RDMAStreamTransport) LocalAddrs(ctx context.Context) ([]netaddr.CustomAddr, error) {
	return localRDMAStreamAddrs(ctx, t.id)
}

func (t *RDMAStreamTransport) DialStream(ctx context.Context, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	return dialRDMAStream(ctx, t.id, remote, opts)
}

func (t *RDMAStreamTransport) ListenStreams(ctx context.Context, accept func(StreamAccept) error) error {
	return listenRDMAStreams(ctx, t.id, accept)
}
