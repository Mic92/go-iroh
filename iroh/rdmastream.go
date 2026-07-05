package iroh

import (
	"context"
	"errors"
	"net"

	"github.com/tmc/go-iroh/netaddr"
)

// ErrRDMAUnsupported reports that no RDMA data path is available.
var ErrRDMAUnsupported = errors.New("rdma: unsupported on this platform")

// RDMAStreamTransport is a placeholder for an RDMA-backed stream transport.
//
// It advertises the RDMA link class so negotiation can prefer RDMA when both
// peers support it. The data path is unsupported unless a platform-specific
// libibverbs or RoCE backend is added.
type RDMAStreamTransport struct {
	id uint64
}

// NewRDMAStreamTransport returns an RDMA stream transport stub.
func NewRDMAStreamTransport(id uint64) (*RDMAStreamTransport, error) {
	if id == 0 {
		return nil, errors.New("iroh: zero rdma stream transport id")
	}
	return &RDMAStreamTransport{id: id}, nil
}

func (t *RDMAStreamTransport) ID() uint64 { return t.id }

func (t *RDMAStreamTransport) LinkClass() TransportLinkClass { return TransportLinkRDMA }

func (t *RDMAStreamTransport) LocalAddrs(ctx context.Context) ([]netaddr.CustomAddr, error) {
	_ = ctx
	return nil, ErrRDMAUnsupported
}

func (t *RDMAStreamTransport) DialStream(ctx context.Context, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	_, _, _ = ctx, remote, opts
	return nil, ErrRDMAUnsupported
}

func (t *RDMAStreamTransport) ListenStreams(ctx context.Context, accept func(StreamAccept) error) error {
	_, _ = ctx, accept
	return ErrRDMAUnsupported
}
