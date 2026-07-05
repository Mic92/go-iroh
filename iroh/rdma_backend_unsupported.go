package iroh

import (
	"context"
	"net"

	"github.com/tmc/go-iroh/netaddr"
)

func platformDialRDMAStream(ctx context.Context, id uint64, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	_, _, _, _ = ctx, id, remote, opts
	return nil, ErrRDMAUnsupported
}

func platformListenRDMAStreams(ctx context.Context, id uint64, accept func(StreamAccept) error) error {
	_, _, _ = ctx, id, accept
	return ErrRDMAUnsupported
}
