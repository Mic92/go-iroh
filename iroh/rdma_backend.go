package iroh

import (
	"context"
	"net"

	"github.com/tmc/go-iroh/netaddr"
)

func dialRDMAStream(ctx context.Context, id uint64, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	return platformDialRDMAStream(ctx, id, remote, opts)
}

func listenRDMAStreams(ctx context.Context, id uint64, accept func(StreamAccept) error) error {
	return platformListenRDMAStreams(ctx, id, accept)
}
