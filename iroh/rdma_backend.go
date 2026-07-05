package iroh

import (
	"context"
	"net"

	"github.com/tmc/go-iroh/netaddr"
)

type rdmaStreamBackend interface {
	DialStream(context.Context, uint64, netaddr.CustomAddr, StreamOptions) (net.Conn, error)
	ListenStreams(context.Context, uint64, func(StreamAccept) error) error
}

var activeRDMAStreamBackend rdmaStreamBackend = unsupportedRDMAStreamBackend{}

func dialRDMAStream(ctx context.Context, id uint64, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	return activeRDMAStreamBackend.DialStream(ctx, id, remote, opts)
}

func listenRDMAStreams(ctx context.Context, id uint64, accept func(StreamAccept) error) error {
	return activeRDMAStreamBackend.ListenStreams(ctx, id, accept)
}
