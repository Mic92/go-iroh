package iroh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

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
	id    uint64
	ctrl  net.Listener
	close sync.Once
}

// NewRDMAStreamTransport returns an RDMA stream transport.
func NewRDMAStreamTransport(id uint64) (*RDMAStreamTransport, error) {
	if id == 0 {
		return nil, errors.New("iroh: zero rdma stream transport id")
	}
	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		return nil, fmt.Errorf("rdma: listen control: %w", err)
	}
	return &RDMAStreamTransport{id: id, ctrl: ln}, nil
}

func (t *RDMAStreamTransport) ID() uint64 { return t.id }

func (t *RDMAStreamTransport) LinkClass() TransportLinkClass { return TransportLinkRDMA }

func (t *RDMAStreamTransport) LocalAddrs(ctx context.Context) ([]netaddr.CustomAddr, error) {
	return localRDMAStreamAddrs(ctx, t.id, t.localControlAddrs())
}

func (t *RDMAStreamTransport) DialStream(ctx context.Context, remote netaddr.CustomAddr, opts StreamOptions) (net.Conn, error) {
	return dialRDMAStream(ctx, t.id, remote, opts)
}

func (t *RDMAStreamTransport) ListenStreams(ctx context.Context, accept func(StreamAccept) error) error {
	return listenRDMAStreams(ctx, t.id, t.ctrl, accept)
}

func (t *RDMAStreamTransport) Close() error {
	var err error
	t.close.Do(func() {
		err = t.ctrl.Close()
	})
	return err
}

func (t *RDMAStreamTransport) localControlAddrs() []rdmaStreamControlAddr {
	tcpAddr, ok := t.ctrl.Addr().(*net.TCPAddr)
	if !ok {
		return []rdmaStreamControlAddr{{Addr: t.ctrl.Addr().String()}}
	}
	if !tcpAddr.IP.IsUnspecified() {
		return []rdmaStreamControlAddr{{Addr: t.ctrl.Addr().String()}}
	}
	links, err := LocalTransportLinkAddrs()
	if err != nil {
		return []rdmaStreamControlAddr{{Addr: t.ctrl.Addr().String()}}
	}
	out := make([]rdmaStreamControlAddr, 0, len(links))
	for _, link := range links {
		if link.Class != TransportLinkThunderbolt && link.Class != TransportLinkWiredLAN && link.Class != TransportLinkLAN && link.Class != TransportLinkLoopback {
			continue
		}
		control, ok := tcpDialAddrFromLinkAddr(link, tcpAddr.Port)
		if ok {
			out = append(out, rdmaStreamControlAddr{Addr: control, Class: link.Class})
		}
	}
	if len(out) == 0 {
		return []rdmaStreamControlAddr{{Addr: t.ctrl.Addr().String()}}
	}
	return out
}
