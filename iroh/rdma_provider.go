package iroh

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/netaddr"
)

// RDMALink describes a local RDMA device that can be advertised.
type RDMALink struct {
	Device    string
	State     int32
	LinkLayer uint8
	ActiveMTU int32
}

func rdmaStreamDialAddr(link RDMALink) string {
	return "rdma:" + link.Device
}

func rdmaStreamAddr(id uint64, link RDMALink) netaddr.CustomAddr {
	return NewStreamLinkAddr(id, TransportLinkRDMA, link.Device, rdmaStreamDialAddr(link))
}

func localRDMAStreamAddrs(ctx context.Context, id uint64) ([]netaddr.CustomAddr, error) {
	links, err := LocalRDMALinks(ctx)
	if err != nil {
		return nil, err
	}
	addrs := make([]netaddr.CustomAddr, 0, len(links))
	for _, link := range links {
		addrs = append(addrs, rdmaStreamAddr(id, link))
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no active rdma devices", ErrRDMAUnsupported)
	}
	return addrs, nil
}
