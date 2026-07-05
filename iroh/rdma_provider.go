package iroh

import (
	"context"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/netaddr"
)

// RDMALink describes a local RDMA device that can be advertised.
type RDMALink struct {
	Device    string
	State     int32
	LinkLayer uint8
	ActiveMTU int32
}

type rdmaStreamDialInfo struct {
	Device  string
	Control string
}

func rdmaStreamDialAddr(link RDMALink, control string) string {
	if control == "" {
		return "rdma:" + link.Device
	}
	return "rdma:" + link.Device + "@" + control
}

func parseRDMAStreamDialAddr(s string) (rdmaStreamDialInfo, error) {
	if !strings.HasPrefix(s, "rdma:") {
		return rdmaStreamDialInfo{}, fmt.Errorf("rdma: malformed dial address %q", s)
	}
	rest := strings.TrimPrefix(s, "rdma:")
	device, control, ok := strings.Cut(rest, "@")
	if device == "" {
		return rdmaStreamDialInfo{}, fmt.Errorf("rdma: malformed dial address %q", s)
	}
	if !ok {
		return rdmaStreamDialInfo{Device: device}, nil
	}
	if control == "" {
		return rdmaStreamDialInfo{}, fmt.Errorf("rdma: malformed dial address %q", s)
	}
	return rdmaStreamDialInfo{Device: device, Control: control}, nil
}

func rdmaStreamAddr(id uint64, link RDMALink, control string) netaddr.CustomAddr {
	return NewStreamLinkAddr(id, TransportLinkRDMA, link.Device, rdmaStreamDialAddr(link, control))
}

func localRDMAStreamAddrs(ctx context.Context, id uint64, controls []string) ([]netaddr.CustomAddr, error) {
	links, err := LocalRDMALinks(ctx)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		controls = []string{""}
	}
	addrs := make([]netaddr.CustomAddr, 0, len(links)*len(controls))
	for _, link := range links {
		for _, control := range controls {
			addrs = append(addrs, rdmaStreamAddr(id, link, control))
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no active rdma devices", ErrRDMAUnsupported)
	}
	return addrs, nil
}
