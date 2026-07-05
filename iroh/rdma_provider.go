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

const rdmaLinkLayerThunderbolt uint8 = 100

type rdmaStreamDialInfo struct {
	Device  string
	Control string
}

type rdmaStreamControlAddr struct {
	Addr  string
	Class TransportLinkClass
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

func localRDMAStreamAddrs(ctx context.Context, id uint64, controls []rdmaStreamControlAddr) ([]netaddr.CustomAddr, error) {
	links, err := LocalRDMALinks(ctx)
	if err != nil {
		return nil, err
	}
	if len(controls) == 0 {
		controls = []rdmaStreamControlAddr{{}}
	}
	addrs := make([]netaddr.CustomAddr, 0, len(links)*len(controls))
	var controlBuf [8]rdmaStreamControlAddr
	for _, link := range links {
		linkControls := rdmaStreamControlsForLink(link, controls, controlBuf[:0])
		for _, control := range linkControls {
			addrs = append(addrs, rdmaStreamAddr(id, link, control.Addr))
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no active rdma devices", ErrRDMAUnsupported)
	}
	return addrs, nil
}

func rdmaStreamControlsForLink(link RDMALink, controls, dst []rdmaStreamControlAddr) []rdmaStreamControlAddr {
	if link.LinkLayer != rdmaLinkLayerThunderbolt {
		return controls
	}
	for _, control := range controls {
		if control.Class == TransportLinkThunderbolt {
			dst = append(dst, control)
		}
	}
	if len(dst) == 0 {
		return controls
	}
	return dst
}
