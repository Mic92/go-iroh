//go:build darwin && arm64

package iroh

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
)

const (
	rdmaPortActive int32 = 4
)

// RDMAAvailable reports whether an active Apple Thunderbolt RDMA interface exists.
func RDMAAvailable() bool {
	links, err := LocalRDMALinks(context.Background())
	return err == nil && len(links) > 0
}

// LocalRDMALinks returns active local RDMA devices usable for advertisement.
func LocalRDMALinks(ctx context.Context) ([]RDMALink, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := exec.CommandContext(ctx, "ioreg", "-r", "-c", "AppleThunderboltRDMAInterface", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("rdma: ioreg AppleThunderboltRDMAInterface: %w", err)
	}
	links := parseDarwinRDMALinks(out)
	if len(links) == 0 {
		return nil, ErrRDMAUnsupported
	}
	return links, nil
}

func checkRDMAStreamDeviceActive(ctx context.Context, device string) (RDMALink, error) {
	links, err := LocalRDMALinks(ctx)
	if err != nil {
		return RDMALink{}, err
	}
	return activeRDMAStreamDevice(links, device)
}

func activeRDMAStreamDevice(links []RDMALink, device string) (RDMALink, error) {
	for _, link := range links {
		if device == "" || link.Device == device {
			return link, nil
		}
	}
	if device == "" {
		return RDMALink{}, ErrRDMAUnsupported
	}
	return RDMALink{}, fmt.Errorf("rdma: active device %q: %w", device, ErrRDMAUnsupported)
}

func parseDarwinRDMALinks(out []byte) []RDMALink {
	blocks := bytes.Split(out, []byte("\n+-o "))
	links := make([]RDMALink, 0, len(blocks))
	for _, block := range blocks {
		name := rdmaBlockName(block)
		if name == "" {
			continue
		}
		if propertyInt(block, "CurrentPowerState") != 2 {
			continue
		}
		links = append(links, RDMALink{
			Device:    name,
			State:     rdmaPortActive,
			LinkLayer: rdmaLinkLayerThunderbolt,
			ActiveMTU: 5,
		})
	}
	return links
}

func rdmaBlockName(block []byte) string {
	m := rdmaBlockNameRE.Find(block)
	if len(m) == 0 {
		return ""
	}
	return string(m)
}

func propertyInt(block []byte, name string) int {
	re := regexp.MustCompile(regexp.QuoteMeta(name) + `"=([0-9]+)`)
	m := re.FindSubmatch(block)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

var rdmaBlockNameRE = regexp.MustCompile(`rdma_[[:alnum:]_]+`)
