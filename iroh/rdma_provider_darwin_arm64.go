//go:build darwin && arm64

package iroh

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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
	out, err := localRDMAIOReg(ctx)
	if err != nil {
		return nil, err
	}
	return darwinRDMALinksFromIOReg(out)
}

func darwinRDMALinksFromIOReg(out []byte) ([]RDMALink, error) {
	links := parseDarwinRDMALinks(out)
	if len(links) == 0 {
		if reason := parseDarwinRDMAProviderBlocked(out); reason != "" {
			return nil, fmt.Errorf("%w: %s", ErrRDMAUnsupported, reason)
		}
		return nil, ErrRDMAUnsupported
	}
	return links, nil
}

func localRDMAIOReg(ctx context.Context) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "ioreg", "-r", "-c", "AppleThunderboltRDMAInterface", "-l").Output()
	if err != nil {
		return nil, fmt.Errorf("rdma: ioreg AppleThunderboltRDMAInterface: %w", err)
	}
	return out, nil
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
	links := make([]RDMALink, 0, bytes.Count(out, darwinRDMABlockSep))
	forEachDarwinRDMABlock(out, func(block []byte) bool {
		name := rdmaBlockName(block)
		if name == "" {
			return true
		}
		if propertyInt(block, "CurrentPowerState") != 2 {
			return true
		}
		if darwinRDMABlockProviderBlocked(block) != "" {
			return true
		}
		links = append(links, RDMALink{
			Device:    name,
			State:     rdmaPortActive,
			LinkLayer: rdmaLinkLayerThunderbolt,
			ActiveMTU: 5,
		})
		return true
	})
	return links
}

func darwinRDMAProviderBlocked(ctx context.Context) (string, error) {
	out, err := localRDMAIOReg(ctx)
	if err != nil {
		return "", err
	}
	return parseDarwinRDMAProviderBlocked(out), nil
}

func parseDarwinRDMAProviderBlocked(out []byte) string {
	var blocked string
	forEachDarwinRDMABlock(out, func(block []byte) bool {
		name := rdmaBlockName(block)
		if name == "" || propertyInt(block, "CurrentPowerState") != 2 {
			return true
		}
		if reason := darwinRDMABlockProviderBlocked(block); reason != "" {
			blocked = name + " " + reason
			return false
		}
		return true
	})
	return blocked
}

func darwinRDMABlockProviderBlocked(block []byte) string {
	var reason string
	if bytes.Contains(block, []byte("AppleThunderboltRDMAProtectionDomain")) && bytes.Contains(block, []byte("inactive, busy 1")) {
		reason = "has inactive busy protection domain"
	} else if bytes.Contains(block, []byte("AppleThunderboltRDMAQueuePair")) && bytes.Contains(block, []byte("inactive, busy 1")) {
		reason = "has inactive busy queue pair"
	}
	if reason == "" {
		return ""
	}
	if creators := rdmaBlockUserClientCreators(block); len(creators) > 0 {
		return reason + " from " + strings.Join(creators, ", ")
	}
	return reason
}

func forEachDarwinRDMABlock(out []byte, yield func([]byte) bool) {
	for {
		i := bytes.Index(out, darwinRDMABlockSep)
		if i < 0 {
			if len(out) > 0 {
				yield(out)
			}
			return
		}
		if i > 0 && !yield(out[:i]) {
			return
		}
		out = out[i+len(darwinRDMABlockSep):]
	}
}

func rdmaBlockName(block []byte) string {
	i := bytes.Index(block, []byte("rdma_"))
	if i < 0 {
		return ""
	}
	j := i + len("rdma_")
	for j < len(block) && isRDMABlockNameByte(block[j]) {
		j++
	}
	if j == i+len("rdma_") {
		return ""
	}
	return string(block[i:j])
}

func isRDMABlockNameByte(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '_'
}

func rdmaBlockUserClientCreators(block []byte) []string {
	const prefix = `"IOUserClientCreator" = "`
	var out []string
	for {
		i := bytes.Index(block, []byte(prefix))
		if i < 0 {
			return out
		}
		block = block[i+len(prefix):]
		j := bytes.IndexByte(block, '"')
		if j < 0 {
			return out
		}
		if j > 0 {
			out = append(out, string(block[:j]))
		}
		block = block[j+1:]
	}
}

func propertyInt(block []byte, name string) int {
	prefix := propertyIntPrefix(name)
	i := bytes.Index(block, prefix)
	if i < 0 {
		return 0
	}
	p := block[i+len(prefix):]
	j := 0
	for j < len(p) && '0' <= p[j] && p[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0
	}
	n := 0
	for _, c := range p[:j] {
		n = n*10 + int(c-'0')
	}
	return n
}

func propertyIntPrefix(name string) []byte {
	if name == "CurrentPowerState" {
		return currentPowerStateProperty
	}
	return []byte(`"` + name + `"=`)
}

var darwinRDMABlockSep = []byte("\n+-o ")

var currentPowerStateProperty = []byte(`"CurrentPowerState"=`)
