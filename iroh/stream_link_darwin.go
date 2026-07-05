//go:build darwin

package iroh

import (
	"net"
	"os/exec"
	"strings"
	"sync"
)

var appleNetworkHardwarePorts = struct {
	sync.Once
	classes map[string]TransportLinkClass
	skip    map[string]bool
}{}

func platformTransportInterfaceClass(name string) (TransportLinkClass, bool) {
	loadAppleNetworkHardwarePorts()
	class, ok := appleNetworkHardwarePorts.classes[name]
	return class, ok
}

func platformUsableTransportInterfaceAddr(name string, addr net.Addr) bool {
	loadAppleNetworkHardwarePorts()
	return !appleNetworkHardwarePorts.skip[name]
}

func loadAppleNetworkHardwarePorts() {
	appleNetworkHardwarePorts.Do(func() {
		out, err := exec.Command("networksetup", "-listallhardwareports").Output()
		if err != nil {
			return
		}
		appleNetworkHardwarePorts.classes, appleNetworkHardwarePorts.skip = parseAppleNetworkHardwarePorts(string(out))
	})
}

func parseAppleNetworkHardwarePortClasses(out string) map[string]TransportLinkClass {
	classes, _ := parseAppleNetworkHardwarePorts(out)
	return classes
}

func parseAppleNetworkHardwarePorts(out string) (map[string]TransportLinkClass, map[string]bool) {
	classes := make(map[string]TransportLinkClass)
	skip := make(map[string]bool)
	var port, device string
	flush := func() {
		if device == "" {
			return
		}
		if appleHardwarePortSkip(port) {
			skip[device] = true
			return
		}
		if class, ok := appleHardwarePortClass(port); ok {
			classes[device] = class
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Hardware Port: "):
			flush()
			port = strings.TrimPrefix(line, "Hardware Port: ")
			device = ""
		case strings.HasPrefix(line, "Device: "):
			device = strings.TrimPrefix(line, "Device: ")
		}
	}
	flush()
	return classes, skip
}

func appleHardwarePortClass(port string) (TransportLinkClass, bool) {
	name := strings.ToLower(port)
	switch {
	case strings.Contains(name, "wi-fi") || strings.Contains(name, "airport"):
		return TransportLinkWiFiLAN, true
	case strings.Contains(name, "thunderbolt bridge"):
		return TransportLinkThunderbolt, true
	case strings.Contains(name, "ethernet"):
		return TransportLinkWiredLAN, true
	default:
		return "", false
	}
}

func appleHardwarePortSkip(port string) bool {
	name := strings.ToLower(port)
	return strings.HasPrefix(name, "thunderbolt ") && !strings.Contains(name, "bridge")
}
