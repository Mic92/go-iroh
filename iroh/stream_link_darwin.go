//go:build darwin

package iroh

import (
	"os/exec"
	"strings"
	"sync"
)

var appleNetworkHardwarePorts = struct {
	sync.Once
	classes map[string]TransportLinkClass
}{}

func platformTransportInterfaceClass(name string) (TransportLinkClass, bool) {
	appleNetworkHardwarePorts.Do(func() {
		out, err := exec.Command("networksetup", "-listallhardwareports").Output()
		if err != nil {
			return
		}
		appleNetworkHardwarePorts.classes = parseAppleNetworkHardwarePortClasses(string(out))
	})
	class, ok := appleNetworkHardwarePorts.classes[name]
	return class, ok
}

func parseAppleNetworkHardwarePortClasses(out string) map[string]TransportLinkClass {
	classes := make(map[string]TransportLinkClass)
	var port, device string
	flush := func() {
		if device == "" {
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
	return classes
}

func appleHardwarePortClass(port string) (TransportLinkClass, bool) {
	name := strings.ToLower(port)
	switch {
	case strings.Contains(name, "wi-fi") || strings.Contains(name, "airport"):
		return TransportLinkWiFiLAN, true
	case strings.Contains(name, "thunderbolt"):
		return TransportLinkThunderbolt, true
	case strings.Contains(name, "ethernet"):
		return TransportLinkWiredLAN, true
	default:
		return "", false
	}
}
