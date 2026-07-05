package iroh

import (
	"net"
	"strings"
)

// TransportLinkAddr is a local address with its inferred link class.
type TransportLinkAddr struct {
	Interface string
	Addr      net.Addr
	Class     TransportLinkClass
}

// LocalTransportLinkAddrs returns usable local interface addresses classified by
// link type. IPv6 scoped addresses keep their interface zone.
func LocalTransportLinkAddrs() ([]TransportLinkAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	return classifyTransportLinkAddrs(ifaces, interfaceAddrs)
}

func interfaceAddrs(iface net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}

func classifyTransportLinkAddrs(ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error)) ([]TransportLinkAddr, error) {
	var out []TransportLinkAddr
	for _, iface := range ifaces {
		if !usableInterface(iface) {
			continue
		}
		as, err := addrs(iface)
		if err != nil {
			return nil, err
		}
		for _, a := range as {
			if !usableInterfaceAddr(a) {
				continue
			}
			out = append(out, TransportLinkAddr{
				Interface: iface.Name,
				Addr:      a,
				Class:     classifyTransportInterfaceAddr(iface, a),
			})
		}
	}
	return out, nil
}

func usableInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	return iface.Flags&net.FlagMulticast != 0 || iface.Flags&net.FlagLoopback != 0
}

func usableInterfaceAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	ip, ok := addrIP(addr)
	if !ok || ip.IsUnspecified() {
		return false
	}
	return true
}

func addrIP(addr net.Addr) (net.IP, bool) {
	switch a := addr.(type) {
	case *net.IPNet:
		return a.IP, true
	case *net.IPAddr:
		return a.IP, true
	default:
		return nil, false
	}
}

func classifyTransportInterface(iface net.Interface) TransportLinkClass {
	return classifyTransportInterfaceAddr(iface, nil)
}

func classifyTransportInterfaceAddr(iface net.Interface, addr net.Addr) TransportLinkClass {
	name := strings.ToLower(iface.Name)
	if iface.Flags&net.FlagLoopback != 0 {
		return TransportLinkLoopback
	}
	if strings.HasPrefix(name, "awdl") {
		return TransportLinkAWDL
	}
	if strings.HasPrefix(name, "bridge") || strings.Contains(name, "thunderbolt") {
		return TransportLinkThunderbolt
	}
	if strings.HasPrefix(name, "en") && isLinkLocalIPv6(addr) && iface.Flags&net.FlagBroadcast == 0 {
		return TransportLinkThunderbolt
	}
	if strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") || strings.HasPrefix(name, "wifi") {
		return TransportLinkWiFiLAN
	}
	if strings.HasPrefix(name, "en") || strings.HasPrefix(name, "eth") {
		return TransportLinkWiredLAN
	}
	if iface.Flags&net.FlagBroadcast != 0 || iface.Flags&net.FlagMulticast != 0 {
		return TransportLinkLAN
	}
	return TransportLinkUnknown
}

func isLinkLocalIPv6(addr net.Addr) bool {
	ip, ok := addrIP(addr)
	return ok && ip.To4() == nil && ip.IsLinkLocalUnicast()
}

// PreferredTransportLink chooses the fastest link class both peers advertise.
// The preference order is RDMA, Thunderbolt, wired LAN, Wi-Fi or AWDL, generic
// LAN, loopback, then unknown. Loopback ranks below LAN because it is only useful
// for same-host peers.
func PreferredTransportLink(a, b []TransportLinkClass) TransportLinkClass {
	aset := linkClassSet(a)
	bset := linkClassSet(b)
	for _, class := range transportLinkPreference {
		if aset[class] && bset[class] {
			return class
		}
	}
	return TransportLinkLAN
}

// PreferredTransportLinkAddr chooses from classified local and remote addresses.
func PreferredTransportLinkAddr(a, b []TransportLinkAddr) TransportLinkClass {
	return PreferredTransportLink(linkAddrClasses(a), linkAddrClasses(b))
}

func linkClassSet(classes []TransportLinkClass) map[TransportLinkClass]bool {
	set := make(map[TransportLinkClass]bool, len(classes))
	for _, class := range classes {
		set[class] = true
	}
	return set
}

func linkAddrClasses(addrs []TransportLinkAddr) []TransportLinkClass {
	classes := make([]TransportLinkClass, 0, len(addrs))
	for _, addr := range addrs {
		classes = append(classes, addr.Class)
	}
	return classes
}

var transportLinkPreference = []TransportLinkClass{
	TransportLinkRDMA,
	TransportLinkThunderbolt,
	TransportLinkWiredLAN,
	TransportLinkWiFiLAN,
	TransportLinkAWDL,
	TransportLinkLAN,
	TransportLinkLoopback,
	TransportLinkUnknown,
}
