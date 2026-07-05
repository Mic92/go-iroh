package iroh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/tmc/go-iroh/netaddr"
)

// TransportLinkAddr is a local address with its inferred link class.
type TransportLinkAddr struct {
	Interface string
	Addr      net.Addr
	Class     TransportLinkClass
}

// StreamLinkCandidate is an advertised stream address with link metadata.
type StreamLinkCandidate struct {
	Addr      netaddr.CustomAddr
	Interface string
	DialAddr  string
	Class     TransportLinkClass
}

// StreamLinkSelection is a deterministic negotiated stream address choice.
type StreamLinkSelection struct {
	Local  netaddr.CustomAddr
	Remote netaddr.CustomAddr
	Class  TransportLinkClass
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

// SelectStreamLink chooses the fastest mutually advertised link and matching
// local and remote addresses. Ties within a class break by CustomAddr ordering.
func SelectStreamLink(local, remote []netaddr.CustomAddr) (StreamLinkSelection, bool) {
	localCandidates := streamLinkCandidates(local)
	remoteCandidates := streamLinkCandidates(remote)
	class := preferredCandidateClass(localCandidates, remoteCandidates)
	for _, preferred := range append([]TransportLinkClass{class}, transportLinkPreference...) {
		locals := candidatesByClass(localCandidates, preferred)
		remotes := candidatesByClass(remoteCandidates, preferred)
		if len(locals) == 0 || len(remotes) == 0 {
			continue
		}
		slices.SortFunc(locals, compareStreamLinkCandidate)
		slices.SortFunc(remotes, compareStreamLinkCandidate)
		return StreamLinkSelection{
			Local:  locals[0].Addr,
			Remote: remotes[0].Addr,
			Class:  preferred,
		}, true
	}
	return StreamLinkSelection{}, false
}

func preferredCandidateClass(local, remote []StreamLinkCandidate) TransportLinkClass {
	return PreferredTransportLink(candidateClasses(local), candidateClasses(remote))
}

func streamLinkCandidates(addrs []netaddr.CustomAddr) []StreamLinkCandidate {
	candidates := make([]StreamLinkCandidate, 0, len(addrs))
	for _, addr := range addrs {
		c, err := ParseStreamLinkAddr(addr)
		if err != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	return candidates
}

func candidatesByClass(candidates []StreamLinkCandidate, class TransportLinkClass) []StreamLinkCandidate {
	var out []StreamLinkCandidate
	for _, c := range candidates {
		if c.Class == class {
			out = append(out, c)
		}
	}
	return out
}

func candidateClasses(candidates []StreamLinkCandidate) []TransportLinkClass {
	classes := make([]TransportLinkClass, 0, len(candidates))
	for _, c := range candidates {
		classes = append(classes, c.Class)
	}
	return classes
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

// NewStreamLinkAddr returns an encoded stream transport address.
func NewStreamLinkAddr(id uint64, class TransportLinkClass, iface, dialAddr string) netaddr.CustomAddr {
	var b []byte
	b = append(b, streamLinkAddrMagic...)
	b = appendStreamLinkString(b, string(class))
	b = appendStreamLinkString(b, iface)
	b = appendStreamLinkString(b, dialAddr)
	return netaddr.NewCustomAddr(id, b)
}

// ParseStreamLinkAddr parses an encoded stream transport address. Raw address
// payloads from older TCP stream transports are treated as unknown-class addrs.
func ParseStreamLinkAddr(addr netaddr.CustomAddr) (StreamLinkCandidate, error) {
	data := addr.Data()
	if !bytes.HasPrefix(data, streamLinkAddrMagic) {
		if len(data) == 0 {
			return StreamLinkCandidate{}, errStreamLinkAddrMalformed
		}
		return StreamLinkCandidate{
			Addr:     addr,
			DialAddr: string(data),
			Class:    TransportLinkUnknown,
		}, nil
	}
	p := streamLinkAddrParser{b: data[len(streamLinkAddrMagic):]}
	class := TransportLinkClass(p.string())
	iface := p.string()
	dialAddr := p.string()
	if p.err != nil || dialAddr == "" {
		return StreamLinkCandidate{}, errStreamLinkAddrMalformed
	}
	return StreamLinkCandidate{
		Addr:      addr,
		Interface: iface,
		DialAddr:  dialAddr,
		Class:     class,
	}, nil
}

func compareStreamLinkCandidate(a, b StreamLinkCandidate) int {
	if c := a.Addr.Compare(b.Addr); c != 0 {
		return c
	}
	return strings.Compare(a.DialAddr, b.DialAddr)
}

func appendStreamLinkString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

type streamLinkAddrParser struct {
	b   []byte
	err error
}

func (p *streamLinkAddrParser) string() string {
	if p.err != nil {
		return ""
	}
	if len(p.b) < 2 {
		p.err = errStreamLinkAddrMalformed
		return ""
	}
	n := int(binary.BigEndian.Uint16(p.b[:2]))
	p.b = p.b[2:]
	if len(p.b) < n {
		p.err = errStreamLinkAddrMalformed
		return ""
	}
	s := string(p.b[:n])
	p.b = p.b[n:]
	return s
}

var errStreamLinkAddrMalformed = errors.New("iroh: malformed stream link address")

var streamLinkAddrMagic = []byte{'i', 's', 't', '1'}

func tcpDialAddrFromNetAddr(addr net.Addr, port int) (string, bool) {
	ip, ok := addrIP(addr)
	if !ok {
		return "", false
	}
	host := ip.String()
	if z := addrZone(addr); z != "" {
		host += "%" + z
	}
	return net.JoinHostPort(host, fmt.Sprint(port)), true
}

func addrZone(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.Zone
	default:
		return ""
	}
}
