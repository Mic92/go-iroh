package iroh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
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
	out := make([]TransportLinkAddr, 0, len(ifaces))
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
	for _, class := range transportLinkPreference {
		if hasTransportLinkClass(a, class) && hasTransportLinkClass(b, class) {
			return class
		}
	}
	return TransportLinkLAN
}

// PreferredTransportLinkAddr chooses from classified local and remote addresses.
func PreferredTransportLinkAddr(a, b []TransportLinkAddr) TransportLinkClass {
	for _, class := range transportLinkPreference {
		if hasTransportLinkAddrClass(a, class) && hasTransportLinkAddrClass(b, class) {
			return class
		}
	}
	return TransportLinkLAN
}

// SelectStreamLink chooses the fastest mutually advertised link and matching
// local and remote addresses. Ties within a class break by CustomAddr ordering.
func SelectStreamLink(local, remote []netaddr.CustomAddr) (StreamLinkSelection, bool) {
	var localBuf, remoteBuf [8]StreamLinkCandidate
	localCandidates := streamLinkCandidates(local, localBuf[:0])
	remoteCandidates := streamLinkCandidates(remote, remoteBuf[:0])
	for _, preferred := range transportLinkPreference {
		localAddr, localOK := selectStreamLinkCandidate(localCandidates, preferred)
		remoteAddr, remoteOK := selectStreamLinkCandidate(remoteCandidates, preferred)
		if localOK && remoteOK {
			return StreamLinkSelection{
				Local:  localAddr,
				Remote: remoteAddr,
				Class:  preferred,
			}, true
		}
	}
	return StreamLinkSelection{}, false
}

func streamLinkCandidates(addrs []netaddr.CustomAddr, candidates []StreamLinkCandidate) []StreamLinkCandidate {
	if cap(candidates) < len(addrs) {
		candidates = make([]StreamLinkCandidate, 0, len(addrs))
	}
	for _, addr := range addrs {
		class, err := streamLinkAddrClass(addr)
		if err != nil {
			continue
		}
		candidates = append(candidates, StreamLinkCandidate{
			Addr:  addr,
			Class: class,
		})
	}
	return candidates
}

func selectStreamLinkCandidate(candidates []StreamLinkCandidate, class TransportLinkClass) (netaddr.CustomAddr, bool) {
	var best StreamLinkCandidate
	ok := false
	for _, c := range candidates {
		if c.Class != class {
			continue
		}
		if !ok || compareStreamLinkCandidate(c, best) < 0 {
			best = c
			ok = true
		}
	}
	if !ok {
		return netaddr.CustomAddr{}, false
	}
	return best.Addr, true
}

func hasTransportLinkClass(classes []TransportLinkClass, want TransportLinkClass) bool {
	for _, class := range classes {
		if class == want {
			return true
		}
	}
	return false
}

func hasTransportLinkAddrClass(addrs []TransportLinkAddr, want TransportLinkClass) bool {
	for _, addr := range addrs {
		if addr.Class == want {
			return true
		}
	}
	return false
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
	n := streamLinkAddrLen(string(class), iface, dialAddr)
	var buf [128]byte
	b := buf[:0]
	if n > len(buf) {
		b = make([]byte, 0, n)
	}
	b = append(b, streamLinkAddrMagic...)
	b = appendStreamLinkString(b, string(class))
	b = appendStreamLinkString(b, iface)
	b = appendStreamLinkString(b, dialAddr)
	return netaddr.NewCustomAddr(id, b)
}

func streamLinkAddrLen(class, iface, dialAddr string) int {
	return len(streamLinkAddrMagic) + 2 + len(class) + 2 + len(iface) + 2 + len(dialAddr)
}

// ParseStreamLinkAddr parses an encoded stream transport address. Raw address
// payloads from older TCP stream transports are treated as unknown-class addrs.
func ParseStreamLinkAddr(addr netaddr.CustomAddr) (StreamLinkCandidate, error) {
	data := addr.RawData()
	if !bytes.HasPrefix(data, streamLinkAddrMagic) {
		if len(data) == 0 {
			return StreamLinkCandidate{}, errStreamLinkAddrMalformed
		}
		return StreamLinkCandidate{
			Addr:     addr,
			DialAddr: stringFromBytes(data),
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

func streamLinkAddrClass(addr netaddr.CustomAddr) (TransportLinkClass, error) {
	data := addr.RawData()
	if !bytes.HasPrefix(data, streamLinkAddrMagic) {
		if len(data) == 0 {
			return "", errStreamLinkAddrMalformed
		}
		return TransportLinkUnknown, nil
	}
	p := streamLinkAddrParser{b: data[len(streamLinkAddrMagic):]}
	class := p.class()
	if p.err != nil {
		return "", errStreamLinkAddrMalformed
	}
	return class, nil
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
	s := stringFromBytes(p.b[:n])
	p.b = p.b[n:]
	return s
}

func (p *streamLinkAddrParser) class() TransportLinkClass {
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
	class := streamLinkClassBytes(p.b[:n])
	p.b = p.b[n:]
	return class
}

func streamLinkClassBytes(b []byte) TransportLinkClass {
	switch {
	case bytes.Equal(b, []byte(TransportLinkRDMA)):
		return TransportLinkRDMA
	case bytes.Equal(b, []byte(TransportLinkLoopback)):
		return TransportLinkLoopback
	case bytes.Equal(b, []byte(TransportLinkThunderbolt)):
		return TransportLinkThunderbolt
	case bytes.Equal(b, []byte(TransportLinkAWDL)):
		return TransportLinkAWDL
	case bytes.Equal(b, []byte(TransportLinkWiredLAN)):
		return TransportLinkWiredLAN
	case bytes.Equal(b, []byte(TransportLinkWiFiLAN)):
		return TransportLinkWiFiLAN
	case bytes.Equal(b, []byte(TransportLinkLAN)):
		return TransportLinkLAN
	case bytes.Equal(b, []byte(TransportLinkUnknown)):
		return TransportLinkUnknown
	default:
		return TransportLinkClass(string(b))
	}
}

var errStreamLinkAddrMalformed = errors.New("iroh: malformed stream link address")

var streamLinkAddrMagic = []byte{'i', 's', 't', '1'}

func tcpDialAddrFromLinkAddr(link TransportLinkAddr, port int) (string, bool) {
	return tcpDialAddrFromNetAddr(link.Interface, link.Addr, port)
}

func tcpDialAddrFromNetAddr(iface string, addr net.Addr, port int) (string, bool) {
	ip, ok := addrIP(addr)
	if !ok {
		return "", false
	}
	host := ip.String()
	zone := addrZone(addr)
	if zone == "" && ip.To4() == nil && ip.IsLinkLocalUnicast() {
		zone = iface
	}
	var b [128]byte
	out := b[:0]
	if ip.To4() == nil {
		out = append(out, '[')
		out = append(out, host...)
		if zone != "" {
			out = append(out, '%')
			out = append(out, zone...)
		}
		out = append(out, ']')
	} else {
		out = append(out, host...)
	}
	out = append(out, ':')
	out = strconv.AppendInt(out, int64(port), 10)
	return string(out), true
}

func addrZone(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.Zone
	default:
		return ""
	}
}
