package iroh

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
)

const (
	// maxInterfaceAddrs caps how many local interface addresses are advertised
	// so tickets and discovery records stay small on hosts with many bridges.
	maxInterfaceAddrs = 8
	// interfaceAddrsInterval is how often interfaces are rescanned. There is
	// no route monitor, so address changes are picked up by polling.
	interfaceAddrsInterval = 30 * time.Second
)

// defaultRouteAddrs returns the source addresses the kernel picks for the
// IPv4 and IPv6 default routes. Dialing UDP sends nothing.
func defaultRouteAddrs() []netip.Addr {
	var out []netip.Addr
	for _, dst := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		c, err := net.Dial("udp", dst)
		if err != nil {
			continue
		}
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if a, ok := netip.AddrFromSlice(ua.IP); ok {
				out = append(out, a.Unmap())
			}
		}
		c.Close()
	}
	return out
}

// interfaceAddrs returns global unicast addresses of local interfaces, the
// default-route source addresses first. v4only drops IPv6 addresses for
// sockets bound to 0.0.0.0.
func interfaceAddrs(v4only bool) []netip.Addr {
	out := defaultRouteAddrs()
	ifas, _ := net.InterfaceAddrs()
	for _, ifa := range ifas {
		if ipn, ok := ifa.(*net.IPNet); ok {
			if a, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, a.Unmap())
			}
		}
	}
	uniq := out[:0]
	for _, a := range out {
		if a.IsGlobalUnicast() && (!v4only || a.Is4()) && !slices.Contains(uniq, a) {
			uniq = append(uniq, a)
		}
	}
	return uniq[:min(len(uniq), maxInterfaceAddrs)]
}

// ifState reports which IP families have a usable local address, so
// net-report does not wait for probes that cannot complete.
func ifState() netreport.IfStateDetails {
	var st netreport.IfStateDetails
	for _, a := range interfaceAddrs(false) {
		if a.Is4() {
			st.HaveV4 = true
		} else {
			st.HaveV6 = true
		}
	}
	if !st.HaveV4 && !st.HaveV6 {
		// Loopback-only host (tests): probe both rather than nothing.
		return netreport.IfStateDetails{HaveV4: true, HaveV6: true}
	}
	return st
}

// refreshInterfaceAddrs rescans local interfaces when bound to a wildcard
// address and republishes Addr() if the set changed.
func (e *Endpoint) refreshInterfaceAddrs() {
	bind := e.LocalAddr()
	if e.disableIP || e.noIfaceAddrs || !bind.IsValid() || !bind.Addr().IsUnspecified() {
		return
	}
	var next []netip.AddrPort
	for _, a := range interfaceAddrs(bind.Addr().Is4()) {
		next = append(next, netip.AddrPortFrom(a, bind.Port()))
	}
	e.mu.Lock()
	if slices.Equal(e.externalIface, next) {
		e.mu.Unlock()
		return
	}
	e.externalIface = next
	e.updateAddrWatchLocked()
	e.mu.Unlock()
	e.advertiseNATTraversalCandidates()
}

func (e *Endpoint) runInterfaceAddrs(ctx context.Context) {
	t := time.NewTicker(interfaceAddrsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.refreshInterfaceAddrs()
		}
	}
}
