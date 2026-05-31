package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTAPIFailsClosed(t *testing.T) {
	c := &Conn{}
	addr := netip.MustParseAddrPort("192.0.2.1:1234")

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "add local address",
			run:  func() error { return c.AddNATTraversalAddress(addr) },
		},
		{
			name: "remove local address",
			run:  func() error { return c.RemoveNATTraversalAddress(addr) },
		},
		{
			name: "initiate round",
			run: func() error {
				addrs, err := c.InitiateNATTraversalRound(context.Background())
				if len(addrs) != 0 {
					t.Fatalf("InitiateNATTraversalRound addresses = %v, want none", addrs)
				}
				return err
			},
		},
		{
			name: "remote addresses",
			run: func() error {
				addrs, err := c.NATTraversalAddresses()
				if len(addrs) != 0 {
					t.Fatalf("NATTraversalAddresses = %v, want none", addrs)
				}
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("err = %v, want ErrNATTraversalNotNegotiated", err)
			}
		})
	}
}

func TestQNTLocalAddressState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)

	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	canon := netip.MustParseAddrPort("192.0.2.1:1234")
	if err := c.AddNATTraversalAddress(mapped); err != nil {
		t.Fatalf("AddNATTraversalAddress(mapped): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != canon {
		t.Fatalf("local addresses = %v, want [%v]", got, canon)
	}

	if err := c.AddNATTraversalAddress(canon); err != nil {
		t.Fatalf("AddNATTraversalAddress(duplicate): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != canon {
		t.Fatalf("after duplicate add = %v, want [%v]", got, canon)
	}

	v6 := netip.MustParseAddrPort("[2001:db8::1]:4433")
	if err := c.AddNATTraversalAddress(v6); err != nil {
		t.Fatalf("AddNATTraversalAddress(v6): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 2 || got[0] != canon || got[1] != v6 {
		t.Fatalf("after v6 add = %v, want [%v %v]", got, canon, v6)
	}

	if err := c.RemoveNATTraversalAddress(mapped); err != nil {
		t.Fatalf("RemoveNATTraversalAddress(mapped): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != v6 {
		t.Fatalf("after remove mapped = %v, want [%v]", got, v6)
	}

	if err := c.RemoveNATTraversalAddress(canon); err != nil {
		t.Fatalf("RemoveNATTraversalAddress(absent): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != v6 {
		t.Fatalf("after absent remove = %v, want [%v]", got, v6)
	}
}

func TestQNTLocalAddressStatePerConnection(t *testing.T) {
	c1 := newNegotiatedQNTConn(8, 16)
	c2 := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	if err := c1.AddNATTraversalAddress(addr); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if got := c2.qntLocalNATTraversalAddresses(); len(got) != 0 {
		t.Fatalf("second connection local addresses = %v, want none", got)
	}
}

func TestQNTLocalAddressStateLimit(t *testing.T) {
	c := newNegotiatedQNTConn(8, 1)
	if err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.1:1234")); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.1:1234")); err != nil {
		t.Fatalf("duplicate AddNATTraversalAddress: %v", err)
	}
	err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.2:1234"))
	if !errors.Is(err, ErrNATTraversalTooManyAddresses) {
		t.Fatalf("second distinct AddNATTraversalAddress err = %v, want ErrNATTraversalTooManyAddresses", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != netip.MustParseAddrPort("192.0.2.1:1234") {
		t.Fatalf("local addresses after limit = %v, want [192.0.2.1:1234]", got)
	}
}

func TestQNTLocalAddressQueuesAddAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr1 := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	addr2 := netip.MustParseAddrPort("[2001:db8::1]:4433")

	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("duplicate AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr2); err != nil {
		t.Fatalf("second AddNATTraversalAddress: %v", err)
	}

	frames := queuedAddAddressFrames(c)
	if len(frames) != 2 {
		t.Fatalf("queued %d ADD_ADDRESS frames, want 2", len(frames))
	}
	if frames[0].SeqNo != 0 || netip.AddrPortFrom(frames[0].Addr, frames[0].Port) != netip.MustParseAddrPort("192.0.2.1:1234") {
		t.Fatalf("first ADD_ADDRESS = seq %d %s:%d, want seq 0 192.0.2.1:1234", frames[0].SeqNo, frames[0].Addr, frames[0].Port)
	}
	if frames[1].SeqNo != 1 || netip.AddrPortFrom(frames[1].Addr, frames[1].Port) != addr2 {
		t.Fatalf("second ADD_ADDRESS = seq %d %s:%d, want seq 1 %v", frames[1].SeqNo, frames[1].Addr, frames[1].Port, addr2)
	}
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("AddNATTraversalAddress did not schedule sending")
	}
}

func TestQNTLocalAddressQueuesRemoveAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr1 := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	addr2 := netip.MustParseAddrPort("192.0.2.2:4321")
	absent := netip.MustParseAddrPort("192.0.2.3:4321")

	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr2); err != nil {
		t.Fatalf("second AddNATTraversalAddress: %v", err)
	}
	select {
	case <-c.sendingScheduled:
	default:
	}
	if err := c.RemoveNATTraversalAddress(addr1); err != nil {
		t.Fatalf("RemoveNATTraversalAddress: %v", err)
	}
	if err := c.RemoveNATTraversalAddress(addr1); err != nil {
		t.Fatalf("duplicate RemoveNATTraversalAddress: %v", err)
	}
	if err := c.RemoveNATTraversalAddress(absent); err != nil {
		t.Fatalf("absent RemoveNATTraversalAddress: %v", err)
	}

	frames := queuedRemoveAddressFrames(c)
	if len(frames) != 1 {
		t.Fatalf("queued %d REMOVE_ADDRESS frames, want 1", len(frames))
	}
	if frames[0].SeqNo != 0 {
		t.Fatalf("REMOVE_ADDRESS seq = %d, want 0", frames[0].SeqNo)
	}
	if got := c.qntLocalNATTraversalAddresses(); !slices.Equal(got, []netip.AddrPort{addr2}) {
		t.Fatalf("local addresses after remove = %v, want [%v]", got, addr2)
	}
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("RemoveNATTraversalAddress did not schedule sending")
	}
}

func TestQNTLocalAddressStateFailsClosedWhenNotNegotiated(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	add := &wire.AddAddressFrame{SeqNo: 1, Addr: addr.Addr(), Port: addr.Port()}
	remove := &wire.RemoveAddressFrame{SeqNo: 1}
	cases := []struct {
		name string
		c    *Conn
	}{
		{name: "empty", c: &Conn{}},
		{name: "local only", c: newLocalOnlyQNTConn(8)},
		{name: "peer only", c: newPeerOnlyQNTConn(8)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.AddNATTraversalAddress(addr); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("AddNATTraversalAddress err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.RemoveNATTraversalAddress(addr); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("RemoveNATTraversalAddress err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.addRemoteNATTraversalAddressFrame(add); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("addRemoteNATTraversalAddressFrame err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.removeRemoteNATTraversalAddressFrame(remove); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("removeRemoteNATTraversalAddressFrame err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if got := tc.c.qntLocalNATTraversalAddresses(); len(got) != 0 {
				t.Fatalf("local addresses after failed operations = %v, want none", got)
			}
		})
	}
}

func TestQNTRoundQueuesState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local := netip.MustParseAddrPort("192.0.2.1:1234")
	remote := netip.MustParseAddrPort("198.51.100.2:5678")

	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if !errors.Is(err, ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("InitiateNATTraversalRound without candidates err = %v, want ErrNATTraversalNotEnoughAddresses", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("InitiateNATTraversalRound without candidates addresses = %v, want none", addrs)
	}

	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if !errors.Is(err, ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("InitiateNATTraversalRound without remote candidates err = %v, want ErrNATTraversalNotEnoughAddresses", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("InitiateNATTraversalRound without remote candidates addresses = %v, want none", addrs)
	}

	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  remote.Addr(),
		Port:  remote.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame: %v", err)
	}
	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("InitiateNATTraversalRound with candidates: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("InitiateNATTraversalRound with candidates addresses = %v, want [%v]", addrs, remote)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 1 {
		t.Fatalf("pending REACH_OUT frames = %d, want 1", len(reachOut))
	}
	if reachOut[0].Round != 1 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local {
		t.Fatalf("pending REACH_OUT = round %d %s:%d, want round 1 %v", reachOut[0].Round, reachOut[0].Addr, reachOut[0].Port, local)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 1 || probes[0] != remote {
		t.Fatalf("pending probe addresses = %v, want [%v]", probes, remote)
	}

	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("second InitiateNATTraversalRound with candidates: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("second InitiateNATTraversalRound addresses = %v, want [%v]", addrs, remote)
	}
	reachOut = c.qntPendingReachOutFrames()
	if len(reachOut) != 1 {
		t.Fatalf("second pending REACH_OUT frames = %d, want 1", len(reachOut))
	}
	if reachOut[0].Round != 2 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local {
		t.Fatalf("second pending REACH_OUT = round %d %s:%d, want round 2 %v", reachOut[0].Round, reachOut[0].Addr, reachOut[0].Port, local)
	}
}

func TestQNTRoundQueuesOneReachOutPerLocalAndProbePerRemote(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local1 := netip.MustParseAddrPort("192.0.2.1:1234")
	local2 := netip.MustParseAddrPort("[2001:db8::1]:4433")
	remote1 := netip.MustParseAddrPort("198.51.100.1:1001")
	remote2 := netip.MustParseAddrPort("198.51.100.2:1002")

	for _, addr := range []netip.AddrPort{local1, local2} {
		if err := c.AddNATTraversalAddress(addr); err != nil {
			t.Fatalf("AddNATTraversalAddress(%v): %v", addr, err)
		}
	}
	for seq, addr := range map[uint64]netip.AddrPort{1: remote1, 2: remote2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{SeqNo: seq, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
			t.Fatalf("add remote seq %d: %v", seq, err)
		}
	}

	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("InitiateNATTraversalRound: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, remote1) || !slices.Contains(addrs, remote2) {
		t.Fatalf("round addresses = %v, want %v and %v", addrs, remote1, remote2)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 2 {
		t.Fatalf("pending REACH_OUT frames = %d, want 2", len(reachOut))
	}
	for _, f := range reachOut {
		if f.Round != 1 {
			t.Fatalf("REACH_OUT round = %d, want 1", f.Round)
		}
	}
	if !hasReachOut(reachOut, local1) || !hasReachOut(reachOut, local2) {
		t.Fatalf("pending REACH_OUT frames = %+v, want local candidates %v and %v", reachOut, local1, local2)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 2 || !slices.Contains(probes, remote1) || !slices.Contains(probes, remote2) {
		t.Fatalf("pending probes = %v, want %v and %v", probes, remote1, remote2)
	}
}

func TestQNTRoundClearsPreviousPendingState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local1 := netip.MustParseAddrPort("192.0.2.1:1234")
	local2 := netip.MustParseAddrPort("192.0.2.2:1234")
	remote1 := netip.MustParseAddrPort("198.51.100.1:1001")
	remote2 := netip.MustParseAddrPort("198.51.100.2:1002")

	for _, addr := range []netip.AddrPort{local1, local2} {
		if err := c.AddNATTraversalAddress(addr); err != nil {
			t.Fatalf("AddNATTraversalAddress(%v): %v", addr, err)
		}
	}
	for seq, addr := range map[uint64]netip.AddrPort{1: remote1, 2: remote2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{SeqNo: seq, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
			t.Fatalf("add remote seq %d: %v", seq, err)
		}
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); err != nil {
		t.Fatalf("first InitiateNATTraversalRound: %v", err)
	}
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{{1, 2, 3, 4, 5, 6, 7, 8}: remote1}
	st.mu.Unlock()

	if err := c.RemoveNATTraversalAddress(local1); err != nil {
		t.Fatalf("RemoveNATTraversalAddress: %v", err)
	}
	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1}); err != nil {
		t.Fatalf("remove remote seq 1: %v", err)
	}
	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("second InitiateNATTraversalRound: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote2 {
		t.Fatalf("second round addresses = %v, want [%v]", addrs, remote2)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 1 || reachOut[0].Round != 2 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local2 {
		t.Fatalf("second round REACH_OUT = %+v, want round 2 for %v", reachOut, local2)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 1 || probes[0] != remote2 {
		t.Fatalf("second round probes = %v, want [%v]", probes, remote2)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.sentProbes) != 0 {
		t.Fatalf("sent probes after second round = %v, want none", st.sentProbes)
	}
}

func TestQNTProbeUDPAddr(t *testing.T) {
	tests := []struct {
		name string
		addr netip.AddrPort
		want netip.AddrPort
	}{
		{
			name: "ipv4",
			addr: netip.MustParseAddrPort("192.0.2.1:1234"),
			want: netip.MustParseAddrPort("192.0.2.1:1234"),
		},
		{
			name: "mapped ipv4",
			addr: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234"),
			want: netip.MustParseAddrPort("192.0.2.1:1234"),
		},
		{
			name: "ipv6",
			addr: netip.MustParseAddrPort("[2001:db8::1]:4433"),
			want: netip.MustParseAddrPort("[2001:db8::1]:4433"),
		},
		{
			name: "invalid",
		},
		{
			name: "zero port",
			addr: netip.MustParseAddrPort("192.0.2.1:0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := qntProbeUDPAddr(tt.addr)
			if !tt.want.IsValid() {
				if got != nil {
					t.Fatalf("qntProbeUDPAddr(%v) = %v, want nil", tt.addr, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("qntProbeUDPAddr(%v) = nil, want %v", tt.addr, tt.want)
			}
			if got.AddrPort() != tt.want {
				t.Fatalf("qntProbeUDPAddr(%v) = %v, want %v", tt.addr, got.AddrPort(), tt.want)
			}
		})
	}
}

func TestQNTSentProbeConsumesMatchingPathResponse(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")
	mapped := netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234")

	c.qntRecordSentProbe(challenge, remote)
	got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, mapped)
	if !ok || got != remote {
		t.Fatalf("qntConsumePathResponse = %v, %v, want %v, true", got, ok, remote)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote); ok || got.IsValid() {
		t.Fatalf("duplicate qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
}

func TestQNTNextProbeFramePopsPendingProbeAndRecordsChallenge(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local := netip.MustParseAddrPort("192.0.2.1:1234")
	remote := netip.MustParseAddrPort("198.51.100.1:5678")

	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  remote.Addr(),
		Port:  remote.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame: %v", err)
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); err != nil {
		t.Fatalf("InitiateNATTraversalRound: %v", err)
	}

	got, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if !ok {
		t.Fatal("qntNextProbeFrame ok = false, want true")
	}
	if got != remote {
		t.Fatalf("qntNextProbeFrame remote = %v, want %v", got, remote)
	}
	pathChallenge, ok := frame.Frame.(*wire.PathChallengeFrame)
	if !ok {
		t.Fatalf("qntNextProbeFrame frame = %T, want *wire.PathChallengeFrame", frame.Frame)
	}
	if probes := c.qntPendingProbeAddresses(); len(probes) != 0 {
		t.Fatalf("pending probes after qntNextProbeFrame = %v, want none", probes)
	}
	if matched, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: pathChallenge.Data}, remote); !ok || matched != remote {
		t.Fatalf("qntConsumePathResponse after qntNextProbeFrame = %v, %v, want %v, true", matched, ok, remote)
	}
}

func TestQNTNextProbeFrameReturnsFalseWhenEmpty(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)

	remote, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if ok || remote.IsValid() || frame.Frame != nil {
		t.Fatalf("qntNextProbeFrame = %v, %#v, %v, want zero frame false", remote, frame, ok)
	}
}

func TestQNTNextProbeFrameInvalidState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.qntLocalState().pendingProbes = []netip.AddrPort{netip.AddrPort{}}

	got, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if ok || got.IsValid() || frame.Frame != nil {
		t.Fatalf("qntNextProbeFrame invalid = %v, %#v, %v, want zero frame false", got, frame, ok)
	}
}

func TestQNTValidatedProbeQueue(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234")
	want := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if c.qntQueueValidatedProbe(want) {
		t.Fatal("duplicate qntQueueValidatedProbe = true, want false")
	}
	if c.qntQueueValidatedProbe(netip.AddrPort{}) {
		t.Fatal("invalid qntQueueValidatedProbe = true, want false")
	}
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != want {
		t.Fatalf("qntPopValidatedProbe = %v, %v, want %v, true", got, ok, want)
	}
	if got, ok := c.qntPopValidatedProbe(); ok || got.IsValid() {
		t.Fatalf("empty qntPopValidatedProbe = %v, %v, want zero false", got, ok)
	}
}

func TestQNTSentProbeRequiresChallengeAndSource(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherChallenge := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")
	otherRemote := netip.MustParseAddrPort("198.51.100.2:1234")

	c.qntRecordSentProbe(challenge, remote)
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, otherRemote); ok || got.IsValid() {
		t.Fatalf("wrong source qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: otherChallenge}, remote); ok || got.IsValid() {
		t.Fatalf("wrong challenge qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(nil, remote); ok || got.IsValid() {
		t.Fatalf("nil frame qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, netip.AddrPort{}); ok || got.IsValid() {
		t.Fatalf("invalid source qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote)
	if !ok || got != remote {
		t.Fatalf("matching response after misses = %v, %v, want %v, true", got, ok, remote)
	}
}

func TestQNTSentProbeIgnoresInvalidRemote(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")

	c.qntRecordSentProbe(challenge, netip.AddrPort{})
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote); ok || got.IsValid() {
		t.Fatalf("invalid remote qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
}

func TestQNTPathResponseHandlerReceivesSourceAddress(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveClient
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	frame := &wire.PathResponseFrame{Data: challenge}
	source := netip.MustParseAddrPort("198.51.100.1:1234")
	otherSource := netip.MustParseAddrPort("198.51.100.2:1234")

	c.qntRecordSentProbe(challenge, source)
	_ = c.handlePathResponseFrame(frame, otherSource)
	if _, ok := c.qntConsumePathResponse(frame, source); !ok {
		t.Fatal("PATH_RESPONSE from wrong source consumed QNT probe")
	}

	c.qntRecordSentProbe(challenge, source)
	_ = c.handlePathResponseFrame(frame, source)
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != source {
		t.Fatalf("validated QNT probe = %v, %v, want %v, true", got, ok, source)
	}
	if _, ok := c.qntConsumePathResponse(frame, source); ok {
		t.Fatal("PATH_RESPONSE from matching source was not consumed by QNT hook")
	}
}

func TestQNTRemoteAddressState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	mapped := netip.MustParseAddrPort("[::ffff:198.51.100.2]:5678")
	canon := netip.MustParseAddrPort("198.51.100.2:5678")

	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  mapped.Addr(),
		Port:  mapped.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame(mapped): %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  canon.Addr(),
		Port:  canon.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame(duplicate): %v", err)
	}

	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != canon {
		t.Fatalf("remote addresses = %v, want [%v]", addrs, canon)
	}

	addrs[0] = netip.MustParseAddrPort("203.0.113.3:9999")
	addrs, err = c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses after caller mutation: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != canon {
		t.Fatalf("remote addresses after caller mutation = %v, want [%v]", addrs, canon)
	}
}

func TestQNTRemoteAddressStateUsesSeqNumbers(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr1 := netip.MustParseAddrPort("198.51.100.1:1001")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1002")
	addr3 := netip.MustParseAddrPort("198.51.100.3:1003")

	for seq, addr := range map[uint64]netip.AddrPort{1: addr1, 2: addr2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
			SeqNo: seq,
			Addr:  addr.Addr(),
			Port:  addr.Port(),
		}); err != nil {
			t.Fatalf("add seq %d: %v", seq, err)
		}
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 3,
		Addr:  addr3.Addr(),
		Port:  addr3.Port(),
	}); !errors.Is(err, errQNTTooManyRemoteAddresses) {
		t.Fatalf("add over limit err = %v, want errQNTTooManyRemoteAddresses", err)
	}

	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 99}); err != nil {
		t.Fatalf("remove absent seq: %v", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses after absent remove: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, addr1) || !slices.Contains(addrs, addr2) {
		t.Fatalf("remote addresses after absent remove = %v, want %v and %v", addrs, addr1, addr2)
	}

	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1}); err != nil {
		t.Fatalf("remove seq 1: %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 3,
		Addr:  addr3.Addr(),
		Port:  addr3.Port(),
	}); err != nil {
		t.Fatalf("add seq 3 after remove: %v", err)
	}

	addrs, err = c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, addr2) || !slices.Contains(addrs, addr3) {
		t.Fatalf("remote addresses = %v, want %v and %v", addrs, addr2, addr3)
	}
}

func TestQNTRemoteAddressStateLimitOnConn(t *testing.T) {
	c := newNegotiatedQNTConn(1, 16)
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("198.51.100.1"),
		Port:  1234,
	}); err != nil {
		t.Fatalf("first addRemoteNATTraversalAddress: %v", err)
	}
	err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 2,
		Addr:  netip.MustParseAddr("198.51.100.2"),
		Port:  1234,
	})
	if !errors.Is(err, ErrNATTraversalTooManyAddresses) {
		t.Fatalf("second addRemoteNATTraversalAddress err = %v, want ErrNATTraversalTooManyAddresses", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddrPort("198.51.100.1:1234") {
		t.Fatalf("remote addresses after limit = %v, want [198.51.100.1:1234]", addrs)
	}
}

func TestQNTConnectionHandlesAddRemoveAddressFrames(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr1 := netip.MustParseAddrPort("198.51.100.1:1001")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1002")

	err := c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  addr1.Addr(),
		Port:  addr1.Port(),
	})
	if err != nil {
		t.Fatalf("handle ADD_ADDRESS seq 1: %v", err)
	}
	err = c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 2,
		Addr:  addr2.Addr(),
		Port:  addr2.Port(),
	})
	if err != nil {
		t.Fatalf("handle ADD_ADDRESS seq 2: %v", err)
	}
	err = c.handleRemoveAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1})
	if err != nil {
		t.Fatalf("handle REMOVE_ADDRESS seq 1: %v", err)
	}

	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != addr2 {
		t.Fatalf("remote addresses = %v, want [%v]", addrs, addr2)
	}
}

func TestQNTConnectionHandlesReachOutFrameInert(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")

	err := c.handleReachOutFrame(&wire.ReachOutFrame{
		Round: 1,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
	if !errors.Is(err, ErrNATTraversalRoundNotImplemented) {
		t.Fatalf("handle REACH_OUT err = %v, want ErrNATTraversalRoundNotImplemented", err)
	}
	if addrs, err := c.NATTraversalAddresses(); err != nil || len(addrs) != 0 {
		t.Fatalf("NATTraversalAddresses after REACH_OUT = %v, %v, want none, nil", addrs, err)
	}
}

func TestQNTConnectionHandlersFailClosedWhenNotNegotiated(t *testing.T) {
	c := newLocalOnlyQNTConn(2)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")

	err := c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle ADD_ADDRESS err = %v, want ErrNATTraversalNotNegotiated", err)
	}
	err = c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr.Addr(), Port: addr.Port()})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle REACH_OUT err = %v, want ErrNATTraversalNotNegotiated", err)
	}
	err = c.handleRemoveAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle REMOVE_ADDRESS err = %v, want ErrNATTraversalNotNegotiated", err)
	}
}

func TestQNTConnectionHandlersIgnoreNilFrames(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	if err := c.handleAddAddressFrame(nil); err != nil {
		t.Fatalf("handle nil ADD_ADDRESS: %v", err)
	}
	if err := c.handleRemoveAddressFrame(nil); err != nil {
		t.Fatalf("handle nil REMOVE_ADDRESS: %v", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("remote addresses after nil frames = %v, want none", addrs)
	}
}

func newNegotiatedQNTConn(local, peer uint8) *Conn {
	return &Conn{
		config: &Config{MaxRemoteNATTraversalAddresses: &local},
		peerParams: &wire.TransportParameters{
			MaxRemoteNATTraversalAddresses: &peer,
		},
	}
}

func queuedAddAddressFrames(c *Conn) []*wire.AddAddressFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.AddAddressFrame
	for _, f := range c.framer.controlFrames {
		if af, ok := f.(*wire.AddAddressFrame); ok {
			frames = append(frames, af)
		}
	}
	return frames
}

func queuedRemoveAddressFrames(c *Conn) []*wire.RemoveAddressFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.RemoveAddressFrame
	for _, f := range c.framer.controlFrames {
		if rf, ok := f.(*wire.RemoveAddressFrame); ok {
			frames = append(frames, rf)
		}
	}
	return frames
}

func hasReachOut(frames []*wire.ReachOutFrame, addr netip.AddrPort) bool {
	return slices.ContainsFunc(frames, func(f *wire.ReachOutFrame) bool {
		return netip.AddrPortFrom(f.Addr, f.Port) == addr
	})
}

func newLocalOnlyQNTConn(local uint8) *Conn {
	return &Conn{config: &Config{MaxRemoteNATTraversalAddresses: &local}}
}

func newPeerOnlyQNTConn(peer uint8) *Conn {
	return &Conn{
		config: &Config{},
		peerParams: &wire.TransportParameters{
			MaxRemoteNATTraversalAddresses: &peer,
		},
	}
}
