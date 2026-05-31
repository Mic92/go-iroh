package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

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

func TestQNTRoundPreconditions(t *testing.T) {
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
	if !errors.Is(err, ErrNATTraversalRoundNotImplemented) {
		t.Fatalf("InitiateNATTraversalRound with candidates err = %v, want ErrNATTraversalRoundNotImplemented", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("InitiateNATTraversalRound with candidates addresses = %v, want [%v]", addrs, remote)
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
