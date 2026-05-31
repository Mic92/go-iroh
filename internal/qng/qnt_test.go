package quic

import (
	"context"
	"errors"
	"net/netip"
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

func TestQNTLocalAddressStateFailsClosedWhenNotNegotiated(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
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

	if err := c.addRemoteNATTraversalAddress(remote); err != nil {
		t.Fatalf("addRemoteNATTraversalAddress: %v", err)
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

	if err := c.addRemoteNATTraversalAddress(mapped); err != nil {
		t.Fatalf("addRemoteNATTraversalAddress(mapped): %v", err)
	}
	if err := c.addRemoteNATTraversalAddress(canon); err != nil {
		t.Fatalf("addRemoteNATTraversalAddress(duplicate): %v", err)
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

func newNegotiatedQNTConn(local, peer uint8) *Conn {
	return &Conn{
		config: &Config{MaxRemoteNATTraversalAddresses: &local},
		peerParams: &wire.TransportParameters{
			MaxRemoteNATTraversalAddresses: &peer,
		},
	}
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
