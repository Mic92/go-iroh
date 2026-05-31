package quic

import (
	"context"
	"errors"
	"net/netip"
	"testing"
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
