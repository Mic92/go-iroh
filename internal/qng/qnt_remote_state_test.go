package quic

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTRemoteAddressStateAddUpdateRemove(t *testing.T) {
	s := newQNTRemoteAddressState(2)

	addr1, changed, err := s.add(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("192.0.2.1"),
		Port:  1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || addr1 != netip.MustParseAddrPort("192.0.2.1:1000") {
		t.Fatalf("first add = %v, %v, want 192.0.2.1:1000, true", addr1, changed)
	}

	addr, changed, err := s.add(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("192.0.2.1"),
		Port:  1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changed || addr.IsValid() {
		t.Fatalf("duplicate add = %v, %v, want zero, false", addr, changed)
	}

	addr2, changed, err := s.add(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("192.0.2.2"),
		Port:  1001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed || addr2 != netip.MustParseAddrPort("192.0.2.2:1001") {
		t.Fatalf("update = %v, %v, want 192.0.2.2:1001, true", addr2, changed)
	}

	if s.check(&wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 1000}) {
		t.Fatal("check accepted changed address for known seq")
	}
	if !s.check(&wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.2"), Port: 1001}) {
		t.Fatal("check rejected same address for known seq")
	}

	removed, ok := s.remove(&wire.RemoveAddressFrame{SeqNo: 1})
	if !ok || removed != netip.MustParseAddrPort("192.0.2.2:1001") {
		t.Fatalf("remove = %v, %v, want 192.0.2.2:1001, true", removed, ok)
	}
	if removed, ok := s.remove(&wire.RemoveAddressFrame{SeqNo: 1}); ok || removed.IsValid() {
		t.Fatalf("duplicate remove = %v, %v, want zero, false", removed, ok)
	}
}

func TestQNTRemoteAddressStateLimit(t *testing.T) {
	s := newQNTRemoteAddressState(1)
	if _, _, err := s.add(&wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.add(&wire.AddAddressFrame{SeqNo: 2, Addr: netip.MustParseAddr("192.0.2.2"), Port: 2}); !errors.Is(err, errQNTTooManyRemoteAddresses) {
		t.Fatalf("second add err = %v, want errQNTTooManyRemoteAddresses", err)
	}
	if _, _, err := s.add(&wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.3"), Port: 3}); err != nil {
		t.Fatalf("update under full table: %v", err)
	}
	got := s.addresses()
	if len(got) != 1 || got[0] != netip.MustParseAddrPort("192.0.2.3:3") {
		t.Fatalf("addresses = %v, want [192.0.2.3:3]", got)
	}
}

func TestQNTRemoteAddressStateCanonicalizesIPv4Mapped(t *testing.T) {
	s := newQNTRemoteAddressState(1)
	if _, _, err := s.add(&wire.AddAddressFrame{SeqNo: 1, Addr: netip.MustParseAddr("::ffff:192.0.2.1"), Port: 1000}); err != nil {
		t.Fatal(err)
	}
	got := s.addresses()
	if len(got) != 1 || got[0] != netip.MustParseAddrPort("192.0.2.1:1000") {
		t.Fatalf("addresses = %v, want [192.0.2.1:1000]", got)
	}
}

func TestQNTRemoteAddressStateAddressesSnapshot(t *testing.T) {
	s := newQNTRemoteAddressState(3)
	for _, f := range []*wire.AddAddressFrame{
		{SeqNo: 1, Addr: netip.MustParseAddr("192.0.2.1"), Port: 1001},
		{SeqNo: 2, Addr: netip.MustParseAddr("192.0.2.2"), Port: 1002},
	} {
		if _, _, err := s.add(f); err != nil {
			t.Fatal(err)
		}
	}
	got := s.addresses()
	slices.SortFunc(got, func(a, b netip.AddrPort) int { return a.Compare(b) })
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:1001"),
		netip.MustParseAddrPort("192.0.2.2:1002"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
}
