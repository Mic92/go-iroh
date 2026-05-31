package wire

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests pin iroh n0 NAT traversal frame layouts against the authoritative
// noq-proto reference in internal/qng/n0ext/reference/frame.rs. Parser admission
// is intentionally not enabled in this slice.

type qntFrame interface {
	Append([]byte, protocol.Version) ([]byte, error)
	Length(protocol.Version) protocol.ByteCount
}

func mustAppendQNT(t *testing.T, f qntFrame) []byte {
	t.Helper()
	b, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got, want := protocol.ByteCount(len(b)), f.Length(protocol.Version1); got != want {
		t.Fatalf("Length() = %d, encoded %d bytes", want, got)
	}
	return b
}

func TestQNTFrameTypeVarints(t *testing.T) {
	cases := []struct {
		typ  FrameType
		want []byte
	}{
		{FrameTypeAddIPv4Address, []byte{0x80, 0x3d, 0x7f, 0x90}},
		{FrameTypeAddIPv6Address, []byte{0x80, 0x3d, 0x7f, 0x91}},
		{FrameTypeReachOutAtIPv4, []byte{0x80, 0x3d, 0x7f, 0x92}},
		{FrameTypeReachOutAtIPv6, []byte{0x80, 0x3d, 0x7f, 0x93}},
		{FrameTypeRemoveAddress, []byte{0x80, 0x3d, 0x7f, 0x94}},
	}
	for _, tc := range cases {
		if got := quicvarint.Append(nil, uint64(tc.typ)); !bytes.Equal(got, tc.want) {
			t.Errorf("frame type %#x: varint = % x, want % x", uint64(tc.typ), got, tc.want)
		}
	}
}

func TestAddAddressFrameGoldenIPv4(t *testing.T) {
	// frame.rs:2355-2367: type, seq_no, IP bytes, big-endian port.
	f := &AddAddressFrame{
		SeqNo: 7,
		Addr:  netip.MustParseAddr("192.0.2.9"),
		Port:  7842,
	}
	want := []byte{0x80, 0x3d, 0x7f, 0x90, 0x07, 0xc0, 0x00, 0x02, 0x09, 0x1e, 0xa2}
	got := mustAppendQNT(t, f)
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parseAddAddressFrame(want[4:], false, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 || parsed.SeqNo != f.SeqNo || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", parsed, n, f, len(want)-4)
	}
}

func TestAddAddressFrameGoldenIPv6(t *testing.T) {
	f := &AddAddressFrame{
		SeqNo: 7,
		Addr:  netip.MustParseAddr("2001:db8::1"),
		Port:  7842,
	}
	want := []byte{
		0x80, 0x3d, 0x7f, 0x91, 0x07,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x1e, 0xa2,
	}
	got := mustAppendQNT(t, f)
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parseAddAddressFrame(want[4:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 || parsed.SeqNo != f.SeqNo || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", parsed, n, f, len(want)-4)
	}
}

func TestReachOutFrameGoldenIPv4(t *testing.T) {
	// frame.rs:2428-2440: type, round, IP bytes, big-endian port.
	f := &ReachOutFrame{
		Round: 10,
		Addr:  netip.MustParseAddr("198.51.100.7"),
		Port:  4433,
	}
	want := []byte{0x80, 0x3d, 0x7f, 0x92, 0x0a, 0xc6, 0x33, 0x64, 0x07, 0x11, 0x51}
	got := mustAppendQNT(t, f)
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parseReachOutFrame(want[4:], false, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 || parsed.Round != f.Round || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", parsed, n, f, len(want)-4)
	}
}

func TestReachOutFrameGoldenIPv6(t *testing.T) {
	f := &ReachOutFrame{
		Round: 10,
		Addr:  netip.MustParseAddr("2001:db8::2"),
		Port:  4433,
	}
	want := []byte{
		0x80, 0x3d, 0x7f, 0x93, 0x0a,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x11, 0x51,
	}
	got := mustAppendQNT(t, f)
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parseReachOutFrame(want[4:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 || parsed.Round != f.Round || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", parsed, n, f, len(want)-4)
	}
}

func TestRemoveAddressFrameGolden(t *testing.T) {
	// frame.rs:2483-2490: type, seq_no.
	f := &RemoveAddressFrame{SeqNo: 7}
	want := []byte{0x80, 0x3d, 0x7f, 0x94, 0x07}
	got := mustAppendQNT(t, f)
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	parsed, n, err := parseRemoveAddressFrame(want[4:], protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 || parsed.SeqNo != f.SeqNo {
		t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", parsed, n, f, len(want)-4)
	}
}

func TestQNTAddressFramesMalformed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		v6   bool
		want error
	}{
		{name: "truncated varint", body: []byte{0x40}, want: io.EOF},
		{name: "v4 address", body: []byte{0x01, 192, 0, 2}, want: errInvalidQNTAddress},
		{name: "v4 port", body: []byte{0x01, 192, 0, 2, 9, 0x1e}, want: errInvalidQNTAddress},
		{name: "v6 address", body: append([]byte{0x01}, make([]byte, 8)...), v6: true, want: errInvalidQNTAddress},
		{name: "v6 port", body: append([]byte{0x01}, make([]byte, 16)...), v6: true, want: errInvalidQNTAddress},
	}
	for _, tc := range cases {
		if _, _, err := parseAddAddressFrame(tc.body, tc.v6, protocol.Version1); !errors.Is(err, tc.want) {
			t.Errorf("AddAddress %s: err = %v, want %v", tc.name, err, tc.want)
		}
		if _, _, err := parseReachOutFrame(tc.body, tc.v6, protocol.Version1); !errors.Is(err, tc.want) {
			t.Errorf("ReachOut %s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestQNTFramesNotAdmittedByParser(t *testing.T) {
	p := NewFrameParser(false, false, false, false)
	for _, ft := range []FrameType{
		FrameTypeAddIPv4Address,
		FrameTypeAddIPv6Address,
		FrameTypeReachOutAtIPv4,
		FrameTypeReachOutAtIPv6,
		FrameTypeRemoveAddress,
	} {
		if _, _, err := p.ParseType(quicvarint.Append(nil, uint64(ft)), protocol.Encryption1RTT); err == nil {
			t.Errorf("ParseType admitted QNT frame %#x", uint64(ft))
		}
	}
}
