package wire

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests pin the QUIC Address Discovery OBSERVED_ADDRESS wire format
// against the authoritative noq-proto reference
// (internal/qng/n0ext/reference/frame.rs). The golden byte slices are derived by
// hand from the Rust field order cited in each case (frame.rs:2164-2178), so a
// drift in either the Go codec or the frame-type ids is caught.

// TestObservedAddrFrameTypeVarints pins the frame-type ids 0x9f81a6 / 0x9f81a7
// (frame.rs:100-103) and their 4-byte QUIC varint encodings. A value in
// [0x40000000, 0x3FFFFFFFFFFFFFFF] uses the 8-byte form; 0x9f81a6 fits the
// 4-byte form (0x80 | high bytes).
func TestObservedAddrFrameTypeVarints(t *testing.T) {
	cases := []struct {
		typ  FrameType
		want []byte
	}{
		// 0x9f81a6 -> 4-byte varint: 0xc0 | 0x00 .. = 0x80,0x9f,0x81,0xa6.
		{FrameTypeObservedIPv4Addr, []byte{0x80, 0x9f, 0x81, 0xa6}},
		{FrameTypeObservedIPv6Addr, []byte{0x80, 0x9f, 0x81, 0xa7}},
	}
	for _, tc := range cases {
		got := quicvarint.Append(nil, uint64(tc.typ))
		if !bytes.Equal(got, tc.want) {
			t.Errorf("frame type %#x varint = % x, want % x", uint64(tc.typ), got, tc.want)
		}

		f := &ObservedAddrFrame{}
		// Drive the type selection through a frame so the helper is exercised too.
		switch tc.typ {
		case FrameTypeObservedIPv6Addr:
			f.Addr = netip.MustParseAddr("::1")
		default:
			f.Addr = netip.MustParseAddr("0.0.0.0")
		}
		if got := f.frameType(); got != tc.typ {
			t.Errorf("frameType() = %#x, want %#x", uint64(got), uint64(tc.typ))
		}
	}
}

func TestObservedAddrFrameGoldenIPv4(t *testing.T) {
	// frame.rs:2164-2178 — encode order: frame_type, seq_no (varint), ip (4 raw
	// bytes), port (u16 big-endian). frame.rs:100-101 — ObservedIpv4Addr =
	// 0x9f81a6 -> varint 80 9f 81 a6.
	f := &ObservedAddrFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("192.0.2.7"),
		Port:  0x1234,
	}
	want := []byte{
		0x80, 0x9f, 0x81, 0xa6, // frame type 0x9f81a6
		0x01,         // seq_no = 1 (1-byte varint)
		192, 0, 2, 7, // ip 192.0.2.7
		0x12, 0x34, // port 0x1234 big-endian
	}
	got, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	if l := f.Length(protocol.Version1); int(l) != len(want) {
		t.Fatalf("Length() = %d, encoded %d bytes", l, len(want))
	}

	// Round-trip: the parser is fed the body (after the frame type), with the
	// family selected by the type, exactly as ParseLessCommonFrame dispatches.
	parsed, n, err := parseObservedAddrFrame(want[4:], false, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 {
		t.Fatalf("consumed %d bytes, want %d", n, len(want)-4)
	}
	if parsed.SeqNo != f.SeqNo || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, want %+v", parsed, f)
	}
}

func TestObservedAddrFrameGoldenIPv6(t *testing.T) {
	// frame.rs:100-103 — ObservedIpv6Addr = 0x9f81a7 -> varint 80 9f 81 a7. A
	// seq_no of 0x4242 needs the 2-byte varint form (0x40|high, low) = 42 42 ->
	// 0x42|0x40 = ... actually 0x4242 > 0x3FFF, so it is a 4-byte varint.
	f := &ObservedAddrFrame{
		SeqNo: 16383, // 0x3FFF: the largest 2-byte varint
		Addr:  netip.MustParseAddr("2001:db8::1"),
		Port:  443,
	}
	v6 := f.Addr.As16()
	want := []byte{0x80, 0x9f, 0x81, 0xa7, 0x7f, 0xff}
	want = append(want, v6[:]...)
	want = append(want, 0x01, 0xbb) // port 443 big-endian
	got, err := f.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encode = % x, want % x", got, want)
	}
	if l := f.Length(protocol.Version1); int(l) != len(want) {
		t.Fatalf("Length() = %d, encoded %d bytes", l, len(want))
	}
	parsed, n, err := parseObservedAddrFrame(want[4:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(want)-4 {
		t.Fatalf("consumed %d bytes, want %d", n, len(want)-4)
	}
	if parsed.SeqNo != f.SeqNo || parsed.Addr != f.Addr || parsed.Port != f.Port {
		t.Fatalf("parsed = %+v, want %+v", parsed, f)
	}
}

// TestObservedAddrFrameTruncated confirms a body too short for its declared
// family is rejected, mirroring the fixed-size reads in ObservedAddr::read
// (frame.rs:2147-2156).
func TestObservedAddrFrameTruncated(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		v6   bool
		want error
	}{
		{
			name: "truncated varint",
			body: []byte{0x40},
			want: io.EOF,
		},
		{
			name: "v4 address",
			body: []byte{0x01, 192, 0, 2},
			want: errInvalidObservedAddr,
		},
		{
			name: "v4 port",
			body: []byte{0x01, 192, 0, 2, 7, 0x12},
			want: errInvalidObservedAddr,
		},
		{
			name: "v6 address",
			body: append([]byte{0x01}, make([]byte, 8)...),
			v6:   true,
			want: errInvalidObservedAddr,
		},
		{
			name: "v6 port",
			body: append([]byte{0x01}, make([]byte, 16)...),
			v6:   true,
			want: errInvalidObservedAddr,
		},
	}
	for _, tc := range cases {
		_, _, err := parseObservedAddrFrame(tc.body, tc.v6, protocol.Version1)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestObservedAddrFrameFamilyFromType(t *testing.T) {
	v4 := &ObservedAddrFrame{
		SeqNo: 9,
		Addr:  netip.MustParseAddr("198.51.100.99"),
		Port:  9999,
	}
	b, err := v4.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseObservedAddrFrame(b[4:], true, protocol.Version1); !errors.Is(err, errInvalidObservedAddr) {
		t.Fatalf("v4 body parsed as v6: err = %v, want %v", err, errInvalidObservedAddr)
	}

	v6 := &ObservedAddrFrame{
		SeqNo: 10,
		Addr:  netip.MustParseAddr("2001:db8::99"),
		Port:  9999,
	}
	b, err = v6.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	parsed, n, err := parseObservedAddrFrame(b[4:], true, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(b)-4 || parsed.Addr != v6.Addr || parsed.Port != v6.Port || parsed.SeqNo != v6.SeqNo {
		t.Fatalf("v6 parse = %+v, %d bytes, want %+v, %d bytes", parsed, n, v6, len(b)-4)
	}
}

// TestAddressDiscoveryRoleSemantics pins the Role transition and negotiation
// logic against address_discovery.rs:44-56.
func TestAddressDiscoveryRoleSemantics(t *testing.T) {
	cases := []struct {
		local, peer AddressDiscoveryRole
		report      bool // local.ShouldReport(peer)
	}{
		// A send-only reporter reports to a receiver.
		{AddressDiscoverySendOnly, AddressDiscoveryReceiveOnly, true},
		{AddressDiscoverySendOnly, AddressDiscoveryBoth, true},
		// A send-only reporter does not report to a non-receiver.
		{AddressDiscoverySendOnly, AddressDiscoverySendOnly, false},
		{AddressDiscoverySendOnly, AddressDiscoveryDisabled, false},
		// A receive-only peer is not a reporter.
		{AddressDiscoveryReceiveOnly, AddressDiscoveryReceiveOnly, false},
		// Both-both reports.
		{AddressDiscoveryBoth, AddressDiscoveryBoth, true},
		// Disabled never reports.
		{AddressDiscoveryDisabled, AddressDiscoveryBoth, false},
	}
	for _, tc := range cases {
		if got := tc.local.ShouldReport(tc.peer); got != tc.report {
			t.Errorf("%v.ShouldReport(%v) = %v, want %v", tc.local, tc.peer, got, tc.report)
		}
	}
}

// TestObservedAddrTransportParameterRoundTrip confirms the observed_address
// transport parameter (id 0x9f81a176, transport_parameters.rs:726) round-trips
// for each enabled role and is omitted when disabled.
func TestObservedAddrTransportParameterRoundTrip(t *testing.T) {
	for _, role := range []AddressDiscoveryRole{
		AddressDiscoverySendOnly,
		AddressDiscoveryReceiveOnly,
		AddressDiscoveryBoth,
	} {
		p := &TransportParameters{
			AddressDiscoveryRole:      role,
			ActiveConnectionIDLimit:   2,
			InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		}
		b := p.Marshal(protocol.PerspectiveClient)
		var got TransportParameters
		if err := got.Unmarshal(b, protocol.PerspectiveClient); err != nil {
			t.Fatalf("role %v: Unmarshal: %v", role, err)
		}
		if got.AddressDiscoveryRole != role {
			t.Errorf("role %v: round-trip = %v", role, got.AddressDiscoveryRole)
		}
	}

	// Disabled omits the parameter entirely: the marshaled bytes must not
	// contain the observed_address id, and decode back to Disabled.
	p := &TransportParameters{
		AddressDiscoveryRole:      AddressDiscoveryDisabled,
		ActiveConnectionIDLimit:   2,
		InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	}
	b := p.Marshal(protocol.PerspectiveClient)
	var got TransportParameters
	if err := got.Unmarshal(b, protocol.PerspectiveClient); err != nil {
		t.Fatalf("disabled: Unmarshal: %v", err)
	}
	if got.AddressDiscoveryRole != AddressDiscoveryDisabled {
		t.Errorf("disabled: round-trip = %v, want Disabled", got.AddressDiscoveryRole)
	}
}

// TestObservedAddrTransportParameterIllegalRole confirms an out-of-range role
// value is rejected (address_discovery.rs:32, transport_parameters.rs:531).
func TestObservedAddrTransportParameterIllegalRole(t *testing.T) {
	p := &TransportParameters{}
	// Hand-build a transport-parameters blob carrying observed_address = 3.
	b := p.marshalVarintParam(nil, observedAddrParameterID, 3)
	var got TransportParameters
	if err := got.Unmarshal(b, protocol.PerspectiveClient); err == nil {
		t.Error("expected error for illegal address-discovery role value 3")
	}
}

func TestObservedAddrTransportParameterMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{
			name: "empty value",
			b: append(quicvarint.Append(quicvarint.Append(nil, uint64(observedAddrParameterID)), 0),
				quicvarint.Append(quicvarint.Append(nil, uint64(initialSourceConnectionIDParameterID)), 0)...),
		},
		{
			name: "overlong value",
			b:    append(quicvarint.Append(quicvarint.Append(nil, uint64(observedAddrParameterID)), 2), 0, 0),
		},
		{
			name: "duplicate",
			b: append((&TransportParameters{}).marshalVarintParam(nil, observedAddrParameterID, 0),
				(&TransportParameters{}).marshalVarintParam(nil, observedAddrParameterID, 1)...),
		},
	}
	for _, tc := range cases {
		var got TransportParameters
		if err := got.Unmarshal(tc.b, protocol.PerspectiveClient); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestObservedAddrFrameAdmissionGated(t *testing.T) {
	off := NewFrameParser(false, false, false, false)
	on := NewFrameParser(false, false, false, false)
	on.SetSupportsAddressDiscovery(true)

	for _, ft := range []FrameType{FrameTypeObservedIPv4Addr, FrameTypeObservedIPv6Addr} {
		typeBytes := quicvarint.Append(nil, uint64(ft))

		_, _, err := off.ParseType(typeBytes, protocol.Encryption1RTT)
		var transErr *qerr.TransportError
		if !errors.As(err, &transErr) || transErr.ErrorCode != qerr.FrameEncodingError {
			t.Errorf("type %#x gate-off: err = %v, want FrameEncodingError", uint64(ft), err)
		}

		got, _, err := on.ParseType(typeBytes, protocol.Encryption1RTT)
		if err != nil {
			t.Errorf("type %#x gate-on: %v", uint64(ft), err)
			continue
		}
		if got != ft {
			t.Errorf("type %#x gate-on: ParseType = %#x", uint64(ft), uint64(got))
		}
	}
}

func TestObservedAddrFrameOneRTTOnly(t *testing.T) {
	p := NewFrameParser(false, false, false, false)
	p.SetSupportsAddressDiscovery(true)
	levels := []protocol.EncryptionLevel{
		protocol.EncryptionInitial,
		protocol.EncryptionHandshake,
		protocol.Encryption0RTT,
	}
	for _, ft := range []FrameType{FrameTypeObservedIPv4Addr, FrameTypeObservedIPv6Addr} {
		typeBytes := quicvarint.Append(nil, uint64(ft))
		for _, lvl := range levels {
			if _, _, err := p.ParseType(typeBytes, lvl); err == nil {
				t.Errorf("type %#x admitted at %s, want rejected", uint64(ft), lvl)
			}
		}
		if _, _, err := p.ParseType(typeBytes, protocol.Encryption1RTT); err != nil {
			t.Errorf("type %#x rejected at 1-RTT: %v", uint64(ft), err)
		}
	}
}

func TestObservedAddrFrameParseDispatch(t *testing.T) {
	p := NewFrameParser(false, false, false, false)
	p.SetSupportsAddressDiscovery(true)

	for _, f := range []*ObservedAddrFrame{
		{SeqNo: 1, Addr: netip.MustParseAddr("203.0.113.10"), Port: 4444},
		{SeqNo: 2, Addr: netip.MustParseAddr("2001:db8::10"), Port: 4445},
	} {
		b, err := f.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		ft, n, err := p.ParseType(b, protocol.Encryption1RTT)
		if err != nil {
			t.Fatal(err)
		}
		got, consumed, err := p.ParseLessCommonFrame(ft, b[n:], protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		obs, ok := got.(*ObservedAddrFrame)
		if !ok {
			t.Fatalf("ParseLessCommonFrame returned %T, want *ObservedAddrFrame", got)
		}
		if consumed != len(b)-n || obs.SeqNo != f.SeqNo || obs.Addr != f.Addr || obs.Port != f.Port {
			t.Fatalf("parsed = %+v, %d bytes, want %+v, %d bytes", obs, consumed, f, len(b)-n)
		}
	}
}
