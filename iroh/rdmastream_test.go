package iroh

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRDMAStreamAddr(t *testing.T) {
	addr := rdmaStreamAddr(99, RDMALink{Device: "rdma_en3", State: 4, LinkLayer: 100, ActiveMTU: 5}, "127.0.0.1:1")
	got, err := ParseStreamLinkAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != TransportLinkRDMA || got.Interface != "rdma_en3" || got.DialAddr != "rdma:rdma_en3@127.0.0.1:1" {
		t.Fatalf("addr = %+v", got)
	}
}

func TestParseRDMAStreamDialAddr(t *testing.T) {
	got, err := parseRDMAStreamDialAddr("rdma:rdma_en3@127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != "rdma_en3" || got.Control != "127.0.0.1:1" {
		t.Fatalf("dial info = %+v", got)
	}
	got, err = parseRDMAStreamDialAddr("rdma:rdma_en3")
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != "rdma_en3" || got.Control != "" {
		t.Fatalf("dial info without control = %+v", got)
	}
	for _, s := range []string{"", "tcp:rdma_en3", "rdma:", "rdma:rdma_en3@"} {
		if _, err := parseRDMAStreamDialAddr(s); err == nil {
			t.Fatalf("parseRDMAStreamDialAddr(%q) succeeded", s)
		}
	}
}

func TestRDMAStreamSelectionString(t *testing.T) {
	sel := StreamLinkSelection{
		Remote: rdmaStreamAddr(99, RDMALink{Device: "rdma_en3"}, "[fe80::1%bridge0]:1"),
		Class:  TransportLinkRDMA,
	}
	got := rdmaStreamSelectionString(sel)
	want := "class=rdma device=rdma_en3 control=[fe80::1%bridge0]:1 interface=rdma_en3"
	if got != want {
		t.Fatalf("selection string = %q, want %q", got, want)
	}
}

func TestRDMAStreamControlsForThunderboltLink(t *testing.T) {
	controls := []rdmaStreamControlAddr{
		{Addr: "127.0.0.1:1", Class: TransportLinkLoopback},
		{Addr: "[fe80::1%bridge0]:1", Class: TransportLinkThunderbolt},
		{Addr: "192.0.2.1:1", Class: TransportLinkWiredLAN},
	}
	got := rdmaStreamControlsForLink(RDMALink{LinkLayer: rdmaLinkLayerThunderbolt}, controls, nil)
	if len(got) != 1 || got[0].Addr != "[fe80::1%bridge0]:1" {
		t.Fatalf("controls = %+v, want thunderbolt only", got)
	}
	if len(controls) != 3 || controls[0].Addr != "127.0.0.1:1" {
		t.Fatalf("controls mutated: %+v", controls)
	}
}

func TestRDMAStreamControlsFallback(t *testing.T) {
	controls := []rdmaStreamControlAddr{
		{Addr: "127.0.0.1:1", Class: TransportLinkLoopback},
		{Addr: "192.0.2.1:1", Class: TransportLinkWiredLAN},
	}
	got := rdmaStreamControlsForLink(RDMALink{LinkLayer: rdmaLinkLayerThunderbolt}, controls, nil)
	if len(got) != len(controls) {
		t.Fatalf("thunderbolt fallback controls = %+v, want %+v", got, controls)
	}
	got = rdmaStreamControlsForLink(RDMALink{}, controls, nil)
	if len(got) != len(controls) {
		t.Fatalf("generic controls = %+v, want %+v", got, controls)
	}
}

func TestLocalRDMAStreamAddrsPrefersThunderboltControls(t *testing.T) {
	old := rdmaLocalLinks
	rdmaLocalLinks = func(ctx context.Context) ([]RDMALink, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []RDMALink{{Device: "rdma_en3", LinkLayer: rdmaLinkLayerThunderbolt}}, nil
	}
	defer func() { rdmaLocalLinks = old }()

	addrs, err := localRDMAStreamAddrs(context.Background(), 99, []rdmaStreamControlAddr{
		{Addr: "127.0.0.1:1", Class: TransportLinkLoopback},
		{Addr: "[fe80::1%bridge0]:1", Class: TransportLinkThunderbolt},
		{Addr: "192.0.2.1:1", Class: TransportLinkWiredLAN},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Fatalf("len(addrs) = %d, want 1", len(addrs))
	}
	got, err := ParseStreamLinkAddr(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.DialAddr != "rdma:rdma_en3@[fe80::1%bridge0]:1" {
		t.Fatalf("dial addr = %q, want thunderbolt control", got.DialAddr)
	}
}

func TestLocalRDMAStreamAddrsKeepsFallbackControls(t *testing.T) {
	old := rdmaLocalLinks
	rdmaLocalLinks = func(ctx context.Context) ([]RDMALink, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []RDMALink{{Device: "rdma_en3", LinkLayer: rdmaLinkLayerThunderbolt}}, nil
	}
	defer func() { rdmaLocalLinks = old }()

	addrs, err := localRDMAStreamAddrs(context.Background(), 99, []rdmaStreamControlAddr{
		{Addr: "127.0.0.1:1", Class: TransportLinkLoopback},
		{Addr: "192.0.2.1:1", Class: TransportLinkWiredLAN},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2", len(addrs))
	}
}

func TestRDMAStreamTransportDialUnsupported(t *testing.T) {
	tr, err := NewRDMAStreamTransport(99)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DialStream(context.Background(), rdmaStreamAddr(99, RDMALink{Device: "rdma_en3"}, "127.0.0.1:1"), StreamOptions{}); !errors.Is(err, ErrRDMAUnsupported) {
		t.Fatalf("DialStream = %v, want %v", err, ErrRDMAUnsupported)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRDMAStreamDestinationRoundTrip(t *testing.T) {
	want := rdmaStreamDestination{
		LID:       17,
		QPN:       42,
		PSN:       7,
		GIDIndex:  3,
		ActiveMTU: 5,
	}
	copy(want.GID[:], []byte{1, 2, 3, 4})
	var buf bytes.Buffer
	if err := writeRDMAStreamDestination(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readRDMAStreamDestination(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("destination = %+v, want %+v", got, want)
	}
}

func TestRDMAStreamDestinationRejectsInvalid(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRDMAStreamDestination(&buf, rdmaStreamDestination{}); err == nil {
		t.Fatal("writeRDMAStreamDestination succeeded with empty destination")
	}
	dst := rdmaStreamDestination{LID: 1, QPN: 1, PSN: maxRDMAStreamPSN + 1}
	if err := writeRDMAStreamDestination(&buf, dst); err == nil {
		t.Fatal("writeRDMAStreamDestination succeeded with out-of-range psn")
	}
}

func TestRDMAStreamFramePayloadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRDMAStreamFramePayload(&buf, 1024); err != nil {
		t.Fatal(err)
	}
	got, err := readRDMAStreamFramePayload(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1024 {
		t.Fatalf("frame payload = %d, want 1024", got)
	}
	if err := writeRDMAStreamFramePayload(&buf, 0); err == nil {
		t.Fatal("writeRDMAStreamFramePayload succeeded with zero payload")
	}
	buf.Reset()
	buf.Write([]byte{0, 0, 0, 0})
	if _, err := readRDMAStreamFramePayload(&buf); err == nil {
		t.Fatal("readRDMAStreamFramePayload succeeded with zero payload")
	}
}

func TestRDMAStreamStringRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRDMAStreamString(&buf, "rdma_en3"); err != nil {
		t.Fatal(err)
	}
	got, err := readRDMAStreamString(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != "rdma_en3" {
		t.Fatalf("string = %q, want rdma_en3", got)
	}
}

func TestRDMAStreamStringRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	if err := writeRDMAStreamString(&buf, string(make([]byte, maxRDMAStreamStringLength+1))); err == nil {
		t.Fatal("writeRDMAStreamString succeeded with oversized string")
	}
	n := maxRDMAStreamStringLength + 1
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
	if _, err := readRDMAStreamString(&buf); err == nil {
		t.Fatal("readRDMAStreamString succeeded with oversized string")
	}
}

func BenchmarkRDMAStreamStringRoundTrip(b *testing.B) {
	var buf bytes.Buffer
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := writeRDMAStreamString(&buf, "rdma_en3"); err != nil {
			b.Fatal(err)
		}
		got, err := readRDMAStreamString(&buf)
		if err != nil {
			b.Fatal(err)
		}
		if got != "rdma_en3" {
			b.Fatalf("string = %q, want rdma_en3", got)
		}
	}
}

func BenchmarkReadRDMAStreamString(b *testing.B) {
	var data bytes.Buffer
	if err := writeRDMAStreamString(&data, "rdma_en3"); err != nil {
		b.Fatal(err)
	}
	p := data.Bytes()
	r := bytes.NewReader(p)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.Reset(p)
		got, err := readRDMAStreamString(r)
		if err != nil {
			b.Fatal(err)
		}
		if got != "rdma_en3" {
			b.Fatalf("string = %q, want rdma_en3", got)
		}
	}
}
