package iroh

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRDMAStreamAddr(t *testing.T) {
	addr := rdmaStreamAddr(99, RDMALink{Device: "rdma_en3", State: 4, LinkLayer: 100, ActiveMTU: 5})
	got, err := ParseStreamLinkAddr(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != TransportLinkRDMA || got.Interface != "rdma_en3" || got.DialAddr != "rdma:rdma_en3" {
		t.Fatalf("addr = %+v", got)
	}
}

func TestRDMAStreamTransportDialUnsupported(t *testing.T) {
	tr, err := NewRDMAStreamTransport(99)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DialStream(context.Background(), rdmaStreamAddr(99, RDMALink{Device: "rdma_en3"}), StreamOptions{}); !errors.Is(err, ErrRDMAUnsupported) {
		t.Fatalf("DialStream = %v, want %v", err, ErrRDMAUnsupported)
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
