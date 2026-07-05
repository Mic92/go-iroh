package iroh

import (
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
