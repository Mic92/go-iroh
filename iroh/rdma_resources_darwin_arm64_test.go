//go:build darwin && arm64

package iroh

import (
	"strings"
	"testing"

	applerdma "github.com/tmc/apple/rdma"
)

func TestRDMAStreamPostWorkValidation(t *testing.T) {
	mr := &rdmaStreamMemoryRegion{buf: make([]byte, 16), handle: 1}
	tests := []struct {
		name string
		work rdmaStreamPostWork
	}{
		{"negative offset", rdmaStreamPostWork{Offset: -1, Length: 1}},
		{"negative length", rdmaStreamPostWork{Offset: 0, Length: -1}},
		{"past end", rdmaStreamPostWork{Offset: 17, Length: 0}},
		{"overflow", rdmaStreamPostWork{Offset: 8, Length: 9}},
	}
	for _, tt := range tests {
		if err := validateRDMAStreamPostWork("post", mr, 0, tt.work); err == nil {
			t.Fatalf("%s: validateRDMAStreamPostWork succeeded", tt.name)
		}
	}
	if err := validateRDMAStreamPostWork("post", mr, 0, rdmaStreamPostWork{Offset: 8, Length: 8}); err != nil {
		t.Fatalf("valid work: %v", err)
	}
}

func TestRDMAStreamPostValidation(t *testing.T) {
	qp := &rdmaStreamQueuePair{handle: 1}
	mr := &rdmaStreamMemoryRegion{buf: make([]byte, 16), handle: 1}
	if err := validateRDMAStreamPost(qp, mr, "post send", 4, 8); err != nil {
		t.Fatalf("valid post: %v", err)
	}
	if err := validateRDMAStreamPost(nil, mr, "post send", 4, 8); err == nil {
		t.Fatal("nil queue pair validation succeeded")
	}
	if err := validateRDMAStreamPost(qp, nil, "post send", 4, 8); err == nil {
		t.Fatal("nil memory region validation succeeded")
	}
	if err := validateRDMAStreamPost(qp, mr, "post send", 12, 8); err == nil {
		t.Fatal("out of range validation succeeded")
	}
}

func TestBuildRDMAStreamWorkRequestsSkipZeroLength(t *testing.T) {
	mr := &rdmaStreamMemoryRegion{buf: make([]byte, 16), handle: 1, lkey: 99}
	var sendWR [2]applerdma.IbvSendWR
	var recvWR [2]applerdma.IbvRecvWR
	var sge [2]applerdma.IbvSGE
	works := []rdmaStreamPostWork{
		{Offset: 0, Length: 0, ID: 1},
		{Offset: 4, Length: 4, ID: 2},
	}
	n, err := buildRDMAStreamSendWorkRequests("send", mr, works, sendWR[:], sge[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || sendWR[0].WRID != 2 || sendWR[0].SGList == nil || sendWR[0].SGList.Length != 4 {
		t.Fatalf("send n=%d wr=%+v", n, sendWR[0])
	}
	n, err = buildRDMAStreamRecvWorkRequests("recv", mr, works, recvWR[:], sge[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || recvWR[0].WRID != 2 || recvWR[0].SGList == nil || recvWR[0].SGList.Length != 4 {
		t.Fatalf("recv n=%d wr=%+v", n, recvWR[0])
	}
}

func TestRDMAStreamWorkRequests(t *testing.T) {
	wc := []applerdma.IbvWC{{WRID: 11, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 7}}
	works, err := rdmaStreamWorkRequests(wc, len(wc))
	if err != nil {
		t.Fatal(err)
	}
	if len(works) != 1 || works[0].ID != 11 || works[0].Bytes != 7 {
		t.Fatalf("works = %+v", works)
	}
	out := make([]rdmaStreamWorkRequest, 8)
	works, err = fillRDMAStreamWorkRequests(out, wc, len(wc))
	if err != nil {
		t.Fatal(err)
	}
	if len(works) != 1 || works[0].ID != 11 || cap(works) != cap(out) {
		t.Fatalf("filled works = len %d cap %d %+v", len(works), cap(works), works)
	}
	_, err = rdmaStreamWorkRequests([]applerdma.IbvWC{{WRID: 12, Status: 5}}, 1)
	if err == nil || !strings.Contains(err.Error(), "status 5") {
		t.Fatalf("failure err = %v", err)
	}
	_, err = fillRDMAStreamWorkRequests(make([]rdmaStreamWorkRequest, 1), wc, 2)
	if err == nil || !strings.Contains(err.Error(), "outside buffer length") {
		t.Fatalf("short input err = %v", err)
	}
	_, err = fillRDMAStreamWorkRequests(nil, wc, 1)
	if err == nil || !strings.Contains(err.Error(), "outside output length") {
		t.Fatalf("short output err = %v", err)
	}
}

func BenchmarkRDMAStreamWorkRequests(b *testing.B) {
	wc := []applerdma.IbvWC{
		{WRID: 11, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 7},
		{WRID: 12, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 8},
		{WRID: 13, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 9},
		{WRID: 14, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 10},
		{WRID: 15, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 11},
		{WRID: 16, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 12},
		{WRID: 17, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 13},
		{WRID: 18, Status: applerdma.IBV_WC_SUCCESS, Opcode: 3, ByteLen: 14},
	}
	out := make([]rdmaStreamWorkRequest, len(wc))
	b.ReportAllocs()
	for b.Loop() {
		works, err := fillRDMAStreamWorkRequests(out, wc, len(wc))
		if err != nil {
			b.Fatal(err)
		}
		if len(works) != len(wc) {
			b.Fatalf("len(works) = %d, want %d", len(works), len(wc))
		}
	}
}

func TestSelectRDMAStreamPortGID(t *testing.T) {
	var zero applerdma.IbvGID
	var ipv4 applerdma.IbvGID
	ipv4[10], ipv4[11], ipv4[12] = 0xff, 0xff, 192
	var other applerdma.IbvGID
	other[15] = 1
	gids := []rdmaStreamPortGID{
		{index: 0, gid: other},
		{index: 1, gid: zero},
		{index: 2, gid: ipv4},
	}
	if got := selectRDMAStreamPortGID(gids); got != 2 {
		t.Fatalf("selectRDMAStreamPortGID = %d, want 2", got)
	}
	gids = []rdmaStreamPortGID{
		{index: 0, gid: other},
		{index: 1, gid: other},
	}
	if got := selectRDMAStreamPortGID(gids); got != 1 {
		t.Fatalf("selectRDMAStreamPortGID fallback = %d, want 1", got)
	}
}

func TestRoundRDMAStreamPage(t *testing.T) {
	if got := roundRDMAStreamPage(1); got != 16*1024 {
		t.Fatalf("roundRDMAStreamPage(1) = %d", got)
	}
	if got := roundRDMAStreamPage(32 * 1024); got != 32*1024 {
		t.Fatalf("roundRDMAStreamPage(32K) = %d", got)
	}
}
