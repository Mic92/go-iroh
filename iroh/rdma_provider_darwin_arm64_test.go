//go:build darwin && arm64

package iroh

import "testing"

func TestParseDarwinRDMALinks(t *testing.T) {
	out := []byte(`
+-o rdma_en1  <class AppleThunderboltRDMAInterface, id 0x100000001, registered, matched, active, busy 0 (0 ms), retain 7>
    {
      "CurrentPowerState"=0
    }
+-o rdma_en3  <class AppleThunderboltRDMAInterface, id 0x100000003, registered, matched, active, busy 0 (0 ms), retain 7>
    {
      "CurrentPowerState"=2
    }
`)
	links := parseDarwinRDMALinks(out)
	if len(links) != 1 {
		t.Fatalf("len(links) = %d, want 1", len(links))
	}
	want := RDMALink{
		Device:    "rdma_en3",
		State:     rdmaPortActive,
		LinkLayer: rdmaLinkLayerThunderbolt,
		ActiveMTU: 5,
	}
	if links[0] != want {
		t.Fatalf("link = %+v, want %+v", links[0], want)
	}
}
