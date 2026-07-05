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

func TestActiveRDMAStreamDevice(t *testing.T) {
	links := []RDMALink{
		{Device: "rdma_en3", State: rdmaPortActive, LinkLayer: rdmaLinkLayerThunderbolt, ActiveMTU: 5},
	}
	for _, tt := range []struct {
		name   string
		device string
		want   string
	}{
		{name: "default", want: "rdma_en3"},
		{name: "named", device: "rdma_en3", want: "rdma_en3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := activeRDMAStreamDevice(links, tt.device)
			if err != nil {
				t.Fatal(err)
			}
			if got.Device != tt.want {
				t.Fatalf("device = %q, want %q", got.Device, tt.want)
			}
		})
	}
	if _, err := activeRDMAStreamDevice(links, "rdma_en1"); err == nil {
		t.Fatal("inactive device lookup succeeded")
	}
	if _, err := activeRDMAStreamDevice(nil, ""); err == nil {
		t.Fatal("empty device lookup succeeded")
	}
}
