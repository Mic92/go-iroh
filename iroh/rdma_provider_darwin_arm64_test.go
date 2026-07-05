//go:build darwin && arm64

package iroh

import (
	"errors"
	"strings"
	"testing"
)

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

func TestParseDarwinRDMAProviderBlocked(t *testing.T) {
	out := []byte(`
+-o rdma_en2  <class AppleThunderboltRDMAInterface, id 0x100000002, registered, matched, active, busy 3 (1 ms), retain 10>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=0,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000003, !registered, !matched, inactive, busy 1 (1 ms), retain 8>

+-o rdma_en3  <class AppleThunderboltRDMAInterface, id 0x100000004, registered, matched, active, busy 2 (1 ms), retain 20>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=2,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000005, !registered, !matched, inactive, busy 1 (1 ms), retain 8>
  +-o AppleThunderboltRDMAQueuePair  <class AppleThunderboltRDMAQueuePair, id 0x100000006, !registered, !matched, inactive, busy 1 (1 ms), retain 10>
`)
	got := parseDarwinRDMAProviderBlocked(out)
	if got != "rdma_en3 has inactive busy protection domain" {
		t.Fatalf("blocked = %q", got)
	}
}

func TestParseDarwinRDMAProviderBlockedReady(t *testing.T) {
	out := []byte(`
+-o rdma_en3  <class AppleThunderboltRDMAInterface, id 0x100000004, registered, matched, active, busy 2 (1 ms), retain 20>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=2,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000005, registered, matched, active, busy 0 (0 ms), retain 6>
`)
	if got := parseDarwinRDMAProviderBlocked(out); got != "" {
		t.Fatalf("blocked = %q", got)
	}
}

func TestDarwinRDMALinksRejectsBlockedProvider(t *testing.T) {
	out := []byte(`
+-o rdma_en3  <class AppleThunderboltRDMAInterface, id 0x100000004, registered, matched, active, busy 2 (1 ms), retain 20>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=2,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000005, !registered, !matched, inactive, busy 1 (1 ms), retain 8>
`)
	links, err := darwinRDMALinksFromIOReg(out)
	if !errors.Is(err, ErrRDMAUnsupported) || !strings.Contains(err.Error(), "rdma_en3 has inactive busy protection domain") {
		t.Fatalf("darwinRDMALinksFromIOReg = %+v, %v; want blocked unsupported", links, err)
	}
}

func TestDarwinRDMALinksFiltersBlockedProvider(t *testing.T) {
	out := []byte(`
+-o rdma_en3  <class AppleThunderboltRDMAInterface, id 0x100000004, registered, matched, active, busy 2 (1 ms), retain 20>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=2,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000005, !registered, !matched, inactive, busy 1 (1 ms), retain 8>

+-o rdma_en4  <class AppleThunderboltRDMAInterface, id 0x100000006, registered, matched, active, busy 2 (1 ms), retain 20>
  | {
  |   "IOPowerManagement" = {"DevicePowerState"=2,"CurrentPowerState"=2,"MaxPowerState"=2}
  | }
  +-o AppleThunderboltRDMAProtectionDomain  <class AppleThunderboltRDMAProtectionDomain, id 0x100000007, registered, matched, active, busy 0 (0 ms), retain 6>
`)
	links, err := darwinRDMALinksFromIOReg(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Device != "rdma_en4" {
		t.Fatalf("links = %+v, want only rdma_en4", links)
	}
}
