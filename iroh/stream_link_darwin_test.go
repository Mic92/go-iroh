//go:build darwin

package iroh

import "testing"

func TestParseAppleNetworkHardwarePortClasses(t *testing.T) {
	out := `
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 8a:11:aa:cc:2d:ec

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:44:6d:68:de:00

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 70:8c:f2:b6:97:b8

Hardware Port: Thunderbolt 1
Device: en1
Ethernet Address: 36:44:6d:68:de:00

VLAN Configurations
===================
`
	got := parseAppleNetworkHardwarePortClasses(out)
	want := map[string]TransportLinkClass{
		"en4":     TransportLinkWiredLAN,
		"bridge0": TransportLinkThunderbolt,
		"en0":     TransportLinkWiFiLAN,
		"en1":     TransportLinkThunderbolt,
	}
	if len(got) != len(want) {
		t.Fatalf("len(classes) = %d, want %d: %+v", len(got), len(want), got)
	}
	for dev, class := range want {
		if got[dev] != class {
			t.Fatalf("class[%s] = %v, want %v", dev, got[dev], class)
		}
	}
}
