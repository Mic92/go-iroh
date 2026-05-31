package iroh

import (
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
)

func TestDnsAddressLookupDefaultsGolden(t *testing.T) {
	if dns.DNSTimeout != 3*time.Second {
		t.Errorf("dns.DNSTimeout = %v, want 3s", dns.DNSTimeout)
	}

	want := []int{200, 300, 600, 1000, 2000, 3000}
	if !slices.Equal(dnsStaggerMs, want) {
		t.Errorf("dnsStaggerMs = %v, want %v", dnsStaggerMs, want)
	}
}
