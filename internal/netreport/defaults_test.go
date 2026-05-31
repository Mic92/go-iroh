package netreport

import (
	"slices"
	"testing"
	"time"
)

func TestNetReportTimeoutAndStaggerGolden(t *testing.T) {
	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"report", overallReportTimeout, 5 * time.Second},
		{"probes", probesTimeout, 3 * time.Second},
		{"dns", dnsTimeout, 3 * time.Second},
		{"history", reportHistoryMaxAge, 5 * time.Minute},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s duration = %v, want %v", tt.name, tt.got, tt.want)
		}
	}

	wantStagger := []int{200, 300, 600, 1000, 2000, 3000}
	if !slices.Equal(dnsStaggerMs, wantStagger) {
		t.Errorf("dnsStaggerMs = %v, want %v", dnsStaggerMs, wantStagger)
	}
}
