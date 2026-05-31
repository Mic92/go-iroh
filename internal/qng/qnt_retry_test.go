package quic

import (
	"testing"
	"time"
)

func TestQNTRetryDelay(t *testing.T) {
	initialRTT := 333 * time.Millisecond
	tests := []struct {
		attempt uint8
		want    time.Duration
	}{
		{attempt: 0, want: 33300 * time.Microsecond},
		{attempt: 1, want: 33300 * time.Microsecond},
		{attempt: 2, want: 66600 * time.Microsecond},
		{attempt: 3, want: 133200 * time.Microsecond},
		{attempt: 4, want: 266400 * time.Microsecond},
		{attempt: 5, want: 532800 * time.Microsecond},
		{attempt: 6, want: 1065600 * time.Microsecond},
		{attempt: 7, want: 2 * time.Second},
		{attempt: 8, want: 2 * time.Second},
		{attempt: 9, want: 2 * time.Second},
	}
	for _, tt := range tests {
		if got := qntRetryDelay(tt.attempt, initialRTT); got != tt.want {
			t.Fatalf("qntRetryDelay(%d, %s) = %s, want %s", tt.attempt, initialRTT, got, tt.want)
		}
	}
}

func TestQNTRetryDelayZeroRTT(t *testing.T) {
	if got := qntRetryDelay(3, 0); got != 0 {
		t.Fatalf("qntRetryDelay(3, 0) = %s, want 0", got)
	}
}
