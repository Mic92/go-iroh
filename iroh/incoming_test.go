package iroh

import (
	"errors"
	"testing"
)

func TestIncomingRetryUnsupported(t *testing.T) {
	for _, in := range []*Incoming{nil, &Incoming{}} {
		if err := in.Retry(); !errors.Is(err, ErrIncomingRetryUnsupported) {
			t.Fatalf("Retry error = %v, want %v", err, ErrIncomingRetryUnsupported)
		}
	}
}

func TestIncomingFilterOutcomeValues(t *testing.T) {
	tests := []struct {
		name string
		got  IncomingFilterOutcome
		want IncomingFilterOutcome
	}{
		{"accept", FilterAccept, 0},
		{"retry", FilterRetry, 1},
		{"reject", FilterReject, 2},
		{"ignore", FilterIgnore, 3},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}
