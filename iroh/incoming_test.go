package iroh

import "testing"

func TestIncomingRetryPreConnection(t *testing.T) {
	retry := false
	in := &Incoming{preRetry: &retry}
	if err := in.Retry(); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	if !retry {
		t.Fatal("Retry did not mark pre-connection incoming for QUIC Retry")
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
