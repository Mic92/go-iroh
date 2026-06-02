package iroh

import "testing"

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
