package netreport

import (
	"context"
	"testing"
)

// TestNewClientNilMapDefaultsToEmpty covers the relayMap == nil branch of
// NewClient: a nil map is replaced with an empty one so the Client is usable
// and reports against it run no probes. client.go:62.
func TestNewClientNilMapDefaultsToEmpty(t *testing.T) {
	c := NewClient(nil)
	if c.relayMap == nil {
		t.Fatal("NewClient(nil) left relayMap nil")
	}
	if !c.relayMap.IsEmpty() {
		t.Error("NewClient(nil) relay map is not empty")
	}

	rep, err := c.GetReport(context.Background(), IfStateDetails{}, true)
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if !rep.PreferredRelay.IsZero() {
		t.Errorf("PreferredRelay = %v, want zero for empty map", rep.PreferredRelay)
	}
	if rep.CaptivePortal != nil {
		t.Error("captive portal should not run for an empty relay map")
	}
}
