package iroh

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/socket"
)

func TestPathKeepAliveConstants(t *testing.T) {
	if HeartbeatInterval != 5*time.Second {
		t.Errorf("HeartbeatInterval = %v, want 5s", HeartbeatInterval)
	}
	if socket.HeartbeatInterval != HeartbeatInterval {
		t.Errorf("socket HeartbeatInterval = %v, want %v", socket.HeartbeatInterval, HeartbeatInterval)
	}
	if PathMaxIdleTimeout != 15*time.Second {
		t.Errorf("PathMaxIdleTimeout = %v, want 15s", PathMaxIdleTimeout)
	}
	if RelayPathMaxIdleTimeout != 30*time.Second {
		t.Errorf("RelayPathMaxIdleTimeout = %v, want 30s", RelayPathMaxIdleTimeout)
	}
}

func TestEndpointPathKeepAliveConfig(t *testing.T) {
	ep, err := Bind(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ep.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if ep.quicConf.KeepAlivePeriod != HeartbeatInterval {
		t.Errorf("KeepAlivePeriod = %v, want %v", ep.quicConf.KeepAlivePeriod, HeartbeatInterval)
	}
	if ep.quicConf.MaxIdleTimeout != RelayPathMaxIdleTimeout {
		t.Errorf("MaxIdleTimeout = %v, want %v", ep.quicConf.MaxIdleTimeout, RelayPathMaxIdleTimeout)
	}
}
