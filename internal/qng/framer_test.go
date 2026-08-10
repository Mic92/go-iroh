package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

func TestFramerHasMaxData(t *testing.T) {
	f := newFramer(nil)
	if f.HasData() {
		t.Fatal("new framer has data")
	}
	f.QueueMaxDataFrame(protocol.ByteCount(1))
	if !f.HasData() {
		t.Fatal("framer with MAX_DATA has no data")
	}
}
