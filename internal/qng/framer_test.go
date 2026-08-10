package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
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

// TestMaxDataFrameNotAliased guards against sharing one wire.MaxDataFrame
// across emissions: the retransmission queue retains the frame pointer on
// loss, so a later window update must not mutate an in-flight frame.
func TestMaxDataFrameNotAliased(t *testing.T) {
	f := newFramer(nil)
	f.QueueMaxDataFrame(1 << 20)
	frames, _ := f.appendControlFrames(nil, 1000, monotime.Now(), protocol.Version1)
	if len(frames) != 1 {
		t.Fatalf("appended %d frames, want 1", len(frames))
	}
	inFlight := frames[0].Frame.(*wire.MaxDataFrame)
	if got := inFlight.MaximumData; got != 1<<20 {
		t.Fatalf("MaximumData = %d, want %d", got, 1<<20)
	}

	f.QueueMaxDataFrame(2 << 20)
	if got := inFlight.MaximumData; got != 1<<20 {
		t.Fatalf("in-flight frame mutated to %d after a later window update", got)
	}
	frames2, _ := f.appendControlFrames(nil, 1000, monotime.Now(), protocol.Version1)
	if len(frames2) != 1 {
		t.Fatalf("appended %d frames, want 1", len(frames2))
	}
	if frames2[0].Frame.(*wire.MaxDataFrame) == inFlight {
		t.Fatal("second emission reused the in-flight frame pointer")
	}
}
