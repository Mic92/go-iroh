package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// newMaxPathIDTestConn builds a minimal Conn with a framer and the channels
// queueControlFrame touches, enough to exercise queueMaxPathID/canOpenPath
// without a full handshake. localMax==nil leaves multipath off (the default);
// peerMax==nil leaves the peer transport parameter unset.
func newMaxPathIDTestConn(localMax, peerMax *uint32) *Conn {
	cfg := &Config{}
	if localMax != nil {
		v := *localMax
		cfg.InitialMaxPathID = &v
	}
	var peer *wire.TransportParameters
	if peerMax != nil {
		peer = &wire.TransportParameters{}
		p := protocol.PathID(*peerMax)
		peer.InitialMaxPathID = &p
	}
	c := &Conn{config: cfg}
	c.peerParams.Store(peer)
	c.multipathManager = newMultipathManager()
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	return c
}

// queuedMaxPathIDFrames returns the MAX_PATH_ID frames currently queued in the
// framer's control-frame list. It also reports the total count of queued
// control frames so callers can assert nothing else was queued.
func queuedMaxPathIDFrames(c *Conn) (max []*wire.MaxPathIDFrame, total int) {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	for _, f := range c.framer.controlFrames {
		if mf, ok := f.(*wire.MaxPathIDFrame); ok {
			max = append(max, mf)
		}
	}
	return max, len(c.framer.controlFrames)
}

// TestQueueMaxPathIDSinglePath is the standing-invariant assertion for 5b: with
// multipath un-negotiated (Config.InitialMaxPathID == nil, the default),
// queueMaxPathID is a no-op, so the framer never holds a MAX_PATH_ID frame
// (0x3e7a) and the single-path send loop is byte-identical.
func TestQueueMaxPathIDSinglePath(t *testing.T) {
	peer := uint32(8)
	tests := []struct {
		name     string
		localMax *uint32
		peerMax  *uint32
	}{
		{name: "neither side advertises", localMax: nil, peerMax: nil},
		{name: "local only (peer did not advertise)", localMax: &peer, peerMax: nil},
		{name: "peer only (we did not advertise)", localMax: nil, peerMax: &peer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newMaxPathIDTestConn(tc.localMax, tc.peerMax)
			if c.multipathNegotiated() {
				t.Fatalf("multipath must be off for this case")
			}
			c.queueMaxPathID()
			if frames, total := queuedMaxPathIDFrames(c); len(frames) != 0 || total != 0 {
				t.Fatalf("single-path queued %d MAX_PATH_ID frame(s) (%d control frames total), want 0/0", len(frames), total)
			}
		})
	}
}

// TestQueueMaxPathIDNegotiated checks that with multipath negotiated,
// queueMaxPathID queues exactly one MAX_PATH_ID frame carrying our configured
// InitialMaxPathID, and that calling it once (as handleHandshakeConfirmed does)
// does not duplicate it.
func TestQueueMaxPathIDNegotiated(t *testing.T) {
	local := uint32(4)
	peer := uint32(8)
	c := newMaxPathIDTestConn(&local, &peer)
	if !c.multipathNegotiated() {
		t.Fatalf("multipath must be on for this case")
	}

	c.queueMaxPathID()

	frames, total := queuedMaxPathIDFrames(c)
	if len(frames) != 1 {
		t.Fatalf("queued %d MAX_PATH_ID frames, want exactly 1", len(frames))
	}
	if total != 1 {
		t.Fatalf("queued %d control frames, want exactly 1 (only the MAX_PATH_ID frame)", total)
	}
	if frames[0].PathID != protocol.PathID(local) {
		t.Fatalf("MAX_PATH_ID PathID = %d, want %d (our configured InitialMaxPathID)", frames[0].PathID, local)
	}
}

// TestPeerMaxPathIDRecordedFromFrame proves the receive side records the peer's
// advertised max path id: feeding a MAX_PATH_ID frame through the same handler
// the run loop uses populates multipathManager.peerMaxPathID, which canOpenPath
// then consults. This is the read-side half of the 5b round trip; the send-side
// half (queueMaxPathID) is covered above.
func TestPeerMaxPathIDRecordedFromFrame(t *testing.T) {
	local := uint32(4)
	peer := uint32(8)
	c := newMaxPathIDTestConn(&local, &peer)
	if !c.multipathNegotiated() {
		t.Fatalf("multipath must be on for this case")
	}

	if _, ok := c.multipathManager.peerMax(); ok {
		t.Fatalf("peerMax should be unset before any MAX_PATH_ID frame")
	}
	if err := c.handleMaxPathIDFrame(&wire.MaxPathIDFrame{PathID: protocol.PathID(4)}); err != nil {
		t.Fatalf("handleMaxPathIDFrame: %v", err)
	}
	got, ok := c.multipathManager.peerMax()
	if !ok || got != protocol.PathID(4) {
		t.Fatalf("peerMax = %d (set=%v), want 4/true", got, ok)
	}
}

// TestCanOpenPath pins the path-open gate. canOpenPath must be false unless
// multipath was negotiated, false for PathIDZero (the always-present initial
// path), and false for any pid beyond the peer's advertised max or our own.
func TestCanOpenPath(t *testing.T) {
	local := uint32(4)
	peer := uint32(8)

	// Multipath off: every pid is rejected.
	t.Run("multipath off", func(t *testing.T) {
		c := newMaxPathIDTestConn(nil, nil)
		c.multipathManager.handleMaxPathID(protocol.PathID(8))
		if c.canOpenPath(protocol.PathID(1)) {
			t.Fatalf("canOpenPath(1) = true with multipath off, want false")
		}
	})

	// Multipath off when the peer's transport parameter is absent.
	t.Run("peer transport parameter unset", func(t *testing.T) {
		c := newMaxPathIDTestConn(&local, nil)
		if c.canOpenPath(protocol.PathID(1)) {
			t.Fatalf("canOpenPath(1) = true without peer initial_max_path_id, want false")
		}
	})

	// Multipath on, peer initial max 3, our local max 4.
	t.Run("within initial maxima", func(t *testing.T) {
		peerInitial := uint32(3)
		c := newMaxPathIDTestConn(&local, &peerInitial)
		tests := []struct {
			pid  protocol.PathID
			want bool
		}{
			{protocol.PathIDZero, false}, // initial path, never "opened"
			{protocol.PathID(1), true},
			{protocol.PathID(3), true},  // == peer max
			{protocol.PathID(4), false}, // > peer max (3), even though <= our max (4)
			{protocol.PathID(5), false}, // > both
		}
		for _, tc := range tests {
			if got := c.canOpenPath(tc.pid); got != tc.want {
				t.Errorf("canOpenPath(%d) = %v, want %v", tc.pid, got, tc.want)
			}
		}
	})

	t.Run("max path id raises peer max", func(t *testing.T) {
		peerInitial := uint32(1)
		c := newMaxPathIDTestConn(&local, &peerInitial)
		if c.canOpenPath(protocol.PathID(2)) {
			t.Fatal("canOpenPath(2) = true before MAX_PATH_ID, want false")
		}
		c.multipathManager.handleMaxPathID(protocol.PathID(3))
		if !c.canOpenPath(protocol.PathID(3)) {
			t.Fatal("canOpenPath(3) = false after MAX_PATH_ID, want true")
		}
	})

	// Our own local max also clamps: peer is generous (max 8) but we only
	// advertised 4, so pid 5..8 are rejected by our local cap.
	t.Run("our local max clamps", func(t *testing.T) {
		c := newMaxPathIDTestConn(&local, &peer)
		if !c.canOpenPath(protocol.PathID(4)) {
			t.Errorf("canOpenPath(4) = false, want true (== our local max, <= peer max)")
		}
		if c.canOpenPath(protocol.PathID(5)) {
			t.Errorf("canOpenPath(5) = true, want false (> our local max 4)")
		}
	})
}
