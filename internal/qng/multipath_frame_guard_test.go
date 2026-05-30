package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// TestMultipathFrameGuardRejectsWhenOff is the Stage 4c defensive guard test:
// every multipath frame handler must return a ProtocolViolation when multipath
// has NOT been negotiated. The frame parser already refuses to admit these
// frames single-path (it is constructed with SetSupportsMultipath), so this is
// a defensive double-guard, mirroring handleHandshakeDoneFrame's perspective
// check. With multipath off (the default), no multipath frame ever reaches
// these handlers in production; if one does, it is a protocol violation.
func TestMultipathFrameGuardRejectsWhenOff(t *testing.T) {
	// A connection with neither side advertising initial_max_path_id:
	// multipathNegotiated() is false.
	newConn := func() *Conn {
		c := &Conn{config: &Config{}, peerParams: &wire.TransportParameters{}}
		c.multipathManager = newMultipathManager()
		return c
	}
	if newConn().multipathNegotiated() {
		t.Fatalf("multipath must be off for this test")
	}

	tests := []struct {
		name string
		call func(c *Conn) error
	}{
		{"PATH_ACK", func(c *Conn) error {
			return c.handlePathAckFrame(&wire.PathAckFrame{PathID: 1, Ack: wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 0, Largest: 0}}}}, 0)
		}},
		{"PATH_STATUS_BACKUP", func(c *Conn) error {
			return c.handlePathStatusBackupFrame(&wire.PathStatusBackupFrame{PathID: 1, SeqNo: 1})
		}},
		{"PATH_STATUS_AVAILABLE", func(c *Conn) error {
			return c.handlePathStatusAvailableFrame(&wire.PathStatusAvailableFrame{PathID: 1, SeqNo: 1})
		}},
		{"PATH_ABANDON", func(c *Conn) error {
			return c.handlePathAbandonFrame(&wire.PathAbandonFrame{PathID: 1, ErrorCode: 0})
		}},
		{"MAX_PATH_ID", func(c *Conn) error {
			return c.handleMaxPathIDFrame(&wire.MaxPathIDFrame{PathID: 4})
		}},
		{"PATHS_BLOCKED", func(c *Conn) error {
			return c.handlePathsBlockedFrame(&wire.PathsBlockedFrame{MaxPathID: 4})
		}},
		{"PATH_CIDS_BLOCKED", func(c *Conn) error {
			return c.handlePathCIDsBlockedFrame(&wire.PathCIDsBlockedFrame{PathID: 1, NextSeq: 1})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(newConn())
			if err == nil {
				t.Fatalf("%s with multipath off should return ProtocolViolation, got nil", tc.name)
			}
			transportErr, ok := err.(*qerr.TransportError)
			if !ok {
				t.Fatalf("error type = %T, want *qerr.TransportError", err)
			}
			if transportErr.ErrorCode != qerr.ProtocolViolation {
				t.Errorf("error code = %v, want ProtocolViolation", transportErr.ErrorCode)
			}
		})
	}
}

// TestMultipathFrameGuardAcceptsWhenOn checks the complementary case: with
// multipath negotiated, the informational frame handlers record state and do
// not error. (PATH_ACK is excluded: it routes into the ackhandler, which needs
// a fully constructed sentPacketHandler; its unknown-pid rejection is covered
// by the ackhandler test TestReceivedAckForPathUnknownPathID.)
func TestMultipathFrameGuardAcceptsWhenOn(t *testing.T) {
	pid := protocol.PathID(8)
	maxLocal := uint32(8)
	newConn := func() *Conn {
		cfg := &Config{InitialMaxPathID: &maxLocal}
		peer := &wire.TransportParameters{InitialMaxPathID: &pid}
		c := &Conn{config: cfg, peerParams: peer}
		c.multipathManager = newMultipathManager()
		return c
	}
	if !newConn().multipathNegotiated() {
		t.Fatalf("multipath must be on for this test")
	}

	c := newConn()
	if err := c.handlePathStatusBackupFrame(&wire.PathStatusBackupFrame{PathID: 1, SeqNo: 3}); err != nil {
		t.Fatalf("PATH_STATUS_BACKUP with multipath on: %v", err)
	}
	if got := c.multipathManager.pathState(protocol.PathID(1)).status.remoteStatus; got != pathStatusBackup {
		t.Errorf("path 1 status = %v, want Backup (frame recorded)", got)
	}

	if err := c.handleMaxPathIDFrame(&wire.MaxPathIDFrame{PathID: 9}); err != nil {
		t.Fatalf("MAX_PATH_ID with multipath on: %v", err)
	}
	if c.multipathManager.peerMaxPathID != protocol.PathID(9) {
		t.Errorf("peerMaxPathID = %d, want 9", c.multipathManager.peerMaxPathID)
	}
}
