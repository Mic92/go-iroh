package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// TestPathStatusStateIgnoresNonIncreasingSeq pins the core read-side semantics
// of the multipath path status state machine: a PATH_STATUS_AVAILABLE /
// PATH_STATUS_BACKUP frame whose status_seq_no does not strictly increase is
// ignored, so reordered or replayed status frames cannot move the status
// backwards. This mirrors reference/paths.rs PathStatusState::remote_update
// (paths.rs:990-1001): `if self.remote_status.is_some_and(|(curr, _)| curr >=
// seq) { return }`.
func TestPathStatusStateIgnoresNonIncreasingSeq(t *testing.T) {
	var s pathStatusState

	// First update at seq 5 -> Backup is applied (no prior remote status).
	if !s.remoteUpdate(pathStatusBackup, 5) {
		t.Fatalf("first update (seq 5) should apply")
	}
	if s.remoteStatus != pathStatusBackup || s.remoteSeq != 5 {
		t.Fatalf("after seq 5: status=%v seq=%d, want Backup/5", s.remoteStatus, s.remoteSeq)
	}

	// Equal seq (5) -> ignored (paths.rs uses `curr >= seq`).
	if s.remoteUpdate(pathStatusAvailable, 5) {
		t.Errorf("equal-seq update (seq 5) should be ignored")
	}
	if s.remoteStatus != pathStatusBackup || s.remoteSeq != 5 {
		t.Errorf("equal-seq update changed state: status=%v seq=%d, want Backup/5", s.remoteStatus, s.remoteSeq)
	}

	// Lower seq (3) -> ignored.
	if s.remoteUpdate(pathStatusAvailable, 3) {
		t.Errorf("lower-seq update (seq 3) should be ignored")
	}
	if s.remoteStatus != pathStatusBackup || s.remoteSeq != 5 {
		t.Errorf("lower-seq update changed state: status=%v seq=%d, want Backup/5", s.remoteStatus, s.remoteSeq)
	}

	// Higher seq (6) -> applied, status flips to Available.
	if !s.remoteUpdate(pathStatusAvailable, 6) {
		t.Errorf("higher-seq update (seq 6) should apply")
	}
	if s.remoteStatus != pathStatusAvailable || s.remoteSeq != 6 {
		t.Errorf("after seq 6: status=%v seq=%d, want Available/6", s.remoteStatus, s.remoteSeq)
	}
}

// TestMultipathManagerStatusRouting checks that the manager routes status
// frames per path id and applies the same non-increasing-seq rule per path.
func TestMultipathManagerStatusRouting(t *testing.T) {
	m := newMultipathManager()

	// PathIDZero exists from construction and defaults to Available.
	if st := m.pathState(protocol.PathIDZero); st.status.remoteSet {
		t.Errorf("PathIDZero remote status should be unset at construction")
	}

	if !m.handleStatusBackup(protocol.PathID(1), 1) {
		t.Errorf("path 1 backup seq 1 should apply")
	}
	if m.handleStatusBackup(protocol.PathID(1), 1) {
		t.Errorf("path 1 backup seq 1 (repeat) should be ignored")
	}
	if !m.handleStatusAvailable(protocol.PathID(1), 2) {
		t.Errorf("path 1 available seq 2 should apply")
	}
	if got := m.pathState(protocol.PathID(1)).status.remoteStatus; got != pathStatusAvailable {
		t.Errorf("path 1 status = %v, want Available", got)
	}

	// A different path id has independent state.
	if !m.handleStatusBackup(protocol.PathID(2), 1) {
		t.Errorf("path 2 backup seq 1 should apply (independent of path 1)")
	}
	if got := m.pathState(protocol.PathID(2)).status.remoteStatus; got != pathStatusBackup {
		t.Errorf("path 2 status = %v, want Backup", got)
	}
}

// TestMultipathManagerAbandonAndMaxPathID checks PATH_ABANDON recording and the
// monotonic MAX_PATH_ID handling.
func TestMultipathManagerAbandonAndMaxPathID(t *testing.T) {
	m := newMultipathManager()

	m.handleAbandon(protocol.PathID(3), 42)
	st := m.pathState(protocol.PathID(3))
	if !st.abandoned || st.abandonErrorCode != 42 {
		t.Errorf("abandon: abandoned=%v code=%d, want true/42", st.abandoned, st.abandonErrorCode)
	}

	m.handleMaxPathID(protocol.PathID(7))
	if !m.peerMaxPathIDSet || m.peerMaxPathID != protocol.PathID(7) {
		t.Errorf("max path id = %d (set=%v), want 7/true", m.peerMaxPathID, m.peerMaxPathIDSet)
	}
	// A non-increasing MAX_PATH_ID is ignored.
	m.handleMaxPathID(protocol.PathID(5))
	if m.peerMaxPathID != protocol.PathID(7) {
		t.Errorf("max path id after lower update = %d, want 7", m.peerMaxPathID)
	}
}
