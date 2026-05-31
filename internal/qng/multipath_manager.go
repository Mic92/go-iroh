package quic

import (
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// multipathManager records the read-side state of QUIC multipath
// (draft-ietf-quic-multipath) paths keyed by protocol.PathID. It mirrors the
// recovery-irrelevant subset of n0ext/reference/paths.rs that the receive
// pipeline updates from incoming PATH_STATUS_*, PATH_ABANDON, MAX_PATH_ID,
// PATHS_BLOCKED and PATH_CIDS_BLOCKED frames.
//
// Stage 4c is read side only: the manager records what the peer tells us. It
// does NOT schedule sends, open paths, or issue path connection IDs — that is
// Stage 5. Until then no second path is opened on the send side, so the
// per-path packet-number state in the ackhandler only ever holds PathIDZero;
// the manager is the place that accumulates the peer's path signaling so the
// send side can consume it later.
type multipathManager struct {
	paths map[protocol.PathID]*multipathState

	// peerMaxPathID is the largest PathID the peer will accept, as raised by
	// MAX_PATH_ID frames. It gates how many paths we may open (Stage 5).
	// paths.rs tracks the analogous remote max path id; a MAX_PATH_ID frame
	// that does not increase it is ignored.
	peerMaxPathID    protocol.PathID
	peerMaxPathIDSet bool

	// peerPathsBlocked / peerPathCIDsBlocked record the most recent
	// informational PATHS_BLOCKED / PATH_CIDS_BLOCKED signaling from the peer.
	// They are advisory: the peer wants more paths / more path CIDs than we
	// have granted. Stage 4c only records them.
	peerPathsBlocked    *protocol.PathID
	peerPathCIDsBlocked map[protocol.PathID]uint64
}

// pathStatus is the QUIC-MULTIPATH path status carried by PATH_STATUS_AVAILABLE
// and PATH_STATUS_BACKUP frames. It mirrors reference/paths.rs PathStatus
// (paths.rs:1026-1038); Available is the zero value, matching the Rust default.
type pathStatus uint8

const (
	pathStatusAvailable pathStatus = iota
	pathStatusBackup
)

// pathStatusState holds the remote-set status for a path and the highest
// status sequence number seen, mirroring reference/paths.rs PathStatusState
// (paths.rs:977-1018). The receive side only consumes the remote status; the
// local status is a Stage 5 send-side concern.
type pathStatusState struct {
	// remoteStatus is the status last set by the peer.
	remoteStatus pathStatus
	// remoteSeq is the status_seq_no of the frame that set remoteStatus.
	remoteSeq uint64
	// remoteSet reports whether the peer has set the status at least once;
	// before that there is no valid remoteSeq to compare against.
	remoteSet bool
}

// remoteUpdate applies a received PATH_STATUS_AVAILABLE/PATH_STATUS_BACKUP
// frame. It mirrors PathStatusState::remote_update (paths.rs:990-1001): a
// non-increasing sequence number is ignored, so reordered or replayed status
// frames cannot move the status backwards. It reports whether the status was
// updated.
func (s *pathStatusState) remoteUpdate(status pathStatus, seq uint64) bool {
	// paths.rs:993-995: if self.remote_status.is_some_and(|(curr, _)| curr >= seq) { return }
	if s.remoteSet && s.remoteSeq >= seq {
		return false
	}
	s.remoteStatus = status
	s.remoteSeq = seq
	s.remoteSet = true
	return true
}

// multipathState is the per-path read-side state.
type multipathState struct {
	status pathStatusState
	// abandoned reports whether the peer sent a PATH_ABANDON for this path.
	// Stage 4c records it without tearing down send state (Stage 5).
	abandoned bool
	// abandonErrorCode is the error code carried by the peer's PATH_ABANDON.
	abandonErrorCode uint64
}

// newMultipathManager returns a multipathManager seeded with the PathIDZero
// entry, the only path that exists until Stage 5 opens additional paths. The
// initial path is always available, matching the Rust default status.
func newMultipathManager() *multipathManager {
	return &multipathManager{
		paths: map[protocol.PathID]*multipathState{
			protocol.PathIDZero: {},
		},
		peerPathCIDsBlocked: make(map[protocol.PathID]uint64),
	}
}

// pathState returns the state for pid, creating it on first reference. The peer
// can signal status for a path before the send side opens it, so the read-side
// manager admits any pid the frame parser let through (the parser already gates
// on multipathNegotiated()).
func (m *multipathManager) pathState(pid protocol.PathID) *multipathState {
	st, ok := m.paths[pid]
	if !ok {
		st = &multipathState{}
		m.paths[pid] = st
	}
	return st
}

// handleStatusBackup records a PATH_STATUS_BACKUP frame. It reports whether the
// remote status changed (the seq was increasing).
func (m *multipathManager) handleStatusBackup(pid protocol.PathID, seq uint64) bool {
	return m.pathState(pid).status.remoteUpdate(pathStatusBackup, seq)
}

// handleStatusAvailable records a PATH_STATUS_AVAILABLE frame. It reports
// whether the remote status changed (the seq was increasing).
func (m *multipathManager) handleStatusAvailable(pid protocol.PathID, seq uint64) bool {
	return m.pathState(pid).status.remoteUpdate(pathStatusAvailable, seq)
}

// handleAbandon records a PATH_ABANDON frame from the peer.
func (m *multipathManager) handleAbandon(pid protocol.PathID, errorCode uint64) {
	st := m.pathState(pid)
	st.abandoned = true
	st.abandonErrorCode = errorCode
}

// handleMaxPathID records a MAX_PATH_ID frame, raising the largest PathID the
// peer will accept. A frame that does not increase the value is ignored,
// matching the monotonic semantics of QUIC's MAX_* frames.
func (m *multipathManager) handleMaxPathID(pid protocol.PathID) {
	if !m.peerMaxPathIDSet || pid > m.peerMaxPathID {
		m.peerMaxPathID = pid
		m.peerMaxPathIDSet = true
	}
}

// peerMax returns the largest PathID the peer will accept and whether the peer
// has raised its initial transport-parameter limit with a MAX_PATH_ID frame.
func (m *multipathManager) peerMax() (protocol.PathID, bool) {
	return m.peerMaxPathID, m.peerMaxPathIDSet
}

// handlePathsBlocked records a PATHS_BLOCKED frame: the peer wants to open more
// paths than its current max path id allows. Informational in Stage 4c.
func (m *multipathManager) handlePathsBlocked(maxPathID protocol.PathID) {
	v := maxPathID
	m.peerPathsBlocked = &v
}

// handlePathCIDsBlocked records a PATH_CIDS_BLOCKED frame: the peer wants more
// connection IDs for pid than we have issued. Informational in Stage 4c.
func (m *multipathManager) handlePathCIDsBlocked(pid protocol.PathID, nextSeq uint64) {
	m.peerPathCIDsBlocked[pid] = nextSeq
}
