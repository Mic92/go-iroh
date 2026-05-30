package quic

import (
	"bytes"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// These tests cover Stage 5c of the QUIC multipath port: per-path connection-ID
// issuance via PATH_NEW_CONNECTION_ID (0x3e78) on the issuer side, recording
// peer-issued path CIDs on the read side, and the send-side DCID->PathID
// resolution. Wire layouts are pinned against the authoritative noq-proto
// reference (internal/qng/n0ext/reference/frame.rs).

// stubConnRunner is a no-op connRunner used only as the map key the
// connIDGenerator stores; CID add/remove bookkeeping is observed through the
// connRunnerCallbacks passed separately to newConnIDGenerator.
type stubConnRunner struct{}

func (stubConnRunner) Add(protocol.ConnectionID, packetHandler) bool                    { return true }
func (stubConnRunner) Remove(protocol.ConnectionID)                                     {}
func (stubConnRunner) ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration) {}
func (stubConnRunner) AddResetToken(protocol.StatelessResetToken, packetHandler)        {}
func (stubConnRunner) RemoveResetToken(protocol.StatelessResetToken)                    {}

// newTestConnIDGenerator builds a connIDGenerator that records the frames it
// queues and the CIDs it registers/removes, so tests can inspect the
// NEW_CONNECTION_ID / PATH_NEW_CONNECTION_ID it emits.
func newTestConnIDGenerator(t *testing.T) (g *connIDGenerator, frames *[]wire.Frame, added *[]protocol.ConnectionID) {
	t.Helper()
	var queued []wire.Frame
	var addedIDs []protocol.ConnectionID
	initial := protocol.ParseConnectionID([]byte{0x00, 0x11, 0x22, 0x33})
	g = newConnIDGenerator(
		stubConnRunner{},
		initial,
		nil, // client: no initialClientDestConnID
		newStatelessResetter(nil),
		connRunnerCallbacks{
			AddConnectionID:    func(id protocol.ConnectionID) { addedIDs = append(addedIDs, id) },
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) { queued = append(queued, f) },
		&protocol.DefaultConnectionIDGenerator{ConnLen: 4},
	)
	return g, &queued, &addedIDs
}

// TestIssueNewConnIDStaysPlain proves the single-path issuance path is
// byte-identical: issueNewConnID never sets a PathID, so the emitted frame is a
// plain NEW_CONNECTION_ID (0x18), and its Append output carries no 0x3e78.
func TestIssueNewConnIDStaysPlain(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if err := g.issueNewConnID(); err != nil {
		t.Fatalf("issueNewConnID: %v", err)
	}
	if len(*frames) != 1 {
		t.Fatalf("queued %d frames, want 1", len(*frames))
	}
	nc, ok := (*frames)[0].(*wire.NewConnectionIDFrame)
	if !ok {
		t.Fatalf("frame type = %T, want *wire.NewConnectionIDFrame", (*frames)[0])
	}
	if nc.PathID != nil {
		t.Fatalf("single-path NEW_CONNECTION_ID has PathID %v, want nil", *nc.PathID)
	}
	got, err := nc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got[0] != byte(wire.FrameTypeNewConnectionID) {
		t.Fatalf("frame type byte = %#x, want %#x (plain NEW_CONNECTION_ID)", got[0], byte(wire.FrameTypeNewConnectionID))
	}
	assertNoPathNewConnID(t, got)
}

// TestIssuePathConnIDEmitsPathFrame proves the issuer side of 5c: opening a path
// emits PATH_NEW_CONNECTION_ID{PathID:1} (0x3e78) with the path's own sequence
// space (starting at 0), and the issued CID is registered so incoming packets
// to it are recognized. The connection-level highestSeq is untouched.
func TestIssuePathConnIDEmitsPathFrame(t *testing.T) {
	g, frames, added := newTestConnIDGenerator(t)

	cid1, err := g.issuePathConnID(1)
	if err != nil {
		t.Fatalf("issuePathConnID(1): %v", err)
	}
	if len(*frames) != 1 {
		t.Fatalf("queued %d frames, want 1", len(*frames))
	}
	nc, ok := (*frames)[0].(*wire.NewConnectionIDFrame)
	if !ok {
		t.Fatalf("frame type = %T, want *wire.NewConnectionIDFrame", (*frames)[0])
	}
	if nc.PathID == nil || *nc.PathID != 1 {
		t.Fatalf("PathID = %v, want 1", nc.PathID)
	}
	if nc.SequenceNumber != 0 {
		t.Fatalf("path-1 first CID sequence = %d, want 0 (independent per-path space)", nc.SequenceNumber)
	}
	if nc.ConnectionID != cid1 {
		t.Fatalf("frame CID %s != returned CID %s", nc.ConnectionID, cid1)
	}
	if g.highestSeq != 0 {
		t.Fatalf("connection-level highestSeq = %d, path issuance must not advance it", g.highestSeq)
	}
	if len(*added) != 1 || (*added)[0] != cid1 {
		t.Fatalf("issued CID not registered with the conn runner: added=%v", *added)
	}

	// A second CID for path 1 advances path 1's own sequence to 1.
	cid1b, err := g.issuePathConnID(1)
	if err != nil {
		t.Fatalf("issuePathConnID(1) #2: %v", err)
	}
	nc2 := (*frames)[1].(*wire.NewConnectionIDFrame)
	if nc2.SequenceNumber != 1 {
		t.Fatalf("path-1 second CID sequence = %d, want 1", nc2.SequenceNumber)
	}
	if cid1b == cid1 {
		t.Fatalf("path 1's two CIDs must differ")
	}

	// A different path has its own sequence space starting at 0.
	if _, err := g.issuePathConnID(2); err != nil {
		t.Fatalf("issuePathConnID(2): %v", err)
	}
	nc3 := (*frames)[2].(*wire.NewConnectionIDFrame)
	if nc3.PathID == nil || *nc3.PathID != 2 || nc3.SequenceNumber != 0 {
		t.Fatalf("path-2 first CID = {PathID:%v Seq:%d}, want {2 0}", nc3.PathID, nc3.SequenceNumber)
	}
}

// TestIssuePathConnIDZeroRejected guards risk #5: PathIDZero's CIDs flow through
// the connection-level issueNewConnID; calling issuePathConnID for it is a bug.
func TestIssuePathConnIDZeroRejected(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if _, err := g.issuePathConnID(protocol.PathIDZero); err == nil {
		t.Fatalf("issuePathConnID(PathIDZero) should error")
	}
	if len(*frames) != 0 {
		t.Fatalf("issuePathConnID(PathIDZero) emitted %d frames, want 0", len(*frames))
	}
}

// TestPathNewConnectionIDGoldenFromGenerator pins the on-wire 0x3e78 layout the
// issuer emits: frame type 0x3e78, then path_id, then sequence (frame.rs:
// 2015-2026 NewConnectionId::encode writes path_id before sequence). It mirrors
// the wire-package golden test but exercises the integration-level frame the
// connIDGenerator actually queues.
func TestPathNewConnectionIDGoldenFromGenerator(t *testing.T) {
	g, frames, _ := newTestConnIDGenerator(t)
	if _, err := g.issuePathConnID(1); err != nil {
		t.Fatalf("issuePathConnID(1): %v", err)
	}
	nc := (*frames)[0].(*wire.NewConnectionIDFrame)
	got, err := nc.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	// 7e 78 (type 0x3e78 as a 2-byte varint) | 01 (path_id) | 00 (sequence) |
	// 00 (retire_prior_to) | 04 (cid len) | <4-byte cid> | 16-byte reset token.
	wantPrefix := []byte{0x7e, 0x78, 0x01, 0x00, 0x00, 0x04}
	if !bytes.HasPrefix(got, wantPrefix) {
		t.Fatalf("encode prefix = % x, want % x (path_id before sequence)", got[:len(wantPrefix)], wantPrefix)
	}
	// type(2) + path_id(1) + seq(1) + retire(1) + len(1) + cid(4) + token(16).
	if len(got) != 2+1+1+1+1+4+16 {
		t.Fatalf("encoded length = %d, want %d", len(got), 2+1+1+1+1+4+16)
	}
}

// assertNoPathNewConnID fails if buf contains the PATH_NEW_CONNECTION_ID frame
// type (0x3e78). Used to prove single-path output carries no multipath CID
// frames.
func assertNoPathNewConnID(t *testing.T, buf []byte) {
	t.Helper()
	marker := quicvarint.Append(nil, uint64(wire.FrameTypePathNewConnectionID))
	if bytes.Contains(buf, marker) {
		t.Fatalf("buffer % x contains PATH_NEW_CONNECTION_ID marker % x", buf, marker)
	}
}

// newMultipathConn builds a minimal *Conn for read-side handler tests, mirroring
// the construction in multipath_frame_guard_test.go. on selects whether
// multipath is negotiated.
func newMultipathConn(on bool) *Conn {
	cfg := &Config{}
	peer := &wire.TransportParameters{}
	if on {
		maxLocal := uint32(8)
		pid := protocol.PathID(8)
		cfg.InitialMaxPathID = &maxLocal
		peer.InitialMaxPathID = &pid
	}
	c := &Conn{config: cfg, peerParams: peer}
	c.multipathManager = newMultipathManager()
	c.perPathDestConnIDs = make(map[protocol.PathID]protocol.ConnectionID)
	return c
}

// TestHandlePathNewConnectionIDRecordsDestConnID proves the read side of 5c: an
// incoming PATH_NEW_CONNECTION_ID{PathID:1} records a distinct DCID for path 1
// in perPathDestConnIDs, and destConnIDForPath(1) returns it.
func TestHandlePathNewConnectionIDRecordsDestConnID(t *testing.T) {
	c := newMultipathConn(true)
	pathCID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})
	pid := protocol.PathID(1)
	frame := &wire.NewConnectionIDFrame{
		PathID:         &pid,
		SequenceNumber: 0,
		ConnectionID:   pathCID,
	}
	if err := c.handleNewConnectionIDFrame(frame); err != nil {
		t.Fatalf("handleNewConnectionIDFrame: %v", err)
	}
	got, ok := c.perPathDestConnIDs[1]
	if !ok {
		t.Fatalf("path 1 DCID not recorded")
	}
	if got != pathCID {
		t.Fatalf("recorded DCID %s, want %s", got, pathCID)
	}
	resolved, ok := c.destConnIDForPath(1)
	if !ok || resolved != pathCID {
		t.Fatalf("destConnIDForPath(1) = %s,%v, want %s,true", resolved, ok, pathCID)
	}
}

// TestHandlePathNewConnectionIDRejectedWhenOff proves a path-qualified frame on a
// single-path connection is a protocol violation (defensive double-guard).
func TestHandlePathNewConnectionIDRejectedWhenOff(t *testing.T) {
	c := newMultipathConn(false)
	pid := protocol.PathID(1)
	frame := &wire.NewConnectionIDFrame{PathID: &pid, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})}
	err := c.handleNewConnectionIDFrame(frame)
	if err == nil {
		t.Fatalf("PATH_NEW_CONNECTION_ID with multipath off should error")
	}
	te, ok := err.(*qerr.TransportError)
	if !ok || te.ErrorCode != qerr.ProtocolViolation {
		t.Fatalf("error = %v, want ProtocolViolation", err)
	}
	if len(c.perPathDestConnIDs) != 0 {
		t.Fatalf("rejected frame must not record a DCID, got %v", c.perPathDestConnIDs)
	}
}

// TestHandlePathNewConnectionIDPathZeroRejected guards the malformed case of a
// PATH_NEW_CONNECTION_ID carrying PathID 0 (whose CIDs use the plain form).
func TestHandlePathNewConnectionIDPathZeroRejected(t *testing.T) {
	c := newMultipathConn(true)
	pid := protocol.PathIDZero
	frame := &wire.NewConnectionIDFrame{PathID: &pid, ConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4})}
	err := c.handleNewConnectionIDFrame(frame)
	if err == nil {
		t.Fatalf("PATH_NEW_CONNECTION_ID for PathID 0 should error")
	}
	te, ok := err.(*qerr.TransportError)
	if !ok || te.ErrorCode != qerr.ProtocolViolation {
		t.Fatalf("error = %v, want ProtocolViolation", err)
	}
}

// TestDestConnIDForPathZeroUsesConnIDManager proves PathIDZero's DCID always
// comes from connIDManager.Get (the single connection-level CID), keeping
// single-path sends byte-identical, and that a non-zero path's DCID is distinct
// from it (perPathDestConnIDs[1] != connIDManager.Get()).
func TestDestConnIDForPathZeroUsesConnIDManager(t *testing.T) {
	c := newMultipathConn(true)
	active := protocol.ParseConnectionID([]byte{0x0a, 0x0b, 0x0c, 0x0d})
	c.connIDManager = newConnIDManager(
		active,
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)

	got, ok := c.destConnIDForPath(protocol.PathIDZero)
	if !ok || got != active {
		t.Fatalf("destConnIDForPath(0) = %s,%v, want %s,true (connIDManager.Get)", got, ok, active)
	}

	// Before the peer issues a path-1 CID, resolution reports not-ok.
	if _, ok := c.destConnIDForPath(1); ok {
		t.Fatalf("destConnIDForPath(1) should be not-ok before PATH_NEW_CONNECTION_ID")
	}

	pathCID := protocol.ParseConnectionID([]byte{0x11, 0x22, 0x33, 0x44})
	pid := protocol.PathID(1)
	if err := c.handleNewConnectionIDFrame(&wire.NewConnectionIDFrame{PathID: &pid, ConnectionID: pathCID}); err != nil {
		t.Fatalf("handleNewConnectionIDFrame: %v", err)
	}
	p1, ok := c.destConnIDForPath(1)
	if !ok || p1 != pathCID {
		t.Fatalf("destConnIDForPath(1) = %s,%v, want %s,true", p1, ok, pathCID)
	}
	if p1 == c.connIDManager.Get() {
		t.Fatalf("path-1 DCID %s must differ from connIDManager.Get() %s", p1, c.connIDManager.Get())
	}
}

// TestHandlePlainNewConnectionIDUnchanged proves the non-multipath read path is
// unchanged: a plain NEW_CONNECTION_ID (PathID nil) is routed to connIDManager
// and never lands in perPathDestConnIDs.
func TestHandlePlainNewConnectionIDUnchanged(t *testing.T) {
	c := newMultipathConn(false)
	var added []wire.Frame
	c.connIDManager = newConnIDManager(
		protocol.ParseConnectionID([]byte{0x01, 0x02, 0x03, 0x04}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(f wire.Frame) { added = append(added, f) },
	)
	var token protocol.StatelessResetToken
	frame := &wire.NewConnectionIDFrame{
		SequenceNumber:      1,
		ConnectionID:        protocol.ParseConnectionID([]byte{0xaa, 0xbb, 0xcc, 0xdd}),
		StatelessResetToken: token,
	}
	if err := c.handleNewConnectionIDFrame(frame); err != nil {
		t.Fatalf("handleNewConnectionIDFrame (plain): %v", err)
	}
	if len(c.perPathDestConnIDs) != 0 {
		t.Fatalf("plain NEW_CONNECTION_ID must not touch perPathDestConnIDs, got %v", c.perPathDestConnIDs)
	}
}
