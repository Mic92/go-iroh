package wire

import (
	"errors"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/quicvarint"
)

// errInvalidPathID is returned when a multipath path id varint exceeds the
// uint32 range, matching the Rust decoder's u32::try_from check
// (n0ext/reference/paths.rs PathId::decode).
var errInvalidPathID = errors.New("wire: multipath path id exceeds uint32 range")

// This file holds the codecs for the simple (non-ACK) QUIC multipath frames
// from draft-ietf-quic-multipath, as used by iroh's noq QUIC fork. The wire
// layouts mirror internal/qng/n0ext/reference/frame.rs byte-for-byte. The
// multipath frame type ids are multi-byte QUIC varints (see frame_type.go), so
// the type is written with quicvarint.Append rather than a single byte.
//
// parsePathID reads a multipath path id: a QUIC varint that must fit in a
// uint32. A value larger than uint32 is malformed, matching the Rust decoder's
// u32::try_from check (paths.rs PathId::decode).

func parsePathID(b []byte) (protocol.PathID, int, error) {
	v, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, replaceUnexpectedEOF(err)
	}
	if v > uint64(protocol.PathIDMax) {
		return 0, 0, errInvalidPathID
	}
	return protocol.PathID(v), l, nil
}

// A PathAbandonFrame signals that the sender is abandoning a path.
// See frame.rs PathAbandon (lines 2185-2213): path_id, error_code.
type PathAbandonFrame struct {
	PathID    protocol.PathID
	ErrorCode uint64
}

func parsePathAbandonFrame(b []byte, _ protocol.Version) (*PathAbandonFrame, int, error) {
	startLen := len(b)
	pid, l, err := parsePathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	code, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return &PathAbandonFrame{PathID: pid, ErrorCode: code}, startLen - len(b), nil
}

func (f *PathAbandonFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathAbandon))
	b = quicvarint.Append(b, uint64(f.PathID))
	b = quicvarint.Append(b, f.ErrorCode)
	return b, nil
}

func (f *PathAbandonFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathAbandon)) +
		quicvarint.Len(uint64(f.PathID)) + quicvarint.Len(f.ErrorCode))
}

// A PathStatusBackupFrame marks a path as a backup path.
// See frame.rs PathStatusBackup (lines 2252-2280): path_id, status_seq_no.
type PathStatusBackupFrame struct {
	PathID protocol.PathID
	SeqNo  uint64
}

func parsePathStatusBackupFrame(b []byte, _ protocol.Version) (*PathStatusBackupFrame, int, error) {
	pid, seq, n, err := parsePathStatus(b)
	if err != nil {
		return nil, 0, err
	}
	return &PathStatusBackupFrame{PathID: pid, SeqNo: seq}, n, nil
}

func (f *PathStatusBackupFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendPathStatus(b, FrameTypePathStatusBackup, f.PathID, f.SeqNo), nil
}

func (f *PathStatusBackupFrame) Length(_ protocol.Version) protocol.ByteCount {
	return pathStatusLength(FrameTypePathStatusBackup, f.PathID, f.SeqNo)
}

// A PathStatusAvailableFrame marks a path as available (non-backup).
// See frame.rs PathStatusAvailable (lines 2218-2247): path_id, status_seq_no.
type PathStatusAvailableFrame struct {
	PathID protocol.PathID
	SeqNo  uint64
}

func parsePathStatusAvailableFrame(b []byte, _ protocol.Version) (*PathStatusAvailableFrame, int, error) {
	pid, seq, n, err := parsePathStatus(b)
	if err != nil {
		return nil, 0, err
	}
	return &PathStatusAvailableFrame{PathID: pid, SeqNo: seq}, n, nil
}

func (f *PathStatusAvailableFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendPathStatus(b, FrameTypePathStatusAvailable, f.PathID, f.SeqNo), nil
}

func (f *PathStatusAvailableFrame) Length(_ protocol.Version) protocol.ByteCount {
	return pathStatusLength(FrameTypePathStatusAvailable, f.PathID, f.SeqNo)
}

// parsePathStatus reads the shared (path_id, status_seq_no) body of the two
// path-status frames.
func parsePathStatus(b []byte) (protocol.PathID, uint64, int, error) {
	startLen := len(b)
	pid, l, err := parsePathID(b)
	if err != nil {
		return 0, 0, 0, err
	}
	b = b[l:]
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, 0, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return pid, seq, startLen - len(b), nil
}

func appendPathStatus(b []byte, typ FrameType, pid protocol.PathID, seq uint64) []byte {
	b = quicvarint.Append(b, uint64(typ))
	b = quicvarint.Append(b, uint64(pid))
	b = quicvarint.Append(b, seq)
	return b
}

func pathStatusLength(typ FrameType, pid protocol.PathID, seq uint64) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(typ)) +
		quicvarint.Len(uint64(pid)) + quicvarint.Len(seq))
}

// A MaxPathIDFrame raises the largest path id the sender will accept.
// See frame.rs MaxPathId (lines 1410-1432): path_id.
type MaxPathIDFrame struct {
	PathID protocol.PathID
}

func parseMaxPathIDFrame(b []byte, _ protocol.Version) (*MaxPathIDFrame, int, error) {
	pid, l, err := parsePathID(b)
	if err != nil {
		return nil, 0, err
	}
	return &MaxPathIDFrame{PathID: pid}, l, nil
}

func (f *MaxPathIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendSinglePathID(b, FrameTypeMaxPathID, f.PathID), nil
}

func (f *MaxPathIDFrame) Length(_ protocol.Version) protocol.ByteCount {
	return singlePathIDLength(FrameTypeMaxPathID, f.PathID)
}

// A PathsBlockedFrame signals the sender wants more paths than its peer allows.
// See frame.rs PathsBlocked (lines 1437-1460): remote_max_path_id.
type PathsBlockedFrame struct {
	MaxPathID protocol.PathID
}

func parsePathsBlockedFrame(b []byte, _ protocol.Version) (*PathsBlockedFrame, int, error) {
	pid, l, err := parsePathID(b)
	if err != nil {
		return nil, 0, err
	}
	return &PathsBlockedFrame{MaxPathID: pid}, l, nil
}

func (f *PathsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return appendSinglePathID(b, FrameTypePathsBlocked, f.MaxPathID), nil
}

func (f *PathsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return singlePathIDLength(FrameTypePathsBlocked, f.MaxPathID)
}

func appendSinglePathID(b []byte, typ FrameType, pid protocol.PathID) []byte {
	b = quicvarint.Append(b, uint64(typ))
	b = quicvarint.Append(b, uint64(pid))
	return b
}

func singlePathIDLength(typ FrameType, pid protocol.PathID) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(typ)) + quicvarint.Len(uint64(pid)))
}

// A PathCIDsBlockedFrame signals the sender wants more connection ids for a
// path than its peer has issued.
// See frame.rs PathCidsBlocked (lines 1465-1494): path_id, next_seq.
type PathCIDsBlockedFrame struct {
	PathID  protocol.PathID
	NextSeq uint64
}

func parsePathCIDsBlockedFrame(b []byte, _ protocol.Version) (*PathCIDsBlockedFrame, int, error) {
	startLen := len(b)
	pid, l, err := parsePathID(b)
	if err != nil {
		return nil, 0, err
	}
	b = b[l:]
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	return &PathCIDsBlockedFrame{PathID: pid, NextSeq: seq}, startLen - len(b), nil
}

func (f *PathCIDsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypePathCIDsBlocked))
	b = quicvarint.Append(b, uint64(f.PathID))
	b = quicvarint.Append(b, f.NextSeq)
	return b, nil
}

func (f *PathCIDsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypePathCIDsBlocked)) +
		quicvarint.Len(uint64(f.PathID)) + quicvarint.Len(f.NextSeq))
}
