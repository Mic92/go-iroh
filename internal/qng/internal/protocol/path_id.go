package protocol

import "math"

// A PathID identifies a path in QUIC multipath (draft-ietf-quic-multipath).
// It is a 32-bit value encoded on the wire as a QUIC variable-length integer.
//
// This is the multipath path identifier from iroh's noq QUIC fork, distinct
// from the unexported single-path migration path id used by the connection's
// path manager. See internal/qng/n0ext/reference/paths.rs (PathId).
type PathID uint32

const (
	// PathIDZero is the path id of the initial path.
	PathIDZero PathID = 0
	// PathIDMax is the largest representable path id.
	PathIDMax PathID = math.MaxUint32
)
