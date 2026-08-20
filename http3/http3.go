package http3

import (
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/quicconn"
)

// Conn is the deprecated name for [quicconn.Conn].
//
// Deprecated: use [quicconn.Conn].
//
//go:fix inline
type Conn = quicconn.Conn

// BidiStream is the deprecated name for [quicconn.BidiStream].
//
// Deprecated: use [quicconn.BidiStream].
//
//go:fix inline
type BidiStream = quicconn.BidiStream

// SendStream is the deprecated name for [quicconn.SendStream].
//
// Deprecated: use [quicconn.SendStream].
//
//go:fix inline
type SendStream = quicconn.SendStream

// ReceiveStream is the deprecated name for [quicconn.ReceiveStream].
//
// Deprecated: use [quicconn.ReceiveStream].
//
//go:fix inline
type ReceiveStream = quicconn.ReceiveStream

// NewConn returns a [quicconn.Conn].
//
// Deprecated: use [quicconn.NewConn].
//
//go:fix inline
func NewConn(c *iroh.Conn) *quicconn.Conn { return quicconn.NewConn(c) }
