package iroh

import (
	"context"
	"fmt"

	"github.com/tmc/go-iroh/netaddr"
)

// HandshakeRejectError rejects a completed handshake with an application close
// code and reason.
type HandshakeRejectError struct {
	Code   uint64
	Reason string
}

// Error implements error.
func (e *HandshakeRejectError) Error() string {
	return fmt.Sprintf("reject handshake: code %d: %s", e.Code, e.Reason)
}

// RejectHandshake rejects a completed handshake with code and reason.
func RejectHandshake(code uint64, reason string) error {
	return &HandshakeRejectError{Code: code, Reason: reason}
}

// EndpointHooks observes and can reject outbound dials and completed
// handshakes.
type EndpointHooks interface {
	BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error
	AfterHandshake(ctx context.Context, conn *Conn) error
}

type noopHooks struct{}

func (noopHooks) BeforeConnect(context.Context, netaddr.EndpointAddr, string) error { return nil }

func (noopHooks) AfterHandshake(context.Context, *Conn) error { return nil }
