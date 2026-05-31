package iroh

import (
	"context"

	"github.com/tmc/go-iroh/base"
)

// BeforeConnectOutcome is the decision returned by an [EndpointHooks]
// BeforeConnect method.
type BeforeConnectOutcome int

const (
	// BeforeConnectAccept allows the dial to continue.
	BeforeConnectAccept BeforeConnectOutcome = iota
	// BeforeConnectReject rejects the dial before any packet is sent.
	BeforeConnectReject
)

// AfterHandshakeOutcome is the decision returned by an [EndpointHooks]
// AfterHandshake method.
type AfterHandshakeOutcome struct {
	// Accept allows the connection to be returned to the caller.
	Accept bool
	// ErrorCode is the application close code used when rejecting.
	ErrorCode uint64
	// Reason is the application close reason used when rejecting.
	Reason []byte
}

// AcceptHandshake accepts a completed handshake.
func AcceptHandshake() AfterHandshakeOutcome { return AfterHandshakeOutcome{Accept: true} }

// RejectHandshake rejects a completed handshake with code and reason.
func RejectHandshake(code uint64, reason []byte) AfterHandshakeOutcome {
	return AfterHandshakeOutcome{ErrorCode: code, Reason: reason}
}

// EndpointHooks observes and can reject outbound dials and completed
// handshakes.
type EndpointHooks interface {
	BeforeConnect(ctx context.Context, addr base.EndpointAddr, alpn []byte) (BeforeConnectOutcome, error)
	AfterHandshake(ctx context.Context, conn *Conn) (AfterHandshakeOutcome, error)
}

type noopHooks struct{}

func (noopHooks) BeforeConnect(context.Context, base.EndpointAddr, []byte) (BeforeConnectOutcome, error) {
	return BeforeConnectAccept, nil
}

func (noopHooks) AfterHandshake(context.Context, *Conn) (AfterHandshakeOutcome, error) {
	return AcceptHandshake(), nil
}
