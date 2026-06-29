package iroh

import (
	"errors"
	"fmt"
	"net"

	quic "github.com/tmc/go-iroh/internal/qng"
)

// ApplicationError is an application-defined connection close error.
type ApplicationError struct {
	// Code is the application-defined close code.
	Code uint64
	// Reason is the application-defined close reason.
	Reason string
	// Remote reports whether the peer sent the close.
	Remote bool
}

// Error returns a human-readable close error.
func (e *ApplicationError) Error() string {
	who := "local"
	if e.Remote {
		who = "remote"
	}
	if e.Reason == "" {
		return fmt.Sprintf("application close %d (%s)", e.Code, who)
	}
	return fmt.Sprintf("application close %d (%s): %s", e.Code, who, e.Reason)
}

// Unwrap returns [net.ErrClosed].
func (e *ApplicationError) Unwrap() error { return net.ErrClosed }

// AsApplicationError returns the application close error in err, if any.
func AsApplicationError(err error) (*ApplicationError, bool) {
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) {
		return nil, false
	}
	return &ApplicationError{
		Code:   uint64(appErr.ErrorCode),
		Reason: appErr.ErrorMessage,
		Remote: appErr.Remote,
	}, true
}
