//go:build !linux && !windows && !darwin

package quic

import (
	"syscall"
)

func setDF(syscall.RawConn) (bool, error) {
	// Unsupported platforms run without explicit don't-fragment control.
	// Path MTU discovery still operates through QUIC loss and packet sizing.
	return false, nil
}

func isSendMsgSizeErr(err error) bool {
	// There is no portable message-size errno classification here.
	return false
}

func isRecvMsgSizeErr(err error) bool {
	// There is no portable message-size errno classification here.
	return false
}
