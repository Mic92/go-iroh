//go:build windows

package mdns

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func reusePortControl(_, _ string, c syscall.RawConn) error {
	var firstErr error
	err := c.Control(func(fd uintptr) {
		firstErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return firstErr
}
