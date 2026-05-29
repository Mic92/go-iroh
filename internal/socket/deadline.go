package socket

import (
	"sync"
	"time"
)

// deadline is a resettable read deadline for [MagicConn]. Its wait channel is
// closed when the deadline elapses (or is set to a past time) and reopened when
// the deadline is cleared. It mirrors the deadline behavior net.Conn requires:
// a zero time means no deadline, and a past time fires immediately.
//
// The zero deadline is not usable; call init first.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func (d *deadline) init() {
	d.cancel = make(chan struct{})
}

// wait returns a channel that is closed when the deadline elapses. A nil
// deadline never fires.
func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

// set updates the deadline. A zero t clears it; a t in the past fires
// immediately.
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}

	closed := isClosed(d.cancel)

	switch {
	case t.IsZero():
		// Clear: ensure an open channel.
		if closed {
			d.cancel = make(chan struct{})
		}
	case !t.After(time.Now()):
		// Already past: fire now.
		if !closed {
			close(d.cancel)
		}
	default:
		// Future: re-arm with a fresh channel and a timer.
		if closed {
			d.cancel = make(chan struct{})
		}
		ch := d.cancel
		d.timer = time.AfterFunc(time.Until(t), func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.cancel == ch && !isClosed(ch) {
				close(ch)
			}
		})
	}
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// timeoutError is the net.Error returned by [MagicConn.ReadFrom] when the read
// deadline elapses. It reports Timeout and Temporary so callers (quic-go) can
// distinguish it from a fatal error.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
