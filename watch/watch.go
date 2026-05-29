// Package watch provides an observable value: a [Value] that can be updated and
// one or more [Watcher] handles that observe its changes.
//
// It is the Go analog of iroh's n0_watcher (Watchable + Watcher). A [Watcher]
// exposes the current value, a one-shot wait for the next change, and a channel
// stream of values. The root package re-exports Watcher for APIs such as
// Endpoint.WatchAddr.
package watch

import (
	"context"
	"sync"
)

// Value is an observable container holding a T. It is safe for concurrent use.
// Updates are published to all [Watcher] handles created from it.
//
// The zero Value holds the zero T and is ready to use.
type Value[T any] struct {
	mu      sync.Mutex
	val     T
	set     bool
	version uint64
	notify  chan struct{} // closed and replaced on each Set
}

// NewValue returns a Value initialized to v.
func NewValue[T any](v T) *Value[T] {
	return &Value[T]{val: v, set: true}
}

// Set updates the value and notifies all watchers if it changed. It uses the
// provided equal function to suppress notifications for no-op updates; pass nil
// to always notify.
func (s *Value[T]) Set(v T, equal func(a, b T) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set && equal != nil && equal(s.val, v) {
		return
	}
	s.val = v
	s.set = true
	s.version++
	if s.notify != nil {
		close(s.notify)
		s.notify = nil
	}
}

// Get returns the current value.
func (s *Value[T]) Get() T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.val
}

// Watch returns a [Watcher] observing this value.
func (s *Value[T]) Watch() Watcher[T] {
	return &watcher[T]{src: s}
}

// changed returns the current value, version, and a channel closed on the next
// change after the given version.
func (s *Value[T]) waitChan(after uint64) (T, uint64, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != after {
		return s.val, s.version, closedChan
	}
	if s.notify == nil {
		s.notify = make(chan struct{})
	}
	return s.val, s.version, s.notify
}

var closedChan = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// Watcher observes a [Value]. Multiple watchers may observe the same value
// independently. It is the Go analog of iroh's n0_watcher::Watcher.
type Watcher[T any] interface {
	// Get returns the current value.
	Get() T
	// Updated blocks until the value changes after the watcher's last observed
	// version, returning the new value, or ctx.Err() if the context is done.
	// The first call returns the current value immediately.
	Updated(ctx context.Context) (T, error)
	// Stream returns a channel that yields each new value until ctx is done.
	// The current value is delivered first.
	Stream(ctx context.Context) <-chan T
}

type watcher[T any] struct {
	src  *Value[T]
	seen uint64
	once bool
}

func (w *watcher[T]) Get() T { return w.src.Get() }

func (w *watcher[T]) Updated(ctx context.Context) (T, error) {
	if !w.once {
		w.once = true
		v, ver, _ := w.src.waitChan(^uint64(0)) // force "current" on first call
		w.seen = ver
		return v, nil
	}
	for {
		v, ver, ch := w.src.waitChan(w.seen)
		if ver != w.seen {
			w.seen = ver
			return v, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
}

func (w *watcher[T]) Stream(ctx context.Context) <-chan T {
	out := make(chan T)
	// Independent cursor so Stream doesn't disturb Updated on the same watcher.
	sub := &watcher[T]{src: w.src}
	go func() {
		defer close(out)
		for {
			v, err := sub.Updated(ctx)
			if err != nil {
				return
			}
			select {
			case out <- v:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
