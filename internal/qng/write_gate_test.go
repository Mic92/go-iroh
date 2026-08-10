package quic

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestWriteGate() writeGate {
	return writeGate{wake: make(chan struct{}, 1)}
}

func TestWriteGateUncontended(t *testing.T) {
	g := newTestWriteGate()
	for range 100 {
		g.lock()
		g.unlock()
	}
}

func TestWriteGateWakesBlockedCaller(t *testing.T) {
	g := newTestWriteGate()
	g.lock()
	acquired := make(chan struct{})
	go func() {
		g.lock()
		close(acquired)
		g.unlock()
	}()
	select {
	case <-acquired:
		t.Fatal("second caller acquired a locked gate")
	case <-time.After(10 * time.Millisecond):
	}
	g.unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("second caller was not woken")
	}
}

func TestWriteGateSerializesCallers(t *testing.T) {
	g := newTestWriteGate()
	var active atomic.Int32
	var failed atomic.Bool
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				g.lock()
				if active.Add(1) != 1 {
					failed.Store(true)
				}
				active.Add(-1)
				g.unlock()
			}
		}()
	}
	wg.Wait()
	if failed.Load() {
		t.Fatal("multiple callers entered the write gate")
	}
}
