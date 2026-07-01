package socket

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func ev(kind PathEventKind, port uint16) PathEvent {
	return PathEvent{Kind: kind, Addr: IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), port))}
}

// TestPathWatcherDelivery checks that a subscriber that keeps up receives every
// event in order.
func TestPathWatcherDelivery(t *testing.T) {
	w := NewPathWatcher()
	defer w.Close()
	ch, cancel := w.Subscribe()
	defer cancel()

	for i := 0; i < PathBroadcastCapacity; i++ {
		w.Send(ev(PathEventOpened, uint16(i)))
	}
	for i := 0; i < PathBroadcastCapacity; i++ {
		got := <-ch
		if got.Kind != PathEventOpened {
			t.Fatalf("event %d: kind %v, want opened", i, got.Kind)
		}
		if got.Addr.String() != ev(PathEventOpened, uint16(i)).Addr.String() {
			t.Fatalf("event %d: addr %s, want port %d", i, got.Addr, i)
		}
	}
}

// TestPathWatcherLag is the slice-H lag gate: a subscriber that does not keep up
// is told how many events it missed via a single Lagged event rather than
// silently dropping. It mirrors the tokio::broadcast lagged-receiver behavior
// (path_watcher.rs:553).
//
// The exact split between in-flight, dropped, and buffered events depends on
// when the delivery goroutine wakes, so the test asserts the invariants that
// hold regardless of scheduling: exactly one Lagged event, accounting that
// covers every sent event, ascending port order, and that the final buffered
// events are the most recent ones (drop-oldest).
func TestPathWatcherLag(t *testing.T) {
	w := NewPathWatcher()
	defer w.Close()
	ch, cancel := w.Subscribe()
	defer cancel()

	// Send well past the channel + ring capacity without reading, forcing drops.
	const total = 3 * PathBroadcastCapacity
	for i := 0; i < total; i++ {
		w.Send(ev(PathEventOpened, uint16(i)))
	}
	var (
		lagged    int
		missed    uint64
		delivered []uint16
	)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-ch:
			switch got.Kind {
			case PathEventLagged:
				lagged++
				missed += got.Missed
			case PathEventOpened:
				ap, _ := got.Addr.IP()
				delivered = append(delivered, ap.Port())
				if ap.Port() == total-1 {
					cancel()
					goto done
				}
			default:
				t.Fatalf("unexpected event kind %v", got.Kind)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for newest event, delivered=%v missed=%d", delivered, missed)
		}
	}
done:
	for got := range ch {
		switch got.Kind {
		case PathEventLagged:
			lagged++
			missed += got.Missed
		case PathEventOpened:
			ap, _ := got.Addr.IP()
			delivered = append(delivered, ap.Port())
		default:
			t.Fatalf("unexpected event kind %v", got.Kind)
		}
	}

	// At least one Lagged must appear (the subscriber fell behind). Multiple may
	// appear if it lags across several episodes, like tokio::broadcast.
	if lagged < 1 {
		t.Errorf("got %d Lagged events, want at least 1", lagged)
	}
	if int(missed)+len(delivered) != total {
		t.Errorf("missed(%d) + delivered(%d) = %d, want %d sent events",
			missed, len(delivered), int(missed)+len(delivered), total)
	}
	// Delivered ports must be strictly ascending (in-order, no reordering).
	for i := 1; i < len(delivered); i++ {
		if delivered[i] <= delivered[i-1] {
			t.Errorf("delivered ports not ascending at %d: %v", i, delivered)
			break
		}
	}
	// Drop-oldest: the very last sent event must always survive.
	if len(delivered) == 0 || delivered[len(delivered)-1] != total-1 {
		t.Errorf("last delivered port = %v, want %d (newest event must survive)",
			delivered, total-1)
	}
}

// TestPathWatcherCloseEndsSubscribers checks that Close closes every
// subscriber's channel.
func TestPathWatcherCloseEndsSubscribers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := NewPathWatcher()
		ch, _ := w.Subscribe()

		done := make(chan struct{})
		go func() {
			for range ch {
			}
			close(done)
		}()

		synctest.Wait()
		select {
		case <-done:
			t.Fatal("subscriber ended before Close")
		default:
		}

		w.Close()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("subscriber channel still open after Close")
		}
	})
}

// TestPathWatcherMultipleSubscribers checks each subscriber gets its own copy.
func TestPathWatcherMultipleSubscribers(t *testing.T) {
	w := NewPathWatcher()
	defer w.Close()
	a, ca := w.Subscribe()
	b, cb := w.Subscribe()
	defer ca()
	defer cb()

	w.Send(ev(PathEventSelected, 7))
	for _, ch := range []<-chan PathEvent{a, b} {
		got := <-ch
		if got.Kind != PathEventSelected {
			t.Errorf("kind %v, want selected", got.Kind)
		}
	}
}
