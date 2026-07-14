package socket

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

// drainUntilClosed reads events from ch until it closes, failing t if that
// takes longer than the deadline. A closed channel proves the subscription's
// delivery goroutine exited.
func drainUntilClosed(t *testing.T, ch <-chan PathEvent) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("event channel not closed: delivery goroutine still running")
		}
	}
}

// TestPathWatcherCancelUnblocksAbandonedSubscriber pins the Subscribe cancel
// contract: cancelling a subscription whose reader stopped (channel and ring
// both full, delivery goroutine blocked mid-send) must end delivery and close
// the channel.
func TestPathWatcherCancelUnblocksAbandonedSubscriber(t *testing.T) {
	w := NewPathWatcher()
	defer w.Close()
	ch, cancel := w.Subscribe()

	// Overfill: the channel buffer, then the ring, then lag accounting.
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	for range 3 * (PathBroadcastCapacity + 1) {
		w.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
	}

	cancel()
	drainUntilClosed(t, ch)
}

// TestActorEndsConnSubscriptionOnConnClose verifies that the actor cancels the
// subscription it creates for a connection when that connection closes, even
// though AddConnection callers have no cancel handle of their own.
func TestActorEndsConnSubscriptionOnConnClose(t *testing.T) {
	a := newRemoteStateActor(t.Context(), key.EndpointID{}, nil, nil, time.Minute, nil, nil)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	conn := newFakeConn(addr, time.Millisecond)
	ch, ok := a.AddConnection(conn)
	if !ok {
		t.Fatal("AddConnection: actor stopped")
	}

	conn.Close()
	drainUntilClosed(t, ch)
}

// TestActorStopsWithUnreadSubscription is the drain-deadlock regression test:
// stopping an actor that still has a connection whose event channel nobody
// reads must not hang. Before the per-connection cancel, the watcher's
// closing drain waited forever on the abandoned reader and the actor
// goroutine leaked.
func TestActorStopsWithUnreadSubscription(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	a := newRemoteStateActor(ctx, key.EndpointID{}, nil, nil, time.Minute, nil, nil)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	conn := newFakeConn(addr, time.Millisecond)
	defer conn.Close()
	ch, ok := a.AddConnection(conn)
	if !ok {
		t.Fatal("AddConnection: actor stopped")
	}

	// Block the delivery goroutine mid-send: nobody reads ch.
	for range 3 * (PathBroadcastCapacity + 1) {
		a.watcher.Send(PathEvent{Kind: PathEventOpened, Addr: addr})
	}

	cancel()
	select {
	case <-a.donec():
	case <-time.After(5 * time.Second):
		t.Fatal("actor did not stop: watcher drain deadlocked on unread subscription")
	}
	drainUntilClosed(t, ch)
}
