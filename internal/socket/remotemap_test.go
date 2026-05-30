package socket

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
)

// fakeConn is a test [Connection]. Close() ends it; SmoothedRTT and RemoteAddr
// are fixed.
type fakeConn struct {
	addr                Addr
	rtt                 time.Duration
	multipathNegotiated bool
	done                chan struct{}
	once                sync.Once
}

func newFakeConn(addr Addr, rtt time.Duration) *fakeConn {
	return &fakeConn{addr: addr, rtt: rtt, done: make(chan struct{})}
}

func (c *fakeConn) SmoothedRTT() time.Duration { return c.rtt }
func (c *fakeConn) Done() <-chan struct{}      { return c.done }
func (c *fakeConn) RemoteAddr() Addr           { return c.addr }
func (c *fakeConn) MultipathNegotiated() bool  { return c.multipathNegotiated }
func (c *fakeConn) Close()                     { c.once.Do(func() { close(c.done) }) }

func testEndpointId(t *testing.T) base.EndpointId {
	t.Helper()
	sk, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Public()
}

// TestRemoteMapSingleActorRace is the O12 gate (iroh/DESIGN.md §6): with a tiny
// idle timeout, actors are constantly idling out and being re-spawned while
// AddConnection hammers the same id. The registry must always hold exactly one
// actor per id — never two — even when an AddConnection lands exactly as the
// idle teardown fires. Run with -race.
func TestRemoteMapSingleActorRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A short idle timeout maximizes the spawn/teardown overlap while still
	// letting each registration win the race often enough to make progress.
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 2*time.Millisecond)
	id := testEndpointId(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))

	var (
		wg      sync.WaitGroup
		maxSeen atomic.Int64
		twoSeen atomic.Bool
	)

	// Track the high-water mark of registered actors throughout the test. A
	// small sleep keeps the monitor from starving the workers under -race.
	stopMonitor := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-stopMonitor:
				return
			default:
			}
			if n := int64(m.Len()); n > maxSeen.Load() {
				maxSeen.Store(n)
				if n > 1 {
					twoSeen.Store(true)
				}
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	const workers = 8
	const rounds = 100
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				c := newFakeConn(addr, 5*time.Millisecond)
				m.AddConnection(id, c)
				// Hold the connection briefly so the actor stays alive, then
				// close it so it can idle out and recreate the spawn/teardown
				// race on the next round.
				time.Sleep(time.Millisecond)
				c.Close()
				// Let the actor idle out roughly half the time, so some rounds
				// hit a live actor and some hit the teardown window.
				if i%2 == 0 {
					time.Sleep(3 * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(stopMonitor)
	<-monitorDone

	if twoSeen.Load() {
		t.Fatalf("RemoteMap held more than one actor for a single id (max seen %d); the O12 single-actor invariant was violated", maxSeen.Load())
	}
}

// TestRemoteMapReuseActor checks a second reference to the same id reuses the
// running actor rather than spawning a new one.
func TestRemoteMapReuseActor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointId(t)

	a1 := m.Actor(id)
	a2 := m.Actor(id)
	if a1 != a2 {
		t.Error("Actor returned different actors for the same id")
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
}

// TestRemoteMapIdleTeardown checks an actor with no connections idles out and
// deregisters.
func TestRemoteMapIdleTeardown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 10*time.Millisecond)
	id := testEndpointId(t)

	m.Actor(id) // spawns an actor with no connections
	if m.Len() != 1 {
		t.Fatalf("Len after spawn = %d, want 1", m.Len())
	}

	// Wait for the idle teardown to deregister it.
	deadline := time.After(2 * time.Second)
	for m.Len() != 0 {
		select {
		case <-deadline:
			t.Fatal("actor did not idle out and deregister")
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// TestActorPathEventsAndSelection checks that adding a connection emits Opened
// and Selected path events and that the actor selects the connection's path.
func TestActorPathEventsAndSelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointId(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 4242))
	c := newFakeConn(addr, 5*time.Millisecond)
	defer c.Close()

	events := m.AddConnection(id, c)

	// Expect an Opened event for the path, and a Selected event (the sole path).
	var sawOpened, sawSelected bool
	deadline := time.After(2 * time.Second)
	for !(sawOpened && sawSelected) {
		select {
		case ev := <-events:
			switch ev.Kind {
			case PathEventOpened:
				if ev.Addr.String() == addr.String() {
					sawOpened = true
				}
			case PathEventSelected:
				if ev.Addr.String() == addr.String() {
					sawSelected = true
				}
			}
		case <-deadline:
			t.Fatalf("missing path events: opened=%v selected=%v", sawOpened, sawSelected)
		}
	}

	a := m.Actor(id)
	if sel, ok := a.SelectedPath(); !ok || sel.String() != addr.String() {
		t.Errorf("SelectedPath = (%v, %v), want %s", sel, ok, addr)
	}
}

// TestActorHolepunchGated asserts the qng X2 degradation: hole-punching returns
// ErrExtensionNotNegotiated.
func TestActorHolepunchGated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointId(t))
	if err := a.TriggerHolepunch(); err != ErrExtensionNotNegotiated {
		t.Errorf("TriggerHolepunch = %v, want ErrExtensionNotNegotiated", err)
	}
}

// TestActorSendDatagramBlackhole asserts the blackhole invariant: SendDatagram
// never returns an error, even when no path is reachable (send returns false).
func TestActorSendDatagramBlackhole(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointId(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 1))
	c := newFakeConn(addr, time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	a := m.Actor(id)
	var sent atomic.Int64
	// Every send "fails" (returns false), yet SendDatagram must report success.
	err := a.SendDatagram([]byte("hi"), func(Addr, []byte) bool {
		sent.Add(1)
		return false
	})
	if err != nil {
		t.Errorf("SendDatagram returned %v on an unreachable path, want nil (blackhole)", err)
	}
	if sent.Load() == 0 {
		t.Error("SendDatagram did not attempt any send")
	}
}

// TestActorResolveAddsPaths checks the resolve hook adds resolved addresses as
// candidate paths.
func TestActorResolveAddsPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolved := []base.TransportAddr{
		base.IPAddr{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 7)},
	}
	resolve := func(ctx context.Context, id base.EndpointId) ([]base.TransportAddr, error) {
		return resolved, nil
	}
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, resolve, time.Second)
	id := testEndpointId(t)

	// Keep the actor alive with a connection so it does not idle out mid-test.
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	c := newFakeConn(addr, time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	if err := m.ResolveRemote(base.NewEndpointAddr(id)); err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}

	// The resolved IP path must now be a candidate. We send a datagram with no
	// selected path forced by clearing selection is not exposed; instead assert
	// via the actor's known paths through a fresh SendDatagram fanout count: with
	// a selected path it only sends to one, so check the path state directly.
	a := m.Actor(id)
	want := IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 7))
	a.mu.Lock()
	_, known := a.paths.Status(want)
	a.mu.Unlock()
	if !known {
		t.Errorf("resolved path %s was not added as a candidate", want)
	}
}
