package watch

import (
	"context"
	"testing"
	"time"
)

func TestValueGetSet(t *testing.T) {
	v := NewValue(1)
	if v.Get() != 1 {
		t.Fatalf("Get = %d, want 1", v.Get())
	}
	v.Set(2, nil)
	if v.Get() != 2 {
		t.Fatalf("Get = %d, want 2", v.Get())
	}
}

func TestWatcherUpdatedDeliversCurrentFirst(t *testing.T) {
	v := NewValue("a")
	w := v.Watch()
	got, err := w.Updated(context.Background())
	if err != nil || got != "a" {
		t.Fatalf("first Updated = %q, %v; want a", got, err)
	}
}

func TestWatcherUpdatedBlocksUntilChange(t *testing.T) {
	v := NewValue(0)
	w := v.Watch()
	w.Updated(context.Background()) // consume current

	done := make(chan int, 1)
	go func() {
		got, _ := w.Updated(context.Background())
		done <- got
	}()
	// Should still be blocked.
	select {
	case <-done:
		t.Fatal("Updated returned before change")
	case <-time.After(20 * time.Millisecond):
	}
	v.Set(42, nil)
	select {
	case got := <-done:
		if got != 42 {
			t.Errorf("got %d, want 42", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Updated did not return after change")
	}
}

func TestWatcherUpdatedContextCancel(t *testing.T) {
	v := NewValue(0)
	w := v.Watch()
	w.Updated(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Updated(ctx); err == nil {
		t.Fatal("expected context error")
	}
}

func TestSetEqualSuppressesNoop(t *testing.T) {
	v := NewValue(5)
	w := v.Watch()
	w.Updated(context.Background())
	eq := func(a, b int) bool { return a == b }
	done := make(chan struct{})
	go func() {
		w.Updated(context.Background())
		close(done)
	}()
	v.Set(5, eq) // no-op, should not notify
	select {
	case <-done:
		t.Fatal("no-op Set notified")
	case <-time.After(20 * time.Millisecond):
	}
	v.Set(6, eq) // real change
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("real change did not notify")
	}
}

func TestStream(t *testing.T) {
	v := NewValue(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := v.Watch().Stream(ctx)
	if got := <-ch; got != 0 {
		t.Fatalf("first stream value = %d, want 0", got)
	}
	v.Set(1, nil)
	if got := <-ch; got != 1 {
		t.Fatalf("stream value = %d, want 1", got)
	}
}
