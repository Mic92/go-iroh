package docs

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreConcurrentStress(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	events, cancelEvents := store.Subscribe()
	defer cancelEvents()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var eventWG sync.WaitGroup
	eventWG.Add(1)
	go func() {
		defer eventWG.Done()
		for {
			select {
			case _, ok := <-events:
				if !ok {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	const workers = 16
	const rounds = 128
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			author := NewAuthor(repeat32(byte(worker + 1)))
			for i := 0; i < rounds; i++ {
				key := []byte(fmt.Sprintf("worker/%02d/key/%03d", worker, i%16))
				entry := testSignedEntry(namespace, author, string(key), testRecord("data", uint64(i+1), uint64(i+1)))
				store.Put(entry)
				store.GetExact(namespace.ID(), author.ID(), key, false)
				store.Entries()
				store.Fingerprint(NewRange(entry.Entry.ID, entry.Entry.ID))
			}
		}()
	}
	wg.Wait()
	cancel()
	done := make(chan struct{})
	go func() {
		eventWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event drain did not stop")
	}
	if store.Len() == 0 {
		t.Fatal("store is empty after stress")
	}
}
