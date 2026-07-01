package blobs

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func TestFSStoreConcurrentStress(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	const workers = 12
	const rounds = 32
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				data := []byte(fmt.Sprintf("worker=%02d round=%02d", worker, i))
				hash, err := store.Add(data)
				if err != nil {
					t.Errorf("Add: %v", err)
					return
				}
				value := RawHash(hash)
				tag := fmt.Sprintf("worker-%02d", worker)
				if err := store.SetTag(tag, value); err != nil {
					t.Errorf("SetTag: %v", err)
					return
				}
				temp, err := store.NewTempTag(value)
				if err != nil {
					t.Errorf("NewTempTag: %v", err)
					return
				}
				store.BlobStatus(hash)
				if _, _, err := store.Get(context.Background(), hash); err != nil {
					t.Errorf("Get: %v", err)
					_ = temp.Close()
					return
				}
				if _, err := store.Tags(); err != nil {
					t.Errorf("Tags: %v", err)
					_ = temp.Close()
					return
				}
				if _, err := store.GC(context.Background()); err != nil {
					t.Errorf("GC: %v", err)
					_ = temp.Close()
					return
				}
				if err := temp.Close(); err != nil {
					t.Errorf("TempTag.Close: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
