package blobs

import (
	"context"
	"testing"
)

func TestStatus(t *testing.T) {
	data := []byte("stored blob")
	hash := NewHash(data)
	store := mustStore(t, data)

	tests := []struct {
		name string
		hash Hash
		want BlobStatus
	}{
		{name: "complete", hash: hash, want: CompleteBlobStatus(int64(len(data)))},
		{name: "empty", hash: EmptyHash, want: CompleteBlobStatus(0)},
		{name: "missing", hash: NewHash([]byte("missing")), want: NotFoundBlobStatus()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Status(context.Background(), store, tt.hash); got != tt.want {
				t.Fatalf("Status = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStatusUsesStater(t *testing.T) {
	hash := NewHash([]byte("partial"))
	store := statusStore{hash: hash, status: PartialBlobStatus(123)}

	if got := Status(context.Background(), store, hash); got != store.status {
		t.Fatalf("Status = %+v, want %+v", got, store.status)
	}
}

type statusStore struct {
	hash   Hash
	status BlobStatus
}

func (s statusStore) Open(context.Context, Hash) (Blob, error) { return nil, ErrBlobNotFound }

func (s statusStore) BlobStatus(hash Hash) BlobStatus {
	if hash != s.hash {
		return NotFoundBlobStatus()
	}
	return s.status
}
