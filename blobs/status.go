package blobs

// BlobState is the local storage state of a blob.
type BlobState uint8

const (
	// BlobNotFound means the blob is not stored.
	BlobNotFound BlobState = iota
	// BlobPartial means the blob is only partially stored.
	BlobPartial
	// BlobComplete means the blob is stored completely.
	BlobComplete
)

const unknownBlobSize int64 = -1

// BlobStatus describes the local storage state of a blob.
//
// Size is -1 when the size is unknown.
type BlobStatus struct {
	State BlobState
	Size  int64
}

// NotFoundBlobStatus returns the status for a missing blob.
func NotFoundBlobStatus() BlobStatus { return BlobStatus{State: BlobNotFound, Size: unknownBlobSize} }

// PartialBlobStatus returns the status for a partial blob.
func PartialBlobStatus(size int64) BlobStatus {
	if size < 0 {
		size = unknownBlobSize
	}
	return BlobStatus{State: BlobPartial, Size: size}
}

// CompleteBlobStatus returns the status for a complete blob.
func CompleteBlobStatus(size int64) BlobStatus {
	if size < 0 {
		size = 0
	}
	return BlobStatus{State: BlobComplete, Size: size}
}

// SizeKnown reports whether s has a known size.
func (s BlobStatus) SizeKnown() bool { return s.Size >= 0 }

// IsComplete reports whether s describes a complete blob.
func (s BlobStatus) IsComplete() bool { return s.State == BlobComplete }

// IsPartial reports whether s describes a partial blob.
func (s BlobStatus) IsPartial() bool { return s.State == BlobPartial }

// IsNotFound reports whether s describes a missing blob.
func (s BlobStatus) IsNotFound() bool { return s.State == BlobNotFound }

// BlobStater reports local blob storage status.
type BlobStater interface {
	BlobStatus(Hash) BlobStatus
}

// Status reports the local storage status for hash in store.
func Status(store Store, hash Hash) BlobStatus {
	if hash == EmptyHash {
		return CompleteBlobStatus(0)
	}
	if store == nil {
		return NotFoundBlobStatus()
	}
	if st, ok := store.(BlobStater); ok {
		return st.BlobStatus(hash)
	}
	data, ok := store.GetBlob(hash)
	if !ok {
		return NotFoundBlobStatus()
	}
	return CompleteBlobStatus(int64(len(data)))
}
