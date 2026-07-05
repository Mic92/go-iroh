//go:build !darwin || !arm64

package iroh

import "context"

// RDMAAvailable reports whether a platform RDMA provider is loadable.
func RDMAAvailable() bool {
	return false
}

// LocalRDMALinks returns active local RDMA devices usable for advertisement.
func LocalRDMALinks(ctx context.Context) ([]RDMALink, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrRDMAUnsupported
}
