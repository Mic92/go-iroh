package docs

import (
	"context"
	"errors"
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// SyncResult is the result of one peer sync attempt.
type SyncResult struct {
	Addr    netaddr.EndpointAddr
	Outcome SyncOutcome
	Err     error
}

// SyncPeers syncs store with peers in order.
func SyncPeers(ctx context.Context, ep *iroh.Endpoint, namespace NamespaceID, peers []netaddr.EndpointAddr, store *MemoryStore, blobStore blobs.Store, config SyncConfig) []SyncResult {
	results := make([]SyncResult, 0, len(peers))
	for _, peer := range peers {
		outcome, err := Sync(ctx, ep, peer, namespace, store, blobStore, config)
		results = append(results, SyncResult{Addr: peer, Outcome: outcome, Err: err})
	}
	return results
}

// SyncTicket syncs store with peers from ticket. If resolver is not nil, ticket
// node IDs are resolved before syncing.
func SyncTicket(ctx context.Context, ep *iroh.Endpoint, ticket DocTicket, store *MemoryStore, blobStore blobs.Store, config SyncConfig, resolver iroh.AddressResolver) []SyncResult {
	return SyncPeers(ctx, ep, ticket.Capability().NamespaceID(), ticketAddrs(ctx, ticket.Nodes(), resolver), store, blobStore, config)
}

func ticketAddrs(ctx context.Context, nodes []netaddr.EndpointAddr, resolver iroh.AddressResolver) []netaddr.EndpointAddr {
	seen := make(map[string]struct{})
	addrs := make([]netaddr.EndpointAddr, 0, len(nodes))
	add := func(addr netaddr.EndpointAddr) {
		if addr.ID.IsZero() {
			return
		}
		key := addr.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		addrs = append(addrs, addr)
	}
	for _, node := range nodes {
		add(node)
		if resolver == nil {
			continue
		}
		seq := resolver.Resolve(ctx, node.ID)
		if seq == nil {
			continue
		}
		for item, err := range seq {
			if err != nil {
				continue
			}
			add(item.Addr())
		}
	}
	return addrs
}

func (r SyncResult) err() error {
	if r.Err == nil {
		return nil
	}
	return fmt.Errorf("sync %s: %w", r.Addr.ID, r.Err)
}

// SyncErrors returns the joined errors in results.
func SyncErrors(results []SyncResult) error {
	var errs []error
	for _, result := range results {
		if err := result.err(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
