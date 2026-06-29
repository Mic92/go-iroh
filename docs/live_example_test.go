package docs_test

import (
	"context"

	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
)

func ExampleStartLiveSync() {
	ctx := context.Background()

	var ep *iroh.Endpoint
	var g *gossip.Gossip
	var namespace docs.NamespaceID
	store := docs.NewMemoryStore()

	live, err := docs.StartLiveSync(ctx, ep, g, namespace, store, docs.LiveSyncOptions{})
	if err != nil {
		return
	}
	defer live.Close()
}
