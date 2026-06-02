package iroh_test

import (
	"context"
	"sync"
	"testing"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

type externalCustomTransport struct {
	mu   sync.Mutex
	sent int
}

func (t *externalCustomTransport) Serve(ctx context.Context, recv func(iroh.CustomDatagram) bool) {
	<-ctx.Done()
}

func (t *externalCustomTransport) Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool {
	_, _, _ = remote, local, p
	t.mu.Lock()
	t.sent++
	t.mu.Unlock()
	return true
}

func TestWithCustomTransportExternalAPI(t *testing.T) {
	var custom externalCustomTransport
	ep, err := iroh.Bind(context.Background(), iroh.WithCustomTransport(&custom))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Close(context.Background())
}
