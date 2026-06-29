package blobs_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestBlobTransferIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data := testData(blobs.BlockSize + 1)
	hash := blobs.NewHash(data)

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		blobs.ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			return blobs.ServeBlob(ctx, s, blobs.StoreFunc(func(got blobs.Hash) ([]byte, bool) {
				if got != hash {
					return nil, false
				}
				return append([]byte(nil), data...), true
			}))
		}),
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, blobs.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	got, err := blobs.GetBlobBytes(ctx, s, hash)
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("data length = %d, want %d", len(got), len(data))
	}
}

func TestGetManyBlobTransferIroh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	data := [][]byte{
		testData(1024),
		testData(blobs.BlockSize + 1),
	}
	var hashes []blobs.Hash
	store := make(map[blobs.Hash][]byte)
	for _, b := range data {
		hash := blobs.NewHash(b)
		hashes = append(hashes, hash)
		store[hash] = append([]byte(nil), b...)
	}

	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		blobs.ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			return blobs.ServeBlob(ctx, s, blobs.StoreFunc(func(hash blobs.Hash) ([]byte, bool) {
				b, ok := store[hash]
				return append([]byte(nil), b...), ok
			}))
		}),
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, blobs.ALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	got, err := blobs.GetManyBlobBytes(ctx, s, hashes)
	if err != nil {
		t.Fatalf("get many blobs: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("got %d blobs, want %d", len(got), len(data))
	}
	for i := range data {
		if string(got[i]) != string(data[i]) {
			t.Fatalf("blob %d length = %d, want %d", i, len(got[i]), len(data[i]))
		}
	}
}

func testData(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31 + 7)
	}
	return out
}
