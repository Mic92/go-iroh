package iroh

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
)

func TestEndpointQLOGDIRWritesConnectionTraces(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	qlogDir := t.TempDir()
	t.Setenv("QLOGDIR", qlogDir)

	const alpn = "iroh-qlog/0"
	srvKey, err := base.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			accepted <- err
			return
		}
		<-conn.Closed()
		accepted <- nil
	}()

	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := conn.CloseWithError(0, ""); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	files, err := waitQLOGFiles(ctx, qlogDir, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("qlog files: %v", files)
}

func waitQLOGFiles(ctx context.Context, dir string, want int) ([]string, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		files, err := qlogFiles(dir)
		if err != nil {
			return nil, err
		}
		if len(files) >= want {
			return files, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("found %d qlog files in %s, want %d: %w", len(files), dir, want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func qlogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sqlog") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	return files, nil
}
